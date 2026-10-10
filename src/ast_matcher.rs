//! Policy composition for executable heredoc and inline-script source.
//!
//! The pattern engine remains independently configurable. The evaluator's
//! default matcher and early filesystem backstop also consult core's shared
//! protected-write classifier. A shell segment is too late for that check:
//! interpreter source has already been masked from that view (#461).
//!
//! Keep core rule identities in dotted AST form. The evaluator's existing
//! `split_ast_rule_id` turns `core.filesystem.credential-file-write` back into
//! the same pack/rule pair used for shell writes and scoped allowlists.

#[path = "ast_pattern_engine.rs"]
mod pattern_engine;
pub use pattern_engine::*;

use crate::heredoc::ScriptLanguage;
use crate::packs::core::credential_files;
use pattern_engine as engine;
use std::ops::Deref;
use std::sync::{LazyLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum DocumentationValue {
    Text,
    Scalar,
    File,
    NodeFs,
}

/// Literal ranges whose shell-looking bytes retain a proven data role (#544).
///
/// This small proof covers straight-line Python/JavaScript text edits. Every
/// expression must use concrete text/scalar values, known string methods, or
/// the standard print/file APIs below. One opaque call, escaped value, rebound
/// API, or unsupported statement withdraws that whole-program proof. A separate
/// bounded proof preserves static argv/option data owned by a named scanner,
/// after verifying its standard module binding and argument roles.
/// The caller must independently prove the interpreter and absence of outer
/// consumers, and keep the ORIGINAL source in execution/protected-write scans.
/// Parsing must run inside the caller's bounded optional-proof worker.
pub(crate) fn inert_documentation_literal_ranges(
    code: &str,
    language: ScriptLanguage,
) -> Vec<std::ops::Range<usize>> {
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    if code.len() > 256 * 1024 || (!code.contains('`') && !code.contains("$(")) {
        return Vec::new();
    }
    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        _ => return Vec::new(),
    };
    let Ok(ast) = AstGrep::try_new(code, grammar) else {
        return Vec::new();
    };
    let root = ast.root();
    // Reject recovery anywhere before deriving an allowance; traversal and
    // recursion are bounded independently of the general AST worker budget.
    for (index, node) in root.dfs().enumerate() {
        if index >= 4096 || node.is_error() || node.is_missing() {
            return Vec::new();
        }
    }
    let mut proof = DocumentationProof {
        language,
        values: std::collections::BTreeMap::new(),
        literals: Vec::new(),
        remaining_steps: 16_384,
    };
    if proof.expression(&root, 0).is_some() {
        proof.literals
    } else {
        inert_named_exec_literal_ranges(&root, code, language)
    }
}

struct DocumentationProof {
    language: ScriptLanguage,
    values: std::collections::BTreeMap<String, DocumentationValue>,
    literals: Vec<std::ops::Range<usize>>,
    remaining_steps: usize,
}

impl DocumentationProof {
    fn expression<D: ast_grep_core::Doc>(
        &mut self,
        node: &ast_grep_core::Node<'_, D>,
        depth: usize,
    ) -> Option<DocumentationValue> {
        use DocumentationValue::{Scalar, Text};
        if depth >= 64 {
            return None;
        }
        self.remaining_steps = self.remaining_steps.checked_sub(1)?;
        let named: Vec<_> = node
            .children()
            .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
            .collect();
        match node.kind().as_ref() {
            "module" | "program" | "lexical_declaration" | "variable_declaration" => {
                for child in &named {
                    self.expression(child, depth + 1)?;
                }
                Some(Scalar)
            }
            "expression_statement" | "parenthesized_expression" => match named.as_slice() {
                [child] => self.expression(child, depth + 1),
                _ => None,
            },
            "assignment" | "variable_declarator" => {
                // Additional named children include evaluated annotations.
                if named.len() != 2 || self.values.len() >= 128 {
                    return None;
                }
                let left = node.field("left").or_else(|| node.field("name"))?;
                if left.kind().as_ref() != "identifier" {
                    return None;
                }
                let name = left.text().into_owned();
                if matches!(name.as_str(), "print" | "open" | "console" | "require") {
                    return None;
                }
                let right = node.field("right").or_else(|| node.field("value"))?;
                let value = self.expression(&right, depth + 1)?;
                self.values.insert(name, value);
                Some(value)
            }
            "identifier" => self.values.get(node.text().as_ref()).copied(),
            "integer" | "float" | "number" | "true" | "false" | "none" | "null" => Some(Scalar),
            "string" | "template_string" => {
                // F-string/template expressions execute. They participate in
                // the same proof; quote shape alone never establishes safety.
                for child in node.dfs().skip(1) {
                    self.remaining_steps = self.remaining_steps.checked_sub(1)?;
                    if matches!(
                        child.kind().as_ref(),
                        "interpolation" | "format_expression" | "template_substitution"
                    ) {
                        let value = child.field("expression").or_else(|| {
                            child.children().find(|item| {
                                item.is_named()
                                    && !matches!(
                                        item.kind().as_ref(),
                                        "comment" | "type_conversion" | "format_specifier"
                                    )
                            })
                        })?;
                        if !matches!(self.expression(&value, depth + 1)?, Text | Scalar) {
                            return None;
                        }
                    }
                }
                if node.text().contains('`') || node.text().contains("$(") {
                    self.literals.push(node.range());
                }
                Some(Text)
            }
            "concatenated_string" => {
                for child in &named {
                    if self.expression(child, depth + 1)? != Text {
                        return None;
                    }
                }
                Some(Text)
            }
            "binary_operator" | "binary_expression" => {
                let left = self.expression(&node.field("left")?, depth + 1)?;
                let right = self.expression(&node.field("right")?, depth + 1)?;
                let operator = node.field("operator")?;
                if left == Text && right == Text && operator.text() == "+" {
                    Some(Text)
                } else if left == Scalar
                    && right == Scalar
                    && matches!(operator.text().as_ref(), "+" | "-" | "*" | "/" | "%")
                {
                    Some(Scalar)
                } else {
                    None
                }
            }
            "call" | "call_expression" => self.call(node, depth + 1),
            _ => None,
        }
    }

    fn call<D: ast_grep_core::Doc>(
        &mut self,
        node: &ast_grep_core::Node<'_, D>,
        depth: usize,
    ) -> Option<DocumentationValue> {
        use DocumentationValue::{File, NodeFs, Scalar, Text};
        if depth >= 64 {
            return None;
        }
        self.remaining_steps = self.remaining_steps.checked_sub(1)?;
        let function = node.field("function")?;
        let arguments = node.field("arguments")?;
        if !matches!(arguments.kind().as_ref(), "argument_list" | "arguments") {
            return None; // tagged templates invoke a callable
        }
        let args: Vec<_> = arguments
            .children()
            .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
            .collect();
        for argument in &args {
            let value = if argument.kind().as_ref() == "keyword_argument" {
                self.expression(&argument.field("value")?, depth + 1)?
            } else {
                self.expression(argument, depth + 1)?
            };
            if !matches!(value, Text | Scalar) {
                return None; // file/module capabilities may not escape
            }
        }
        if function.kind().as_ref() == "identifier" {
            return match (self.language, function.text().as_ref()) {
                (ScriptLanguage::Python, "print") => Some(Scalar),
                (ScriptLanguage::Python, "open") if !args.is_empty() => {
                    // Arbitrary codecs can import executable module code, and
                    // opener callbacks are not ordinary file operations. Only
                    // file/mode/buffering and literal built-in encodings prove
                    // the data-only open used by documentation edits.
                    let positional = args
                        .iter()
                        .filter(|arg| arg.kind().as_ref() != "keyword_argument")
                        .count();
                    let plain_options = args.iter().all(|arg| {
                        if arg.kind().as_ref() != "keyword_argument" {
                            return true;
                        }
                        let Some(name) = arg.field("name") else {
                            return false;
                        };
                        match name.text().as_ref() {
                            "file" | "mode" | "buffering" => true,
                            "encoding" => arg.field("value").is_some_and(|value| {
                                value.kind().as_ref() == "string"
                                    && matches!(
                                        value.text().trim_matches(['\'', '"']),
                                        "utf8" | "utf-8" | "ascii" | "latin1" | "latin-1"
                                    )
                            }),
                            _ => false,
                        }
                    });
                    (positional <= 3 && plain_options).then_some(File)
                }
                (ScriptLanguage::JavaScript, "require") if args.len() == 1 => {
                    // No computed module names or preloaded application code.
                    let literal = args[0].text();
                    matches!(
                        literal.as_ref(),
                        "'fs'" | "\"fs\"" | "'node:fs'" | "\"node:fs\""
                    )
                    .then_some(NodeFs)
                }
                _ => None,
            };
        }
        if !matches!(function.kind().as_ref(), "attribute" | "member_expression") {
            return None;
        }
        let object = function.field("object")?;
        let method = function
            .field("attribute")
            .or_else(|| function.field("property"))?;
        if self.language == ScriptLanguage::JavaScript
            && object.kind().as_ref() == "identifier"
            && object.text() == "console"
        {
            return matches!(method.text().as_ref(), "log" | "info" | "warn" | "error")
                .then_some(Scalar);
        }
        let receiver = self.expression(&object, depth + 1)?;
        match (receiver, method.text().as_ref()) {
            (
                Text,
                "replace" | "replaceAll" | "strip" | "lstrip" | "rstrip" | "lower" | "upper"
                | "removeprefix" | "removesuffix" | "trim" | "trimStart" | "trimEnd"
                | "toLowerCase" | "toUpperCase",
            ) => Some(Text),
            (File, "read") => Some(Text),
            (File, "write" | "close" | "flush") => Some(Scalar),
            (NodeFs, "readFileSync") => Some(Text),
            (NodeFs, "writeFileSync" | "appendFileSync") => Some(Scalar),
            _ => None,
        }
    }
}

const MAX_INTERPRETER_LITERAL_SOURCE_BYTES: usize = 256 * 1024;
const MAX_INTERPRETER_LITERAL_NODES: usize = 4096;
const MAX_INTERPRETER_LITERAL_CANDIDATES: usize = 128;
const MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum LiteralModule {
    PythonOs,
    PythonSubprocess,
    NodeChildProcess,
}

enum LiteralBinding {
    Text {
        value: String,
        range: std::ops::Range<usize>,
    },
    Module(LiteralModule),
}

type LiteralBindings = std::collections::BTreeMap<String, LiteralBinding>;

/// A later JavaScript function declaration can replace require/eval before
/// the verified prefix runs. Decline these optional prefix proofs without
/// attempting scope analysis; the original execution scans still run.
fn literal_prefix_has_no_function_hoisting<D: ast_grep_core::Doc>(
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> bool {
    language != ScriptLanguage::JavaScript
        || root.dfs().enumerate().all(|(index, node)| {
            index < MAX_INTERPRETER_LITERAL_NODES
                && !matches!(
                    node.kind().as_ref(),
                    "function_declaration" | "generator_function_declaration"
                )
        })
}

fn literal_statement<D: ast_grep_core::Doc>(
    mut node: ast_grep_core::Node<'_, D>,
) -> Option<ast_grep_core::Node<'_, D>> {
    for _ in 0..4 {
        if !matches!(
            node.kind().as_ref(),
            "expression_statement" | "lexical_declaration" | "variable_declaration"
        ) {
            return Some(node);
        }
        node = {
            let mut children = node
                .children()
                .filter(|child| child.is_named() && child.kind().as_ref() != "comment");
            let child = children.next()?;
            if children.next().is_some() {
                return None;
            }
            child
        };
    }
    None
}

fn literal_required_module<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> Option<LiteralModule> {
    if language != ScriptLanguage::JavaScript || node.kind().as_ref() != "call_expression" {
        return None;
    }
    let function = node.field("function")?;
    if function.kind().as_ref() != "identifier" || function.text() != "require" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let mut args = arguments
        .children()
        .filter(|child| child.is_named() && child.kind().as_ref() != "comment");
    let module = static_interpreter_literal(&args.next()?, language, 0)?;
    (args.next().is_none() && matches!(module.as_str(), "child_process" | "node:child_process"))
        .then_some(LiteralModule::NodeChildProcess)
}

/// Only straight-line literal assignments and standard module bindings may
/// establish a value for a later execution call. An unknown statement ends
/// this optional proof instead of guessing about rebinding or side effects.
fn record_literal_binding<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    bindings: &mut LiteralBindings,
) -> bool {
    if bindings.len() >= MAX_INTERPRETER_LITERAL_CANDIDATES {
        return false;
    }
    if language == ScriptLanguage::Python && node.kind().as_ref() == "import_statement" {
        let (name, module) = match node.text().as_ref() {
            "import os" => ("os", LiteralModule::PythonOs),
            "import posix" => ("posix", LiteralModule::PythonOs),
            "import subprocess" => ("subprocess", LiteralModule::PythonSubprocess),
            _ => return false,
        };
        bindings.insert(name.to_owned(), LiteralBinding::Module(module));
        return true;
    }
    if !matches!(node.kind().as_ref(), "assignment" | "variable_declarator")
        || node
            .children()
            .filter(ast_grep_core::Node::is_named)
            .count()
            != 2
    {
        return false;
    }
    let Some(name) = node.field("left").or_else(|| node.field("name")) else {
        return false;
    };
    let name_text = name.text();
    if name.kind().as_ref() != "identifier"
        // Python normalizes identifiers; JavaScript permits identifier
        // escapes. Raw spellings cannot establish a distinct binding then.
        || !name_text.is_ascii()
        || name_text.contains('\\')
        || matches!(name_text.as_ref(), "exec" | "eval" | "require")
    {
        return false;
    }
    let Some(value) = node.field("right").or_else(|| node.field("value")) else {
        return false;
    };
    let binding = if let Some(module) = literal_required_module(&value, language) {
        LiteralBinding::Module(module)
    } else if let Some(text) = static_interpreter_literal(&value, language, 0) {
        if text.len() > MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES {
            return false;
        }
        LiteralBinding::Text {
            value: text,
            range: value.range(),
        }
    } else {
        return false;
    };
    bindings.insert(name_text.into_owned(), binding);
    true
}

fn bound_literal_callee<D: ast_grep_core::Doc>(
    call: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    bindings: &LiteralBindings,
) -> Option<(LiteralModule, String, usize)> {
    let function = call.field("function")?;
    if !matches!(function.kind().as_ref(), "attribute" | "member_expression") {
        return None;
    }
    let object = function.field("object")?;
    let name = function
        .field("attribute")
        .or_else(|| function.field("property"))?;
    if !matches!(name.kind().as_ref(), "identifier" | "property_identifier") {
        return None;
    }
    let module = if object.kind().as_ref() == "identifier" {
        let LiteralBinding::Module(module) = bindings.get(object.text().as_ref())? else {
            return None;
        };
        *module
    } else {
        literal_required_module(&object, language)?
    };
    Some((module, name.text().into_owned(), name.range().start))
}

fn literal_mapping_key<D: ast_grep_core::Doc>(
    key: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> Option<String> {
    if language == ScriptLanguage::JavaScript && key.kind().as_ref() == "property_identifier" {
        let text = key.text();
        // JavaScript permits escapes inside an identifier. Its source spelling
        // cannot prove that the resulting key is not shell, input, or env.
        return (text.is_ascii() && !text.contains('\\')).then(|| text.into_owned());
    }
    static_interpreter_literal(key, language, 0).filter(|key| key.is_ascii())
}

fn literal_node_options_disable_shell<D: ast_grep_core::Doc>(
    options: &ast_grep_core::Node<'_, D>,
) -> bool {
    if options.kind().as_ref() != "object"
        || options
            .dfs()
            .filter(ast_grep_core::Node::is_named)
            .any(|node| {
                !matches!(
                    node.kind().as_ref(),
                    "object"
                        | "pair"
                        | "property_identifier"
                        | "string"
                        | "string_fragment"
                        | "escape_sequence"
                        | "number"
                        | "true"
                        | "false"
                        | "null"
                        | "array"
                )
            })
    {
        return false;
    }
    options
        .children()
        .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
        .all(|pair| {
            let Some(key) = pair.field("key") else {
                return false;
            };
            let name = literal_mapping_key(&key, ScriptLanguage::JavaScript);
            name.is_some_and(|name| {
                name != "shell"
                    || pair
                        .field("value")
                        .is_some_and(|value| value.text() == "false")
            })
        })
}

fn literal_argv_has_no_shell<D: ast_grep_core::Doc>(
    args: &[ast_grep_core::Node<'_, D>],
    module: LiteralModule,
    sink: &str,
) -> bool {
    match module {
        LiteralModule::PythonSubprocess
            if matches!(
                sink,
                "run" | "call" | "Popen" | "check_call" | "check_output"
            ) =>
        {
            args.iter().enumerate().all(|(index, argument)| {
                if argument.kind().as_ref() != "keyword_argument" {
                    return index == 0;
                }
                argument.field("name").is_some_and(|name| {
                    let name = name.text();
                    // CPython normalizes identifiers with NFKC; raw Unicode
                    // spelling cannot exclude an executable/shell override.
                    name.is_ascii()
                        && match name.as_ref() {
                            // The argv scanner models args[0], so an executable
                            // override can select an unmodeled shell or interpreter.
                            "executable" => false,
                            "shell" => argument
                                .field("value")
                                .is_some_and(|value| value.text() == "False"),
                            _ => true,
                        }
                })
            })
        }
        LiteralModule::NodeChildProcess
            if matches!(sink, "spawn" | "spawnSync" | "execFile" | "execFileSync") =>
        {
            match args {
                [_] => true,
                [_, argv] if argv.kind().as_ref() == "array" => true,
                [_, options] => literal_node_options_disable_shell(options),
                [_, argv, options] if argv.kind().as_ref() == "array" => {
                    literal_node_options_disable_shell(options)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn literal_argument_is_data<D: ast_grep_core::Doc>(
    argument: &ast_grep_core::Node<'_, D>,
    index: usize,
    module: LiteralModule,
    sink: &str,
    no_shell: bool,
) -> bool {
    match module {
        LiteralModule::PythonOs | LiteralModule::PythonSubprocess => {
            if argument.kind().as_ref() == "keyword_argument" {
                return argument.field("name").is_some_and(|name| {
                    let name = name.text();
                    name.is_ascii()
                        && match name.as_ref() {
                            "input" => false,
                            "args" => no_shell,
                            _ => true,
                        }
                });
            }
            index > 0 || no_shell
        }
        LiteralModule::NodeChildProcess if matches!(sink, "exec" | "execSync") => index > 0,
        LiteralModule::NodeChildProcess
            if matches!(sink, "spawn" | "spawnSync" | "execFile" | "execFileSync") =>
        {
            no_shell || index >= 2 || index == 1 && argument.kind().as_ref() == "object"
        }
        _ => false,
    }
}

fn literal_environment_data<'a, D: ast_grep_core::Doc>(
    environment: &ast_grep_core::Node<'a, D>,
    language: ScriptLanguage,
) -> Option<Vec<ast_grep_core::Node<'a, D>>> {
    if !matches!(environment.kind().as_ref(), "dictionary" | "object") {
        return None;
    }
    let mut values = Vec::new();
    for pair in environment
        .children()
        .filter(|node| node.is_named() && node.kind().as_ref() != "comment")
    {
        let key = literal_mapping_key(&pair.field("key")?, language)?;
        let value = pair.field("value")?;
        // Shell startup variables and Node's import options can execute
        // source before the child's ordinary argv. Unknown keys or container
        // spreads likewise cannot establish a data role.
        if !matches!(key.as_str(), "BASH_ENV" | "ENV" | "NODE_OPTIONS") {
            values.push(value);
        }
    }
    Some(values)
}

fn literal_argument_data_roots<'a, D: ast_grep_core::Doc>(
    argument: &ast_grep_core::Node<'a, D>,
    language: ScriptLanguage,
) -> Vec<ast_grep_core::Node<'a, D>> {
    if language == ScriptLanguage::Python
        && argument.kind().as_ref() == "keyword_argument"
        && argument
            .field("name")
            .is_some_and(|name| name.text() == "env")
    {
        return argument
            .field("value")
            .and_then(|value| literal_environment_data(&value, language))
            .unwrap_or_default();
    }
    if language != ScriptLanguage::JavaScript || argument.kind().as_ref() != "object" {
        return vec![argument.clone()];
    }
    let mut roots = Vec::new();
    for pair in argument
        .children()
        .filter(|node| node.is_named() && node.kind().as_ref() != "comment")
    {
        let Some(key) = pair
            .field("key")
            .and_then(|key| literal_mapping_key(&key, language))
        else {
            return Vec::new();
        };
        match key.as_str() {
            // A shell/interpreter child can execute this stdin directly.
            "input" => {}
            "env" => {
                let Some(values) = pair
                    .field("value")
                    .and_then(|value| literal_environment_data(&value, language))
                else {
                    return Vec::new();
                };
                roots.extend(values);
            }
            _ => roots.push(pair),
        }
    }
    roots
}

/// A named scanner owns complete static argv independently of whether the
/// surrounding program is a documentation edit. Only literal data positions
/// get this raw-view mask; shell programs and executable argument expressions
/// keep their original bytes in every execution scanner.
fn inert_named_exec_literal_ranges<D: ast_grep_core::Doc>(
    root: &ast_grep_core::Node<'_, D>,
    code: &str,
    language: ScriptLanguage,
) -> Vec<std::ops::Range<usize>> {
    if !literal_prefix_has_no_function_hoisting(root, language) {
        return Vec::new();
    }
    let Some(owned) =
        engine::literal_exec_sink_starts(code, language, MAX_INTERPRETER_LITERAL_CANDIDATES)
    else {
        return Vec::new();
    };
    let mut bindings = LiteralBindings::new();
    for statement in root
        .children()
        .filter(|node| node.is_named() && node.kind().as_ref() != "comment")
    {
        let Some(node) = literal_statement(statement) else {
            break;
        };
        if !matches!(node.kind().as_ref(), "call" | "call_expression") {
            if record_literal_binding(&node, language, &mut bindings) {
                continue;
            }
            break;
        }
        let Some((module, sink, start)) = bound_literal_callee(&node, language, &bindings) else {
            break;
        };
        if owned.binary_search(&start).is_err() {
            break;
        }
        let Some(arguments) = node.field("arguments") else {
            break;
        };
        let args: Vec<_> = arguments
            .children()
            .filter(|arg| arg.is_named() && arg.kind().as_ref() != "comment")
            .collect();
        let no_shell = literal_argv_has_no_shell(&args, module, &sink);
        let mut ranges = Vec::new();
        for (index, argument) in args.iter().enumerate() {
            if !literal_argument_is_data(argument, index, module, &sink, no_shell) {
                continue;
            }
            for literal in literal_argument_data_roots(argument, language)
                .iter()
                .flat_map(ast_grep_core::Node::dfs)
            {
                if matches!(
                    literal.kind().as_ref(),
                    "string" | "template_string" | "concatenated_string"
                ) && interpreter_literal_has_owned_sink(&literal, &[start])
                    && static_interpreter_literal(&literal, language, 0)
                        .is_some_and(|value| value.contains('`') || value.contains("$("))
                {
                    ranges.push(literal.range());
                }
            }
        }
        // Later calls may rebind modules or run callbacks. This small proof
        // owns only the first call after its verified literal/module prefix.
        return ranges;
    }
    Vec::new()
}

/// This cheap gate is shared with the evaluator so direct exec/eval dependency
/// recovery is not accidentally disabled before its bounded AST proof runs.
pub(crate) fn has_interpreter_literal_candidates(code: &str, language: ScriptLanguage) -> bool {
    matches!(
        language,
        ScriptLanguage::Python | ScriptLanguage::JavaScript
    ) && (code.contains('`')
        || code.contains("$(")
        || code.contains('\\')
        || code.contains("eval")
        || language == ScriptLanguage::Python && code.contains("exec"))
}

fn evaluated_shell_dependency(
    code: &str,
    language: ScriptLanguage,
    bindings: &LiteralBindings,
) -> Result<Option<String>, MatchError> {
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    if code.len() > MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES {
        return Err(interpreter_literal_parse_error(
            language,
            "evaluated source byte limit",
        ));
    }
    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        _ => return Ok(None),
    };
    let Ok(ast) = AstGrep::try_new(code, grammar) else {
        return Ok(None);
    };
    let root = ast.root();
    for (index, node) in root.dfs().enumerate() {
        if index >= MAX_INTERPRETER_LITERAL_NODES {
            return Err(interpreter_literal_parse_error(
                language,
                "evaluated AST node limit",
            ));
        }
        if node.is_error() || node.is_missing() {
            return Ok(None);
        }
    }
    let mut statements = root
        .children()
        .filter(|node| node.is_named() && node.kind().as_ref() != "comment");
    let Some(call) = statements.next().and_then(literal_statement) else {
        return Ok(None);
    };
    if statements.next().is_some() || !matches!(call.kind().as_ref(), "call" | "call_expression") {
        return Ok(None);
    }
    let Some((module, sink, _)) = bound_literal_callee(&call, language, bindings) else {
        return Ok(None);
    };
    if !match module {
        LiteralModule::PythonOs => matches!(sink.as_str(), "system" | "popen"),
        LiteralModule::PythonSubprocess => matches!(sink.as_str(), "getoutput" | "getstatusoutput"),
        LiteralModule::NodeChildProcess => matches!(sink.as_str(), "exec" | "execSync"),
    } {
        return Ok(None);
    }
    let Some(arguments) = call.field("arguments") else {
        return Ok(None);
    };
    let mut args = arguments
        .children()
        .filter(|node| node.is_named() && node.kind().as_ref() != "comment");
    let Some(value) = args.next() else {
        return Ok(None);
    };
    Ok(
        (args.next().is_none() && value.kind().as_ref() == "identifier")
            .then(|| value.text().into_owned()),
    )
}

/// Recover a bound value only when a direct exec/eval's complete literal
/// program passes that identifier to a known shell sink. Ordinary literals,
/// unknown prefixes, custom globals, and safe evaluated print calls do not
/// become shell programs merely because an exec/eval spelling is present.
fn evaluated_literal_commands<D: ast_grep_core::Doc>(
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> Result<Vec<ReconstructedCommand>, MatchError> {
    if !literal_prefix_has_no_function_hoisting(root, language) {
        return Ok(Vec::new());
    }
    let mut bindings = LiteralBindings::new();
    for statement in root
        .children()
        .filter(|node| node.is_named() && node.kind().as_ref() != "comment")
    {
        let Some(node) = literal_statement(statement) else {
            break;
        };
        if !matches!(node.kind().as_ref(), "call" | "call_expression") {
            if record_literal_binding(&node, language, &mut bindings) {
                continue;
            }
            break;
        }
        let Some(function) = node.field("function") else {
            break;
        };
        if function.kind().as_ref() != "identifier"
            || !matches!(
                (language, function.text().as_ref()),
                (ScriptLanguage::Python, "exec" | "eval") | (ScriptLanguage::JavaScript, "eval")
            )
        {
            break;
        }
        let Some(arguments) = node.field("arguments") else {
            break;
        };
        let mut args = arguments
            .children()
            .filter(|arg| arg.is_named() && arg.kind().as_ref() != "comment");
        let Some(program) = args.next() else {
            break;
        };
        if args.next().is_some() {
            break;
        }
        let Some(source) = static_interpreter_literal(&program, language, 0) else {
            break;
        };
        let Some(dependency) = evaluated_shell_dependency(&source, language, &bindings)? else {
            break;
        };
        let Some(LiteralBinding::Text { value, range }) = bindings.get(&dependency) else {
            break;
        };
        return Ok(vec![ReconstructedCommand {
            command: value.clone(),
            start: range.start,
            end: range.end,
        }]);
    }
    Ok(Vec::new())
}

/// Recover shell commands carried by literal interpreter values (#544).
///
/// A Python assignment can hold ``echo `git branch -d x``` and later hand that
/// value to `os.system` or an opaque imported function. The assignment itself
/// is not a Git invocation, so scanning the whole program as shell loses the
/// substitution after Git's executable-position check. Preserve that existing
/// conservative evidence by examining the actual string value independently.
/// This is not a claim that the outer heredoc performs shell expansion.
/// A plain literal also qualifies when a direct exec/eval's complete source
/// passes its recorded binding to a known shell sink. This dependency proof
/// never promotes unrelated plain strings into executable commands.
///
/// The caller proves the executable source and may permit the complete
/// documentation proof only when there are no unaccounted-for outer consumers.
/// Returning `None` leaves unsupported inline extracts to the existing paths.
/// AST-confirmed named sink arguments remain owned by their existing scanner,
/// so an existing allowlist grant is not denied under a new rule.
/// Original source, including interpolation and unsupported values, still runs
/// through the normal interpreter and raw-pattern analysis.
pub(crate) fn interpreter_literal_shell_commands(
    code: &str,
    language: ScriptLanguage,
    allow_documentation_literals: impl FnOnce() -> Option<bool> + Send + 'static,
    budget: Duration,
) -> Result<Vec<ReconstructedCommand>, MatchError> {
    use std::sync::atomic::{AtomicBool, Ordering};

    if !has_interpreter_literal_candidates(code, language) {
        return Ok(Vec::new());
    }
    if code.len() > MAX_INTERPRETER_LITERAL_SOURCE_BYTES {
        return Err(interpreter_literal_parse_error(
            language,
            "source byte limit",
        ));
    }
    let started = Instant::now();
    if budget.is_zero() {
        return Err(interpreter_literal_timeout(started, budget));
    }
    // A timed-out parser retains its permit until its source and AST are gone;
    // subsequent requests cannot leave an unbounded number of workers running.
    static ACTIVE: AtomicBool = AtomicBool::new(false);
    if ACTIVE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(MatchError::Unavailable {
            language,
            detail: "interpreter literal analysis is still busy".into(),
        });
    }
    struct Permit(&'static AtomicBool);
    impl Drop for Permit {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let permit = Permit(&ACTIVE);
    let source = code.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    let _worker = thread::Builder::new()
        .name("dcg-interpreter-literals".into())
        .spawn(move || {
            // The outer Bash source proof can parse too. Keep it under this
            // worker's deadline and permit along with the interpreter parse.
            // An unsupported inline extraction is not a complete program;
            // leave it to the existing analysis instead of parsing a fragment.
            let result = match allow_documentation_literals() {
                Some(allow_documentation_literals) => interpreter_literal_shell_commands_inner(
                    &source,
                    language,
                    allow_documentation_literals,
                ),
                None => Ok(Vec::new()),
            };
            drop(source);
            drop(permit);
            let _ = sender.send(result);
        })
        .map_err(|error| MatchError::Unavailable {
            language,
            detail: format!("could not start interpreter literal analysis: {error}"),
        })?;
    let remaining = budget
        .checked_sub(started.elapsed())
        .ok_or_else(|| interpreter_literal_timeout(started, budget))?;
    match receiver.recv_timeout(remaining) {
        Ok(result) if started.elapsed() < budget => result,
        Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(interpreter_literal_timeout(started, budget))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(MatchError::Unavailable {
            language,
            detail: "interpreter literal analysis did not complete".into(),
        }),
    }
}

fn interpreter_literal_timeout(started: Instant, budget: Duration) -> MatchError {
    MatchError::Timeout {
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        budget_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
    }
}

fn interpreter_literal_parse_error(language: ScriptLanguage, detail: &str) -> MatchError {
    MatchError::ParseError {
        language,
        detail: format!("interpreter literal analysis exceeded or could not verify {detail}"),
    }
}

fn interpreter_literal_shell_commands_inner(
    code: &str,
    language: ScriptLanguage,
    allow_documentation_literals: bool,
) -> Result<Vec<ReconstructedCommand>, MatchError> {
    use ast_grep_core::{AstGrep, Node};
    use ast_grep_language::SupportLang;

    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        _ => return Ok(Vec::new()),
    };
    if code.len() > MAX_INTERPRETER_LITERAL_SOURCE_BYTES {
        return Err(interpreter_literal_parse_error(
            language,
            "source byte limit",
        ));
    }
    let ast = AstGrep::try_new(code, grammar)
        .map_err(|_| interpreter_literal_parse_error(language, "source grammar"))?;
    let root = ast.root();
    for (index, node) in root.dfs().enumerate() {
        if index >= MAX_INTERPRETER_LITERAL_NODES {
            return Err(interpreter_literal_parse_error(language, "AST node limit"));
        }
        if node.is_error() || node.is_missing() {
            return Err(interpreter_literal_parse_error(language, "source grammar"));
        }
    }
    if allow_documentation_literals {
        let mut proof = DocumentationProof {
            language,
            values: std::collections::BTreeMap::new(),
            literals: Vec::new(),
            remaining_steps: 16_384,
        };
        if proof.expression(&root, 0).is_some() {
            return Ok(Vec::new());
        }
    }
    let mut owned_call_starts =
        engine::literal_exec_sink_starts(code, language, MAX_INTERPRETER_LITERAL_CANDIDATES)
            .ok_or_else(|| interpreter_literal_parse_error(language, "named sink count limit"))?;
    owned_call_starts.extend(
        engine::scan_executing_sink_matches(code, language)
            .into_iter()
            .map(|matched| matched.start),
    );
    owned_call_starts.sort_unstable();
    owned_call_starts.dedup();
    let mut commands = evaluated_literal_commands(&root, language)?;
    let mut pending = vec![root];
    let mut candidates = commands.len();
    let mut payload_bytes = commands
        .iter()
        .map(|command| command.command.len())
        .sum::<usize>();
    while let Some(node) = pending.pop() {
        if node.kind().as_ref() == "comment" {
            continue;
        }
        if matches!(
            node.kind().as_ref(),
            "string" | "template_string" | "concatenated_string"
        ) {
            let range = node.range();
            if commands
                .iter()
                .any(|command| command.start == range.start && command.end == range.end)
            {
                continue;
            }
            if interpreter_literal_has_owned_sink(&node, &owned_call_starts) {
                continue;
            }
            candidates += 1;
            if candidates > MAX_INTERPRETER_LITERAL_CANDIDATES {
                return Err(interpreter_literal_parse_error(
                    language,
                    "literal count limit",
                ));
            }
            if node.range().len() > MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES {
                return Err(interpreter_literal_parse_error(
                    language,
                    "literal byte limit",
                ));
            }
            if let Some(command) = static_interpreter_literal(&node, language, 0) {
                if command.contains('`') || command.contains("$(") {
                    payload_bytes = payload_bytes.saturating_add(command.len());
                    if payload_bytes > MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES {
                        return Err(interpreter_literal_parse_error(
                            language,
                            "aggregate literal byte limit",
                        ));
                    }
                    let range = node.range();
                    commands.push(ReconstructedCommand {
                        command,
                        start: range.start,
                        end: range.end,
                    });
                }
                // An adjacent Python literal sequence is one value. Do not
                // evaluate its individual fragments again as different scripts.
                continue;
            }
        }
        pending.extend(node.children().filter(Node::is_named));
    }
    commands.sort_by_key(|command| command.start);
    Ok(commands)
}

fn interpreter_literal_has_owned_sink<D: ast_grep_core::Doc>(
    literal: &ast_grep_core::Node<'_, D>,
    owned_call_starts: &[usize],
) -> bool {
    let literal_range = literal.range();
    let mut ancestor = literal.parent();
    for _ in 0..64 {
        let Some(node) = ancestor else {
            break;
        };
        if matches!(node.kind().as_ref(), "call" | "call_expression") {
            let Some(arguments) = node.field("arguments") else {
                return false;
            };
            if arguments.range().start > literal_range.start
                || arguments.range().end < literal_range.end
            {
                return false;
            }
            let Some(function) = node.field("function") else {
                return false;
            };
            // Inspect the terminal callee name, not a receiver expression
            // whose own arguments can contain fake `exec(...)` source text.
            let name = match function.kind().as_ref() {
                "identifier" => Some(function),
                "attribute" => function.field("attribute"),
                "member_expression" => function.field("property"),
                _ => None,
            };
            if let Some(name) = name
                && matches!(name.kind().as_ref(), "identifier" | "property_identifier")
            {
                let range = name.range();
                let at = owned_call_starts.partition_point(|start| *start < range.start);
                return owned_call_starts
                    .get(at)
                    .is_some_and(|start| *start < range.end);
            }
            // An unknown nested call can execute this value before passing
            // its result to an enclosing spawn. It cannot borrow that outer
            // call's argv proof or an allowlist grant for the outer rule.
            return false;
        }
        // A named sink owns values assembled into its argv or options, not
        // code that runs while evaluating another argument or a callback.
        // Walking through assignments, sequences or function bodies would
        // let a harmless outer exec hide an indirect shell command inside it.
        if !matches!(
            node.kind().as_ref(),
            "parenthesized_expression"
                | "argument_list"
                | "arguments"
                | "array"
                | "list"
                | "tuple"
                | "object"
                | "dictionary"
                | "pair"
                | "keyword_argument"
                | "concatenated_string"
                | "binary_operator"
                | "binary_expression"
        ) {
            return false;
        }
        ancestor = node.parent();
    }
    false
}

/// Decode complete AST string values, retaining unknown expressions as unknown.
/// Python's raw/bytes/triple strings and JavaScript's static templates have
/// different escape contracts; shell quoting cannot decode either language.
fn static_interpreter_literal<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    depth: usize,
) -> Option<String> {
    if depth >= 64 {
        return None;
    }
    if node.kind().as_ref() == "concatenated_string" {
        let mut joined = String::new();
        for child in node
            .children()
            .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
        {
            joined.push_str(&static_interpreter_literal(&child, language, depth + 1)?);
        }
        return Some(joined);
    }
    if !matches!(node.kind().as_ref(), "string" | "template_string")
        || node.dfs().any(|child| {
            matches!(
                child.kind().as_ref(),
                "interpolation" | "format_expression" | "template_substitution"
            )
        })
    {
        return None;
    }
    if language == ScriptLanguage::JavaScript
        && node.kind().as_ref() == "template_string"
        && node.parent().is_some_and(|parent| {
            parent.kind().as_ref() == "call_expression"
                && parent
                    .field("arguments")
                    .is_some_and(|arguments| arguments.range() == node.range())
        })
    {
        // A tag receives raw and cooked pieces and chooses the result itself.
        // In particular String.raw retains escaped backticks; cooking its
        // template here would invent shell substitutions that never execute.
        return None;
    }
    let raw = node.text();
    let first = raw.find(['\'', '"', '`'])?;
    let prefix = raw[..first].to_ascii_lowercase();
    let python = language == ScriptLanguage::Python;
    if (python
        && !matches!(
            prefix.as_str(),
            "" | "r" | "u" | "b" | "f" | "br" | "rb" | "fr" | "rf"
        ))
        || (!python && !prefix.is_empty())
    {
        return None;
    }
    let quote = raw.as_bytes()[first];
    if python && quote == b'`' {
        return None;
    }
    let width = if python
        && raw
            .as_bytes()
            .get(first..first + 3)
            .is_some_and(|bytes| bytes == [quote; 3])
    {
        3
    } else {
        1
    };
    if raw.len() < first + 2 * width
        || !raw.as_bytes()[raw.len() - width..]
            .iter()
            .all(|byte| *byte == quote)
    {
        return None;
    }
    let body = &raw[first + width..raw.len() - width];
    let bytes_literal = python && prefix.contains('b');
    if bytes_literal && !body.is_ascii() {
        return None;
    }
    let raw_mode = python && prefix.contains('r');
    let formatted = python && prefix.contains('f');
    let mut result = String::new();
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            result.push('\n');
        } else if formatted && matches!(ch, '{' | '}') && chars.peek() == Some(&ch) {
            chars.next();
            result.push(ch);
        } else if ch != '\\' || raw_mode {
            result.push(ch);
        } else {
            let escaped = chars.next()?;
            match escaped {
                '\\' | '\'' | '"' => result.push(escaped),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                'b' => result.push('\u{0008}'),
                'f' => result.push('\u{000c}'),
                'v' => result.push('\u{000b}'),
                'a' if python => result.push('\u{0007}'),
                '\n' => {}
                '\u{2028}' | '\u{2029}' if !python => {}
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                }
                '0'..='7' if python => {
                    let mut value = escaped.to_digit(8)?;
                    for _ in 0..2 {
                        let Some(digit) = chars.peek().and_then(|ch| ch.to_digit(8)) else {
                            break;
                        };
                        chars.next();
                        value = value * 8 + digit;
                    }
                    result.push(char::from_u32(value)?);
                }
                'x' => result.push(interpreter_hex_escape(&mut chars, 2)?),
                'u' | 'U' if python && !bytes_literal => {
                    result.push(interpreter_hex_escape(
                        &mut chars,
                        if escaped == 'u' { 4 } else { 8 },
                    )?);
                }
                'u' if !python => {
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        let mut value = 0u32;
                        let mut digits = 0usize;
                        loop {
                            let next = chars.next()?;
                            if next == '}' {
                                break;
                            }
                            digits += 1;
                            if digits > 6 {
                                return None;
                            }
                            value = value * 16 + next.to_digit(16)?;
                        }
                        if digits == 0 {
                            return None;
                        }
                        result.push(char::from_u32(value)?);
                    } else {
                        result.push(interpreter_hex_escape(&mut chars, 4)?);
                    }
                }
                'N' if python && !bytes_literal => return None,
                '0' if !python && !chars.peek().is_some_and(char::is_ascii_digit) => {
                    result.push('\0');
                }
                '0'..='9' if !python => return None,
                _ if python => {
                    // Python retains an unrecognized escape's backslash.
                    // Removing it would turn literal shell syntax into a live
                    // substitution, unlike JavaScript's identity escapes.
                    result.push('\\');
                    result.push(escaped);
                }
                _ => result.push(escaped),
            }
        }
    }
    // A Python bytes value is a byte sequence, not UTF-8 encoded Unicode.
    // Non-ASCII bytes cannot be represented faithfully as a shell String.
    (!bytes_literal || result.is_ascii()).then_some(result)
}

fn interpreter_hex_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    count: usize,
) -> Option<char> {
    let mut value = 0u32;
    for _ in 0..count {
        value = value
            .checked_mul(16)?
            .checked_add(chars.next()?.to_digit(16)?)?;
    }
    char::from_u32(value)
}

/// The default executable-source matcher, including the shared core policy.
/// Custom `AstMatcher::with_patterns` instances retain their explicit corpus.
#[derive(Debug, Default)]
pub struct DefaultPolicyMatcher;

/// The entry point used by the evaluator after source extraction.
pub static DEFAULT_MATCHER: LazyLock<DefaultPolicyMatcher> =
    LazyLock::new(DefaultPolicyMatcher::default);

impl Deref for DefaultPolicyMatcher {
    type Target = engine::AstMatcher;

    fn deref(&self) -> &Self::Target {
        &engine::DEFAULT_MATCHER
    }
}

impl DefaultPolicyMatcher {
    /// Match both the configured built-in AST corpus and core write policy.
    /// A source-budget failure is an error, never a successful empty result.
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let protected = protected_matches(code, language, protected_scan_budget());
        let matches = engine::DEFAULT_MATCHER.find_matches(code, language);
        compose_policy_matches(matches, protected)
    }

    /// [`Self::find_matches`] with one explicit time budget for both the
    /// pattern corpus and the protected-write classifier: the second reading
    /// the evaluator gives a body whose first one the host cut short.
    pub fn find_matches_with_timeout(
        &self,
        code: &str,
        language: ScriptLanguage,
        timeout: Duration,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let protected = protected_matches(code, language, timeout);
        let matches = engine::DEFAULT_MATCHER.find_matches_with_timeout(code, language, timeout);
        compose_policy_matches(matches, protected)
    }

    /// Return the first blocking match from the composed default matcher.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()?
            .into_iter()
            .find(|hit| hit.severity.blocks_by_default())
    }
}

/// Merge the pattern corpus's matches with the protected-write classifier's.
fn compose_policy_matches(
    matches: Result<Vec<PatternMatch>, MatchError>,
    protected: Result<Vec<PatternMatch>, MatchError>,
) -> Result<Vec<PatternMatch>, MatchError> {
    let mut matches = matches?;
    match protected {
        Ok(protected) => matches.extend(protected),
        // A new classifier's limit must not suppress a deletion/exec
        // denial the existing engine has already established.
        Err(_) if matches.iter().any(|hit| hit.severity.blocks_by_default()) => {}
        Err(error) => return Err(error),
    }
    matches.sort_by_key(|hit| hit.start);
    Ok(matches)
}

/// Deletion backstop plus protected-write detection on extracted source.
///
/// Retains the existing deletion backstop and adds protected writes on the SAME
/// extracted-source path, before the expensive full-pattern scan. This is
/// independent of core.filesystem's shell-keyword candidate gate.
/// Returns all established rule families: the caller must apply a rule grant
/// to each finding, not treat the first granted rule as a grant for the script.
#[must_use]
pub fn scan_filesystem_sink_fallback(code: &str, language: ScriptLanguage) -> Vec<PatternMatch> {
    let existing = engine::scan_filesystem_sink_fallback(code, language);
    let mut matches =
        protected_matches(code, language, protected_scan_budget()).unwrap_or_default();
    // Keep the established deletion precedence, but do not discard another
    // policy finding before the evaluator has applied per-rule allowlists.
    if let Some(existing) = existing {
        matches.insert(0, existing);
    }
    matches
}

pub(crate) fn protected_scan_budget() -> Duration {
    // Match the pattern engine's only-raise timeout convention. No new knob,
    // no smaller production deadline, and no dependence on the working path.
    #[cfg(test)]
    const FLOOR_MS: u64 = 5_000;
    #[cfg(not(test))]
    const FLOOR_MS: u64 = 20;
    static MILLIS: LazyLock<u64> = LazyLock::new(|| {
        std::env::var("DCG_AST_TIMEOUT_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .map_or(FLOOR_MS, |ms| ms.clamp(FLOOR_MS, 60_000))
    });
    Duration::from_millis(*MILLIS)
}

fn protected_matches(
    code: &str,
    language: ScriptLanguage,
    budget: Duration,
) -> Result<Vec<PatternMatch>, MatchError> {
    if !credential_files::source_scan_required(code, language) {
        return Ok(Vec::new());
    }
    if code.len() > 256 * 1024 {
        return Err(MatchError::ParseError {
            language,
            detail: "protected-write source exceeds the byte limit".into(),
        });
    }
    let started = Instant::now();
    // Do not parse another language AST unbounded on the hook thread. The
    // worker owns its input, has byte/node/depth caps, and never executes code.
    // A timed-out receiver cannot leave the worker blocked on a send.
    let source = code.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    let _worker = thread::Builder::new()
        .name("dcg-protected-source".into())
        .spawn(move || {
            let _ = sender.send(credential_files::scan_extracted(&source, language));
        })
        .map_err(|error| MatchError::Unavailable {
            language,
            detail: format!("could not start protected-write analysis: {error}"),
        })?;
    let hits = match receiver.recv_timeout(budget) {
        Ok(result) => result.map_err(|detail| MatchError::ParseError {
            language,
            detail: detail.to_string(),
        })?,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(MatchError::Timeout {
                elapsed_ms: started.elapsed().as_millis() as u64,
                budget_ms: budget.as_millis() as u64,
            });
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(MatchError::Unavailable {
                language,
                detail: "protected-write analysis did not complete".into(),
            });
        }
    };
    Ok(hits
        .into_iter()
        .map(|hit| PatternMatch {
            rule_id: format!("core.filesystem.{}", hit.rule),
            reason: hit.reason,
            matched_text_preview: code
                .get(hit.span.clone())
                .unwrap_or("")
                .chars()
                .take(80)
                .collect(),
            line_number: code[..hit.span.start]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count()
                + 1,
            start: hit.span.start,
            end: hit.span.end,
            severity: Severity::Critical,
            suggestion: Some(
                "Stage the proposed content in a scratch file for review; use dcg allow-once for an approved write."
                    .into(),
            ),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_exec_data_literals_keep_their_roles_544() {
        for (language, source) in [
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)']);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.execSync('printf ready', {env: {NOTICE: '$(git reset --hard)'}});",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', '%s', '$(git reset --hard)'])",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', 'ready'], env={'NOTICE': '$(git reset --hard)'})",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('node:child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {shell: false});",
            ),
        ] {
            let ranges = inert_documentation_literal_ranges(source, language);
            assert_eq!(ranges.len(), 1, "named data must retain its role: {source}");
            assert_eq!(
                source.get(ranges[0].clone()),
                Some("'$(git reset --hard)'"),
                "mask only the complete static data literal: {source}"
            );
        }
    }

    #[test]
    fn named_exec_data_literals_do_not_hide_executable_source_544() {
        for (language, source) in [
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.execSync('echo $(git reset --hard)');",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {shell: true});",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {'sh\u0065ll': true});",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {shell: mode});",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {...options});",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync = run; cp.spawnSync('printf', ['%s', '$(git reset --hard)']);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('./helper'); cp.spawnSync('printf', ['%s', '$(git reset --hard)']);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.exec('printf ready', () => { const s = 'echo $(git reset --hard)'; cp.execSync(s); });",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', run('$(git reset --hard)')]);",
            ),
            (
                ScriptLanguage::Python,
                "import os\nos.system('echo $(git reset --hard)')",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', '%s', '$(git reset --hard)'], shell=True)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', '-c', '$(git reset --hard)'], executable='/bin/sh')",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', '%s', '$(git reset --hard)'], **options)",
            ),
        ] {
            assert!(
                inert_documentation_literal_ranges(source, language).is_empty(),
                "execution and unknown ownership retain their source evidence: {source}"
            );
        }
    }

    #[test]
    fn named_exec_data_proof_rejects_hoisted_javascript_functions_544() {
        for declaration in [
            "function require() { return {spawnSync(_file, argv) { module.require('child_process').execSync(argv[1]); }}; }",
            "function* require() { yield 'unused'; }",
            "async function require() { return {}; }",
        ] {
            let source = format!(
                "const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)']); {declaration}"
            );
            assert!(
                inert_documentation_literal_ranges(&source, ScriptLanguage::JavaScript).is_empty(),
                "a hoisted declaration can replace the standard module binding: {source}"
            );
        }
    }

    #[test]
    fn named_exec_input_and_environment_sources_remain_visible_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['sh'], input='$(git reset --hard)', text=True)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('sh', [], {input: '$(git reset --hard)'});",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.execFileSync('sh', [], {input: '$(git reset --hard)'});",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.execSync('sh', {input: '$(git reset --hard)'});",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['/bin/bash', '-c', 'true'], env={'BASH_ENV': '$(git reset --hard)'})",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('/bin/bash', ['-c', 'true'], {env: {BASH_ENV: '$(git reset --hard)'}});",
            ),
            (
                ScriptLanguage::JavaScript,
                r#"const cp = require('child_process'); cp.spawnSync('node', ['-e', ''], {env: {NODE_OPTIONS: "--import=\"data:text/javascript,import cp from 'node:child_process';cp.execSync('echo $(git reset --hard)')\""}});"#,
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['sh', '-i'], env={'ENV': '$(git reset --hard)'})",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('sh', ['-i'], {env: {ENV: '$(git reset --hard)'}});",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['sh'], env={key: '$(git reset --hard)'})",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('sh', [], {env: {[key]: '$(git reset --hard)'}});",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.spawnSync('sh', [], {env: {NOTICE: '$(git reset --hard)', ...environment}});",
            ),
        ] {
            assert!(
                inert_documentation_literal_ranges(source, language).is_empty(),
                "stdin/startup source and unproved environments retain their bytes: {source}"
            );
        }
    }

    #[test]
    fn named_exec_option_keys_require_exact_semantics_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', '-c', '$(git reset --hard)'], ｅxecutable='/bin/sh')",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['printf', '$(git reset --hard)'], ｓｈｅｌｌ=True)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['sh'], ｉｎｐｕｔ='$(git reset --hard)', text=True)",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const cp = require('child_process'); cp.spawnSync('printf', ['%s', '$(git reset --hard)'], {sh\u0065ll:true});",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const cp = require('child_process'); cp.spawnSync('sh', [], {in\u0070ut: '$(git reset --hard)'});",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const cp = require('child_process'); cp.spawnSync('sh', [], {'in\u0070ut': '$(git reset --hard)'});",
            ),
        ] {
            assert!(
                inert_documentation_literal_ranges(source, language).is_empty(),
                "encoded option names cannot acquire a different argument role: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literals_recover_proven_exec_eval_dependencies_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\neval('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\ns = 'git branch -d x'\nexec('subprocess.getoutput(s)')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = 'git branch -d x'; eval(\"require('child_process').execSync(s)\");",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); const s = 'git branch -d x'; eval('cp.execSync(s)');",
            ),
        ] {
            assert!(has_interpreter_literal_candidates(source, language));
            let commands = interpreter_literal_shell_commands_inner(source, language, true)
                .expect("bounded direct evaluation dependency");
            assert_eq!(commands.len(), 1, "missing executed dependency: {source}");
            assert_eq!(commands[0].command, "git branch -d x");
            assert_eq!(
                source.get(commands[0].start..commands[0].end),
                Some("'git branch -d x'"),
                "report the bound value's original source span: {source}"
            );
        }
        let source = "import os\ns = 'git branch -d x'\ns = 'printf ready'\nexec('os.system(s)')";
        let commands =
            interpreter_literal_shell_commands_inner(source, ScriptLanguage::Python, true)
                .expect("the latest literal assignment owns the value");
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].command, "printf ready");

        let payload = format!("echo $(git reset --hard){}", " ".repeat(40 * 1024));
        let source = format!("import os\ns = '{payload}'\nexec('os.system(s)')");
        let commands =
            interpreter_literal_shell_commands_inner(&source, ScriptLanguage::Python, true)
                .expect("one literal must count once even when two recovery routes identify it");
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].command, payload);
    }

    #[test]
    fn interpreter_literals_do_not_invent_exec_eval_dependencies_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "s = 'git branch -d x'\nexec('print(s)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nexec('os.system(other)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nexec('os.system(s)', {'s': 'printf ready'})",
            ),
            (
                ScriptLanguage::Python,
                "import os\nexec = print\ns = 'git branch -d x'\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nmutate()\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nexec(source)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = 'git branch -d x'; eval('console.log(s)');",
            ),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('./helper'); const s = 'git branch -d x'; eval('cp.execSync(s)');",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = 'git branch -d x'; const example = \"eval('cp.execSync(s)')\";",
            ),
        ] {
            assert!(
                interpreter_literal_shell_commands_inner(source, language, true)
                    .expect("unsupported dependencies retain existing analysis")
                    .is_empty(),
                "an unrelated literal must not become executed shell source: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literals_decline_hoisted_javascript_eval_544() {
        for declaration in [
            "function eval() {}",
            "function* eval() {}",
            "async function eval() {}",
        ] {
            let source = format!(
                "const s = 'git branch -d x'; eval(\"require('child_process').execSync(s)\"); {declaration}"
            );
            assert!(
                interpreter_literal_shell_commands_inner(
                    &source,
                    ScriptLanguage::JavaScript,
                    true,
                )
                .expect("unproved hoisted bindings retain the original analysis")
                .is_empty(),
                "a hoisted eval declaration must not invent an execution dependency: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literals_reject_encoded_binding_identities_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nｅxec = 'data'\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git branch -d x'\nｅval = 'data'\neval('os.system(s)')",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const cp = require('child_process'); const s = 'git branch -d x'; const e\u0076al = 'data'; eval('cp.execSync(s)');",
            ),
        ] {
            assert!(
                interpreter_literal_shell_commands_inner(source, language, true)
                    .expect("uncertain binding identities retain the original analysis")
                    .is_empty(),
                "an encoded rebinding must not be mistaken for the builtin API: {source}"
            );
        }
        let source = "import os\ns = 'printf élève'\nexec('os.system(s)')";
        let commands =
            interpreter_literal_shell_commands_inner(source, ScriptLanguage::Python, true)
                .expect("Unicode literal payloads retain their established value");
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].command, "printf élève");
    }

    #[test]
    fn interpreter_literal_shell_commands_recover_indirect_payloads_544() {
        for (language, source, literal, expected) in [
            (
                ScriptLanguage::Python,
                "import os\ns = 'echo `git branch -d x`'\nos.system(s)",
                "'echo `git branch -d x`'",
                "echo `git branch -d x`",
            ),
            (
                ScriptLanguage::Python,
                "from helper import run\ns = 'echo $(git reset --hard)'\nrun(s)",
                "'echo $(git reset --hard)'",
                "echo $(git reset --hard)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = 'echo `git branch -d x`'; require('child_process').execSync(s);",
                "'echo `git branch -d x`'",
                "echo `git branch -d x`",
            ),
            (
                ScriptLanguage::JavaScript,
                "const run = require('./helper'); const s = 'echo $(git reset --hard)'; run(s);",
                "'echo $(git reset --hard)'",
                "echo $(git reset --hard)",
            ),
            (
                ScriptLanguage::Python,
                "# Unicode source: élève\ns = 'echo ' '`git branch -d x`'\nrun(s)",
                "'echo ' '`git branch -d x`'",
                "echo `git branch -d x`",
            ),
        ] {
            let commands = interpreter_literal_shell_commands_inner(source, language, true)
                .expect("bounded, valid interpreter source");
            assert_eq!(commands.len(), 1, "missing literal evidence in {source}");
            assert_eq!(commands[0].command, expected, "source: {source}");
            assert_eq!(
                source.get(commands[0].start..commands[0].end),
                Some(literal),
                "decoded values must retain the original byte span: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literal_shell_commands_require_the_outer_documentation_proof_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "s = 'echo `git branch -d x`'\nprint(s)",
            ),
            (
                ScriptLanguage::Python,
                "s = 'echo $(git reset --hard)'\nopen('README.md', 'w').write(s)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = 'echo `git branch -d x`'; console.log(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('fs'); const s = 'echo $(git reset --hard)'; fs.writeFileSync('README.md', s);",
            ),
        ] {
            assert!(
                interpreter_literal_shell_commands_inner(source, language, true)
                    .expect("complete documentation proof")
                    .is_empty(),
                "proven documentation must not become shell: {source}"
            );
            assert_eq!(
                interpreter_literal_shell_commands_inner(source, language, false)
                    .expect("literal source without an outer consumer proof")
                    .len(),
                1,
                "a later shell consumer must retain the literal evidence: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literal_shell_commands_decode_encoded_markers_before_gating_544() {
        for (language, execution, documentation) in [
            (
                ScriptLanguage::Python,
                r"s = 'echo \x60git branch -d x\x60'; os.system(s)",
                r"s = 'echo \x60git branch -d x\x60'; print(s)",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = 'echo \u0060git branch -d x\u0060'; run(s);",
                r"const s = 'echo \u0060git branch -d x\u0060'; console.log(s);",
            ),
        ] {
            let commands = interpreter_literal_shell_commands(
                execution,
                language,
                || Some(true),
                protected_scan_budget(),
            )
            .expect("a supported encoded marker must reach literal analysis");
            assert_eq!(commands.len(), 1);
            assert_eq!(commands[0].command, "echo `git branch -d x`");
            assert!(
                interpreter_literal_shell_commands(
                    documentation,
                    language,
                    || Some(true),
                    protected_scan_budget(),
                )
                .expect("encoded documentation retains the same proof")
                .is_empty()
            );
        }
        assert!(
            interpreter_literal_shell_commands(
                "print(\\",
                ScriptLanguage::Python,
                || None,
                protected_scan_budget(),
            )
            .expect("an unverified inline extraction keeps its existing analysis")
            .is_empty()
        );
    }

    #[test]
    fn interpreter_literal_shell_commands_decode_each_language_exactly_544() {
        for (language, source, expected) in [
            (
                ScriptLanguage::Python,
                r"s = 'echo \`git branch -d x\`'; run(s)",
                r"echo \`git branch -d x\`",
            ),
            (
                ScriptLanguage::Python,
                r"s = r'echo \`git branch -d x\`'; run(s)",
                r"echo \`git branch -d x\`",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = 'echo \`git branch -d x\`'; run(s);",
                "echo `git branch -d x`",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = `echo \`git branch -d x\``; run(s);",
                "echo `git branch -d x`",
            ),
            (
                ScriptLanguage::Python,
                "s = '''echo `git branch -d x`\nsecond line'''\nrun(s)",
                "echo `git branch -d x`\nsecond line",
            ),
            (
                ScriptLanguage::Python,
                "s = b'echo `git branch -d x`'\nrun(s)",
                "echo `git branch -d x`",
            ),
            (
                ScriptLanguage::Python,
                r"s = f'echo {{note}} \x60git branch -d x`'; run(s)",
                "echo {note} `git branch -d x`",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = 'echo \u{60}git branch -d x`'; run(s);",
                "echo `git branch -d x`",
            ),
            (
                ScriptLanguage::Python,
                "s = 'echo `git branch -d \\\nx`'\nrun(s)",
                "echo `git branch -d x`",
            ),
        ] {
            let commands = interpreter_literal_shell_commands_inner(source, language, false)
                .expect("bounded literal source");
            assert_eq!(commands.len(), 1, "source: {source}");
            assert_eq!(commands[0].command, expected, "source: {source}");
        }
    }

    #[test]
    fn interpreter_literal_shell_commands_preserve_named_sink_ownership_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['echo', '`git branch -d x`'])",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run('echo `git branch -d x`')",
            ),
            (
                ScriptLanguage::Python,
                "import os\nos.system('git reset --hard; echo `git branch -d x`')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('child_process').spawnSync('echo', ['`git branch -d x`']);",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('child_process').execSync('echo `git branch -d x`');",
            ),
            (
                ScriptLanguage::Python,
                "subprocess.run(['printf', 'ready'], preexec_fn=lambda: os.system('git reset --hard; echo $(printf done)'))",
            ),
            (
                ScriptLanguage::JavaScript,
                "cp.exec('printf ready', () => { cp.execSync('git reset --hard; echo $(printf done)'); });",
            ),
            (
                ScriptLanguage::Python,
                "subprocess.run(['printf', 'ready'], preexec_fn=lambda: subprocess.run(('echo', '$(git reset --hard)')))",
            ),
            (
                ScriptLanguage::JavaScript,
                "cp.exec('printf ready', () => { cp.spawnSync('echo', ['$(git reset --hard)']); });",
            ),
            (
                ScriptLanguage::Python,
                "subprocess.run(args=['printf', 'ready'], env={'NOTE': 'echo $(git reset --hard)'})",
            ),
            (
                ScriptLanguage::JavaScript,
                "cp.exec('printf ready', {env: {NOTE: 'echo $(git reset --hard)'}});",
            ),
            (
                ScriptLanguage::Python,
                "os.system(('git reset --hard; ' + 'echo $(printf done)'))",
            ),
            (
                ScriptLanguage::JavaScript,
                "cp.execSync('git reset --hard; ' + 'echo $(printf done)');",
            ),
        ] {
            assert!(
                interpreter_literal_shell_commands_inner(source, language, false)
                    .expect("the named sink already owns its complete literal arguments")
                    .is_empty(),
                "literal recovery must not reinterpret argv or duplicate a named sink rule: {source}"
            );
        }
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "consume('echo `git branch -d x`; system(\"plain\")')",
            ),
            (
                ScriptLanguage::JavaScript,
                "consume('echo `git branch -d x`; exec(\"plain\")');",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('exec(\"plain\")').consume('echo `git branch -d x`');",
            ),
            (
                ScriptLanguage::Python,
                "subprocess.run(['echo', transform('echo `git branch -d x`'), 'git reset --hard'])",
            ),
            (
                ScriptLanguage::JavaScript,
                "cp.execSync(('echo `git branch -d x`'));",
            ),
        ] {
            let commands = interpreter_literal_shell_commands_inner(source, language, false)
                .expect("unowned literal retains its conservative evidence");
            assert_eq!(commands.len(), 1, "a false callee claim hid {source}");
            assert!(commands[0].command.contains("`git branch -d x`"));
        }
    }

    #[test]
    fn interpreter_literal_shell_commands_do_not_borrow_outer_sink_ownership_544() {
        for (language, source, literal, expected) in [
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); cp.exec('printf ready', function () { const s = 'echo $(git reset --hard)'; cp.execSync(s); });",
                "'echo $(git reset --hard)'",
                "echo $(git reset --hard)",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const cp = require('child_process'); cp.exec('printf ready', () => { const s = 'echo \u0060git reset --hard\u0060'; cp.execSync(s); });",
                r"'echo \u0060git reset --hard\u0060'",
                "echo `git reset --hard`",
            ),
            (
                ScriptLanguage::JavaScript,
                "let s; const cp = require('child_process'); cp.exec('printf ready', (s = 'echo $(git reset --hard)', cp.execSync(s)));",
                "'echo $(git reset --hard)'",
                "echo $(git reset --hard)",
            ),
            (
                ScriptLanguage::Python,
                "import os, subprocess\nsubprocess.run(['printf', 'ready'], preexec_fn=lambda: ((s := 'echo $(git reset --hard)'), os.system(s)))",
                "'echo $(git reset --hard)'",
                "echo $(git reset --hard)",
            ),
        ] {
            let commands = interpreter_literal_shell_commands_inner(source, language, false)
                .expect("bounded callback and argument-expression source");
            assert_eq!(
                commands.len(),
                1,
                "an outer sink's harmless argv must not hide executable source: {source}"
            );
            assert_eq!(commands[0].command, expected, "source: {source}");
            assert_eq!(
                source.get(commands[0].start..commands[0].end),
                Some(literal),
                "recovery must identify the inner literal, not the outer sink: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literal_shell_commands_do_not_invent_fragment_values_544() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "# documentation: `git branch -d x`\nprint('plain text')",
            ),
            (
                ScriptLanguage::JavaScript,
                "// documentation: $(git reset --hard)\nconsole.log('plain text');",
            ),
            (
                ScriptLanguage::Python,
                "s = f'echo `git branch -d x` {name}'\nrun(s)",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = `echo \`git branch -d x\` ${name}`; run(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = String.raw`echo \`git branch -d x\``; require('child_process').execSync(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = transform`echo \`git branch -d x\``; run(s);",
            ),
            (
                ScriptLanguage::Python,
                r"s = 'echo `git branch -d x` \N{UNKNOWN CHARACTER}'; run(s)",
            ),
            (
                ScriptLanguage::JavaScript,
                r"const s = 'echo `git branch -d x` \uD800'; run(s);",
            ),
            (
                ScriptLanguage::Python,
                r"s = b'echo `git branch -d x` \xff'; run(s)",
            ),
        ] {
            assert!(
                interpreter_literal_shell_commands_inner(source, language, false)
                    .expect("unsupported values retain their original source analysis")
                    .is_empty(),
                "an unknown value must not be reconstructed as a complete command: {source}"
            );
        }
    }

    #[test]
    fn interpreter_literal_shell_commands_report_analysis_limits_544() {
        let oversized = format!(
            "s = '`git branch -d x`'\n#{}",
            "x".repeat(MAX_INTERPRETER_LITERAL_SOURCE_BYTES)
        );
        let many_nodes = format!("# `git branch -d x`\n{}", "pass\n".repeat(4096));
        let many_literals =
            "consume('`git branch -d x`')\n".repeat(MAX_INTERPRETER_LITERAL_CANDIDATES + 1);
        let large_literal = format!(
            "consume('`git branch -d x`{}')",
            "x".repeat(MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES)
        );
        let aggregate = format!(
            "consume('`git branch -d x`{}')\nconsume('`git branch -d x`{}')",
            "x".repeat(MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES / 2),
            "y".repeat(MAX_INTERPRETER_LITERAL_PAYLOAD_BYTES / 2),
        );
        for source in [
            "s = '`git branch -d x`'\nrun(s",
            &oversized,
            &many_nodes,
            &many_literals,
            &large_literal,
            &aggregate,
        ] {
            assert!(
                matches!(
                    interpreter_literal_shell_commands_inner(source, ScriptLanguage::Python, false),
                    Err(MatchError::ParseError { .. })
                ),
                "incomplete analysis must not be an empty successful scan"
            );
        }
        let many_calls =
            "run('plain')\n".repeat(MAX_INTERPRETER_LITERAL_CANDIDATES + 1) + "# `git`";
        assert!(matches!(
            interpreter_literal_shell_commands_inner(&many_calls, ScriptLanguage::Python, false),
            Err(MatchError::ParseError { .. })
        ));
        assert!(matches!(
            interpreter_literal_shell_commands(
                "s = '`git branch -d x`'\nrun(s)",
                ScriptLanguage::Python,
                || Some(false),
                Duration::ZERO,
            ),
            Err(MatchError::Timeout { .. })
        ));
        assert!(
            interpreter_literal_shell_commands(
                "print('plain text')",
                ScriptLanguage::Python,
                || Some(false),
                Duration::ZERO,
            )
            .expect("no substitution candidate needs no worker")
            .is_empty()
        );
    }

    #[test]
    fn documentation_literal_proof_handles_text_edits_and_literal_forms() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "s = \"run `git branch -d x` later\"\nprint(s)",
            ),
            (
                ScriptLanguage::Python,
                "s = r'''run `git branch -d x` later'''\nprint(s)",
            ),
            (
                ScriptLanguage::Python,
                "s = b'run `git branch -d x` later'\nprint(s)",
            ),
            (
                ScriptLanguage::Python,
                "s = 'run ' '`git branch -d x`' ' later'\nprint(s)",
            ),
            (ScriptLanguage::Python, "'''run `git branch -d x` later'''"),
            (
                ScriptLanguage::Python,
                "n = 1\ns = f'run `git branch -d x` after {n}'\nprint(s)",
            ),
            (
                ScriptLanguage::Python,
                "p = 'README.md'\ns = open(p).read()\ns = s.replace('old', '''run `git checkout main && git branch -d x` later''')\nopen(p, 'w').write(s)",
            ),
            (
                ScriptLanguage::Python,
                "open('README.md', 'w', encoding='utf-8').write('run `git branch -d x` later')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = \"run `git branch -d x` later\"; console.log(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const n = 1; const s = `run \\`git branch -d x\\` after ${n}`; console.log(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const fs = require('node:fs'); const p = 'README.md'; const s = fs.readFileSync(p, 'utf8').replace('old', 'run `git branch -d x` later'); fs.writeFileSync(p, s);",
            ),
        ] {
            let ranges = inert_documentation_literal_ranges(source, language);
            assert!(
                !ranges.is_empty(),
                "data-only source must be proved: {source}"
            );
            for range in ranges {
                assert!(source.get(range).is_some_and(|text| text.contains('`')));
            }
        }
    }

    #[test]
    fn documentation_literal_proof_rejects_execution_and_unknown_effects() {
        for (language, source) in [
            (ScriptLanguage::Python, "s = '`git branch -d x`'\nrun(s)"),
            (
                ScriptLanguage::Python,
                "s = '`git branch -d x`'\nos.system(s)",
            ),
            (
                ScriptLanguage::Python,
                "s = '`git branch -d x`'\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "s = '`git branch -d x`'\nopen('README.md', 'w', encoding='custom_codec').write(s)",
            ),
            (
                ScriptLanguage::Python,
                "s = '`git branch -d x`'\nopen('README.md', 'w', opener=run).write(s)",
            ),
            (
                ScriptLanguage::Python,
                "print = os.system\nprint('`git branch -d x`')",
            ),
            (
                ScriptLanguage::Python,
                "s: dangerous() = '`git branch -d x`'",
            ),
            (ScriptLanguage::Python, "obj.value = '`git branch -d x`'"),
            (ScriptLanguage::Python, "s = f'`git branch -d x` {run()}'"),
            (
                ScriptLanguage::Python,
                "s = f'`git branch -d x` {1:{run()}}'",
            ),
            (ScriptLanguage::Python, "s = '`git branch -d x`'\nprint(s"),
            (
                ScriptLanguage::JavaScript,
                "const s = '`git branch -d x`'; run(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = '`git branch -d x`'; Function('run(s)')();",
            ),
            (
                ScriptLanguage::JavaScript,
                "console.log = require('child_process').execSync; console.log('`git branch -d x`');",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = `run \\`git branch -d x\\` ${run()}`;",
            ),
            (
                ScriptLanguage::JavaScript,
                "const s = tag`git branch -d x`;",
            ),
            (
                ScriptLanguage::JavaScript,
                "const {s = run()} = '`git branch -d x`';",
            ),
            (
                ScriptLanguage::JavaScript,
                "obj.value = '`git branch -d x`';",
            ),
            (ScriptLanguage::Ruby, "puts '`git branch -d x`'"),
        ] {
            assert!(
                inert_documentation_literal_ranges(source, language).is_empty(),
                "unproved source must retain its conservative scan: {source}"
            );
        }
        let oversized = format!("s = '`git branch -d x`'\n#{}", "x".repeat(256 * 1024));
        assert!(inert_documentation_literal_ranges(&oversized, ScriptLanguage::Python).is_empty());
        let mut nested_template = "'`git branch -d x`'".to_string();
        for _ in 0..32 {
            nested_template = format!("`text ${{{nested_template}}}`");
        }
        assert!(
            inert_documentation_literal_ranges(&nested_template, ScriptLanguage::JavaScript)
                .is_empty(),
            "nested interpolation must withdraw its proof on the shared work bound"
        );
    }

    #[test]
    fn extracted_source_reaches_shared_core_rule_before_full_pattern_matching() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "open('/home/u/.ssh/authorized_keys', 'a')",
            ),
            (ScriptLanguage::Ruby, "File.write('/home/u/.bashrc', 'x')"),
            (
                ScriptLanguage::JavaScript,
                "require('fs').appendFileSync('/home/u/.ssh/authorized_keys', 'x')",
            ),
            (
                ScriptLanguage::TypeScript,
                "const p: string = '/home/u/.bashrc'; require('fs').writeFileSync(p, 'x')",
            ),
        ] {
            let early = scan_filesystem_sink_fallback(source, language);
            assert_eq!(early.len(), 1, "{source}: {early:?}");
            let early = &early[0];
            assert_eq!(early.rule_id, "core.filesystem.credential-file-write");
            assert_eq!(early.severity, Severity::Critical);
            assert!(source.get(early.start..early.end).is_some());
            assert!(
                DEFAULT_MATCHER
                    .find_matches(source, language)
                    .unwrap()
                    .iter()
                    .any(|hit| hit.rule_id == "core.filesystem.credential-file-write")
            );
        }
    }

    #[test]
    fn default_matcher_preserves_both_rule_families_in_source_order() {
        for source in [
            "open('/home/u/.bashrc', 'w'); open('.git/config', 'w')",
            "open('.git/config', 'w'); open('/home/u/.bashrc', 'w')",
        ] {
            let hits = DEFAULT_MATCHER
                .find_matches(source, ScriptLanguage::Python)
                .unwrap();
            let core: Vec<_> = hits
                .iter()
                .filter(|hit| hit.rule_id.starts_with("core.filesystem."))
                .collect();
            assert_eq!(core.len(), 2, "{source}: {hits:?}");
            assert!(
                core.iter()
                    .any(|hit| hit.rule_id.ends_with("credential-file-write"))
            );
            assert!(
                core.iter()
                    .any(|hit| hit.rule_id.ends_with("git-internals-write"))
            );
            assert!(core[0].start < core[1].start);
        }
    }

    #[test]
    fn early_backstop_preserves_both_rules_at_one_transfer_span() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os; os.replace('.git/config', '.bashrc')",
            ),
            (
                ScriptLanguage::Ruby,
                "File.rename('.git/config', '.bashrc')",
            ),
            (
                ScriptLanguage::JavaScript,
                "require('fs').renameSync('.git/config', '.bashrc')",
            ),
        ] {
            for hits in [
                scan_filesystem_sink_fallback(source, language),
                DEFAULT_MATCHER.find_matches(source, language).unwrap(),
            ] {
                let core: Vec<_> = hits
                    .iter()
                    .filter(|hit| hit.rule_id.starts_with("core.filesystem."))
                    .collect();
                assert_eq!(core.len(), 2, "{source}: {hits:?}");
                assert_ne!(core[0].rule_id, core[1].rule_id, "{source}");
                assert_eq!((core[0].start, core[0].end), (core[1].start, core[1].end));
            }
        }
    }

    #[test]
    fn early_backstop_retains_writes_beside_an_allowlistable_deletion() {
        let source = "FileUtils.rm_rf('/home/u/work'); File.write('/etc/shadow', 'x')";
        let hits = scan_filesystem_sink_fallback(source, ScriptLanguage::Ruby);
        assert!(hits[0].rule_id.starts_with("heredoc.ruby.fileutils_rm_rf"));
        assert!(
            hits.iter()
                .any(|hit| hit.rule_id == "core.filesystem.credential-file-write")
        );
    }

    #[test]
    fn protected_write_limits_report_incomplete_analysis() {
        let oversized = format!("# open\n{}", " ".repeat(256 * 1024));
        assert!(matches!(
            DEFAULT_MATCHER.find_matches(&oversized, ScriptLanguage::Python),
            Err(MatchError::ParseError { .. })
        ));
    }
}

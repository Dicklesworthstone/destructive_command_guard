//! Dynamic execution in a quoted interpreter body's own language.
//!
//! The body of a quoted heredoc given to a proven interpreter is not shell
//! source, so POSIX `eval` has no claim on it (#544, #560). That reading was
//! also what denied `eval(Buffer.from(x, "base64").toString())`, by accident:
//! the language analysis judges named sinks, not source a program builds and
//! runs. This module finds those calls in the language they are written in.
//!
//! A call whose source is a literal is judged by that literal, one level deep,
//! so `eval("1+1")` stays allowed and a dangerous string does not. Anything else
//! is source nothing here has read. A value bound once, at the top level, to a
//! literal and used nowhere else is that literal.
//!
//! Methods that share a name are not sites: `model.eval()`, `df.eval("x")`,
//! `re.compile(p)`, `redis.eval(s)`. Neither are forms that take code rather
//! than a string: Perl's `eval { ... }` and Ruby's `instance_eval { ... }`.

use super::MatchError;
use super::source_analysis::static_interpreter_literal;
use crate::heredoc::ScriptLanguage;
use regex::Regex;
use std::sync::{LazyLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// The same bounds as the interpreter literal analysis.
const MAX_DYNAMIC_SOURCE_BYTES: usize = 256 * 1024;
const MAX_DYNAMIC_SOURCE_SITES: usize = 128;
const MAX_DYNAMIC_LITERAL_BYTES: usize = 64 * 1024;
const MAX_DYNAMIC_SOURCE_NODES: usize = 512 * 1024;
/// Parentheses, sequences and casts around a callee.
const MAX_CALLEE_DEPTH: usize = 8;

/// What a dynamic-execution call runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DynamicSource {
    /// The decoded text of a literal, to be judged as source.
    Literal(String),
    /// A value this analysis cannot read: computed, decoded, or unbound.
    Unverified,
}

/// One call that runs source in the body's own language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynamicSourceSite {
    /// The name the body calls it by, for the denial reason.
    pub(crate) callee: String,
    pub(crate) source: DynamicSource,
    /// Byte span of the call in the scanned body.
    pub(crate) start: usize,
    /// End of that span.
    pub(crate) end: usize,
}

/// Everything one reading of a body found.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DynamicSourceReading {
    pub(crate) sites: Vec<DynamicSourceSite>,
    /// A backtick expression, which only Python 2 can run.
    pub(crate) python2_backticks: bool,
    /// The constant strings in the source, when the reading asked for them.
    pub(crate) strings: Vec<String>,
}

static PYTHON_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:eval|exec|execfile)\b").expect("python dynamic source regex compiles")
});
static JAVASCRIPT_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beval\b|Function\b|\bconstructor\b|\brunIn(?:This|New)?Context\b|\bcompileFunction\b|\bvm\.Script\b|\\u")
        .expect("javascript dynamic source regex compiles")
});
static RUBY_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:eval|instance_eval|class_eval|module_eval)\b")
        .expect("ruby dynamic source regex compiles")
});
static PERL_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\beval\b").expect("perl dynamic source regex compiles"));
/// `eval` in code a double-quoted string runs: after `@{[` or `${\`, or inside a
/// subscript. `${name}` and a subscript that closes first run no `eval`.
static PERL_INTERPOLATED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)[$@]\{\s*[\[\\].*\beval\b|[$@][\w:]*(?:->)?[\[{][^\]}]*\beval\b")
        .expect("perl interpolated code regex compiles")
});

/// Whether this module reads `language`. A language it does not read has no
/// answer here for a POSIX `eval` reading to give way to.
#[must_use]
pub(crate) const fn reads_dynamic_source(language: ScriptLanguage) -> bool {
    matches!(
        language,
        ScriptLanguage::Python
            | ScriptLanguage::JavaScript
            | ScriptLanguage::TypeScript
            | ScriptLanguage::Ruby
            | ScriptLanguage::Perl
    )
}

/// The cheap gate. A body with none of these names costs one regex scan.
#[must_use]
pub(crate) fn has_dynamic_source_candidates(
    code: &str,
    language: ScriptLanguage,
    python2: bool,
) -> bool {
    match language {
        ScriptLanguage::Python => {
            PYTHON_CANDIDATE.is_match(code) || (python2 && code.contains('`'))
        }
        ScriptLanguage::JavaScript | ScriptLanguage::TypeScript => {
            JAVASCRIPT_CANDIDATE.is_match(code)
        }
        ScriptLanguage::Ruby => RUBY_CANDIDATE.is_match(code),
        ScriptLanguage::Perl => PERL_CANDIDATE.is_match(code),
        _ => false,
    }
}

/// Read `code` for dynamic execution, within `budget`.
///
/// # Errors
///
/// A body past the size limits, or a reading that could not finish in
/// `budget`, is an error and never an empty reading: the caller must not treat
/// the body as clean.
pub(crate) fn dynamic_source_reading(
    code: &str,
    language: ScriptLanguage,
    python2: bool,
    budget: Duration,
) -> Result<DynamicSourceReading, MatchError> {
    if !has_dynamic_source_candidates(code, language, python2) {
        return Ok(DynamicSourceReading::default());
    }
    if code.len() > MAX_DYNAMIC_SOURCE_BYTES {
        return Err(reading_error(language, "source byte limit"));
    }
    if language == ScriptLanguage::Perl {
        return perl_reading(code);
    }
    tree_reading_on_worker(code, language, python2, false, budget)
}

/// Read the literal handed to a dynamic call, within `budget`.
///
/// Unlike [`dynamic_source_reading`] this has no cheap gate, because a literal
/// with no dynamic call in it still has strings, and they are what the caller
/// wants.
///
/// # Errors
///
/// The same as [`dynamic_source_reading`].
pub(crate) fn literal_source_reading(
    code: &str,
    language: ScriptLanguage,
    budget: Duration,
) -> Result<DynamicSourceReading, MatchError> {
    if code.len() > MAX_DYNAMIC_SOURCE_BYTES {
        return Err(reading_error(language, "source byte limit"));
    }
    if language == ScriptLanguage::Perl {
        return perl_reading(code);
    }
    tree_reading_on_worker(code, language, false, true, budget)
}

fn reading_error(language: ScriptLanguage, detail: &str) -> MatchError {
    MatchError::ParseError {
        language,
        detail: format!("dynamic source analysis exceeded or could not verify {detail}"),
    }
}

fn reading_timeout(started: Instant, budget: Duration) -> MatchError {
    MatchError::Timeout {
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        budget_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
    }
}

/// Tree-sitter has no deadline of its own, so the parse runs on a worker the
/// caller can stop waiting for. A worker that overruns keeps its permit until
/// it finishes: one evaluating thread cannot leave several running.
fn tree_reading_on_worker(
    code: &str,
    language: ScriptLanguage,
    python2: bool,
    strings: bool,
    budget: Duration,
) -> Result<DynamicSourceReading, MatchError> {
    use std::sync::atomic::{AtomicBool, Ordering};

    thread_local! {
        static ACTIVE: std::sync::Arc<AtomicBool> =
            std::sync::Arc::new(AtomicBool::new(false));
    }
    struct Permit(std::sync::Arc<AtomicBool>);
    impl Drop for Permit {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let started = Instant::now();
    if budget.is_zero() {
        return Err(reading_timeout(started, budget));
    }
    let active = ACTIVE.with(std::sync::Arc::clone);
    if active
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(MatchError::Unavailable {
            language,
            detail: "dynamic source analysis is still busy".into(),
        });
    }
    let permit = Permit(active);
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
    let source = code.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    let profile = crate::perf::capture_profile();
    let _worker = thread::Builder::new()
        .name("dcg-dynamic-source".into())
        .spawn(move || {
            let result = {
                let _profile = profile.enter();
                let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
                tree_reading(&source, language, python2, strings)
            };
            drop(source);
            drop(permit);
            let _ = sender.send(result);
        })
        .map_err(|error| MatchError::Unavailable {
            language,
            detail: format!("could not start dynamic source analysis: {error}"),
        })?;
    let remaining = budget
        .checked_sub(started.elapsed())
        .ok_or_else(|| reading_timeout(started, budget))?;
    match receiver.recv_timeout(remaining) {
        Ok(result) if started.elapsed() < budget => result,
        Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => Err(reading_timeout(started, budget)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(MatchError::Unavailable {
            language,
            detail: "dynamic source analysis did not complete".into(),
        }),
    }
}

fn tree_reading(
    code: &str,
    language: ScriptLanguage,
    python2: bool,
    strings: bool,
) -> Result<DynamicSourceReading, MatchError> {
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        ScriptLanguage::TypeScript => SupportLang::TypeScript,
        ScriptLanguage::Ruby => SupportLang::Ruby,
        _ => return Ok(DynamicSourceReading::default()),
    };
    let ast = {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstParse);
        AstGrep::try_new(code, grammar).map_err(|_| reading_error(language, "source grammar"))?
    };
    let root = ast.root();
    let mut reading = DynamicSourceReading::default();
    for (index, node) in root.dfs().enumerate() {
        if index >= MAX_DYNAMIC_SOURCE_NODES {
            return Err(reading_error(language, "AST node limit"));
        }
        match language {
            ScriptLanguage::Python => read_python_node(&node, &root, python2, &mut reading)?,
            ScriptLanguage::Ruby => read_ruby_node(&node, &root, &mut reading),
            _ => read_javascript_node(&node, &root, language, &mut reading)?,
        }
        if strings {
            reading.strings.extend(constant_string(&node, language));
        }
        if reading.sites.len() > MAX_DYNAMIC_SOURCE_SITES
            || reading.strings.len() > MAX_DYNAMIC_SOURCE_SITES
        {
            return Err(reading_error(language, "call site limit"));
        }
    }
    // A call in text the grammar could not finish may have no node. A site that
    // already denies needs no more; anything else would end in allow unread.
    if !strings
        && !reading.python2_backticks
        && root.get_inner_node().has_error()
        && !reading
            .sites
            .iter()
            .any(|site| site.source == DynamicSource::Unverified)
    {
        return Err(reading_error(language, "unfinished source grammar"));
    }
    Ok(reading)
}

fn push_site<D: ast_grep_core::Doc>(
    reading: &mut DynamicSourceReading,
    node: &ast_grep_core::Node<'_, D>,
    callee: impl Into<String>,
    source: DynamicSource,
) {
    let range = node.range();
    reading.sites.push(DynamicSourceSite {
        callee: callee.into(),
        source,
        start: range.start,
        end: range.end,
    });
}

fn positional_arguments<'tree, D: ast_grep_core::Doc>(
    arguments: &ast_grep_core::Node<'tree, D>,
) -> Vec<ast_grep_core::Node<'tree, D>> {
    arguments
        .children()
        .filter(|child| {
            child.is_named()
                && !matches!(
                    child.kind().as_ref(),
                    "comment" | "keyword_argument" | "pair" | "block_argument"
                )
        })
        .collect()
}

fn literal_value<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> Option<String> {
    match language {
        ScriptLanguage::Ruby => ruby_string_value(node),
        // TypeScript strings are JavaScript strings.
        ScriptLanguage::TypeScript => {
            static_interpreter_literal(node, ScriptLanguage::JavaScript, 0)
        }
        _ => static_interpreter_literal(node, language, 0),
    }
}

/// The text of a constant string or Ruby command literal.
fn constant_string<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> Option<String> {
    match node.kind().as_ref() {
        "string" | "template_string" | "concatenated_string" => literal_value(node, language),
        "subshell"
            if !node
                .dfs()
                .any(|child| child.kind().as_ref() == "interpolation") =>
        {
            let raw = node.text();
            let start = if raw.starts_with('`') { 1 } else { "%x{".len() };
            raw.get(start..raw.len().checked_sub(1)?)
                .map(str::to_string)
        }
        _ => None,
    }
}

/// The source a call hands over: its own literal, or the literal that a
/// plain name was bound to.
fn source_of<D: ast_grep_core::Doc>(
    program: &ast_grep_core::Node<'_, D>,
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> DynamicSource {
    let literal = literal_value(program, language).or_else(|| {
        (program.kind().as_ref() == "identifier")
            .then(|| sole_literal_binding(root, program.text().as_ref(), language))
            .flatten()
    });
    match literal {
        Some(text) if text.len() <= MAX_DYNAMIC_LITERAL_BYTES => DynamicSource::Literal(text),
        _ => DynamicSource::Unverified,
    }
}

/// Whether a word equal to `name` appears in `text`.
fn text_names(text: &str, name: &str) -> bool {
    text.split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
        .any(|word| word == name)
}

/// A form that can change a name without mentioning it as an identifier: a
/// write through a scope object or a binding, a star import, a `with` scope.
fn can_rebind_unseen<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> bool {
    let kind = node.kind();
    match language {
        ScriptLanguage::Python => {
            kind.as_ref() == "wildcard_import"
                || (kind.as_ref() == "identifier"
                    && matches!(
                        node.text().as_ref(),
                        "globals" | "locals" | "vars" | "setattr" | "__dict__"
                    ))
        }
        ScriptLanguage::Ruby => kind.as_ref() == "identifier" && node.text().as_ref() == "binding",
        _ => {
            kind.as_ref() == "with_statement"
                || (kind.as_ref() == "identifier"
                    && matches!(
                        node.text().as_ref(),
                        "globalThis" | "global" | "window" | "self"
                    ))
        }
    }
}

/// The literal `name` is bound to, when the program's only two mentions of
/// `name` are one top-level assignment of that literal and the use after it.
/// A third mention could rebind, mutate or alias the value, so it ends this
/// proof rather than being reasoned about. So does the name inside a string or
/// symbol, which is how `globals()["x"]` and `exec("x = ...")` reach it, and any
/// form that can rebind it without naming it.
fn sole_literal_binding<D: ast_grep_core::Doc>(
    root: &ast_grep_core::Node<'_, D>,
    name: &str,
    language: ScriptLanguage,
) -> Option<String> {
    let mut mentions = 0_usize;
    let mut value = None;
    for (index, node) in root.dfs().enumerate() {
        if index >= MAX_DYNAMIC_SOURCE_NODES || can_rebind_unseen(&node, language) {
            return None;
        }
        let kind = node.kind();
        if (kind.contains("string") || kind.as_ref() == "simple_symbol")
            && text_names(node.text().as_ref(), name)
        {
            return None;
        }
        if !kind.contains("identifier") || node.text().as_ref() != name {
            continue;
        }
        mentions += 1;
        if mentions > 2 {
            return None;
        }
        if mentions == 1 {
            let parent = node.parent()?;
            if !matches!(
                parent.kind().as_ref(),
                "assignment" | "assignment_expression" | "variable_declarator"
            ) || parent
                .field("left")
                .or_else(|| parent.field("name"))
                .is_none_or(|left| left.range() != node.range())
                || !is_top_level_statement(&parent, root)
            {
                return None;
            }
            value = parent
                .field("right")
                .or_else(|| parent.field("value"))
                .and_then(|right| literal_value(&right, language));
        }
    }
    if mentions == 2 { value } else { None }
}

fn is_top_level_statement<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    root: &ast_grep_core::Node<'_, D>,
) -> bool {
    let mut current = node.parent();
    for _ in 0..4 {
        let Some(parent) = current else {
            return false;
        };
        if parent.range() == root.range() && parent.parent().is_none() {
            return true;
        }
        if !matches!(
            parent.kind().as_ref(),
            "expression_statement" | "lexical_declaration" | "variable_declaration"
        ) {
            return false;
        }
        current = parent.parent();
    }
    false
}

// ---------------------------------------------------------------- Python ---

fn read_python_node<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    root: &ast_grep_core::Node<'_, D>,
    python2: bool,
    reading: &mut DynamicSourceReading,
) -> Result<(), MatchError> {
    match node.kind().as_ref() {
        "call" => {
            let Some(function) = node.field("function") else {
                return Ok(());
            };
            let Some(callee) = python_dynamic_callee(&function, 0)
                .map_err(|()| reading_error(ScriptLanguage::Python, "callee nesting limit"))?
            else {
                return Ok(());
            };
            let Some(arguments) = node.field("arguments") else {
                return Ok(());
            };
            // `eval()` with no argument raises; nothing runs.
            if let Some(program) = positional_arguments(&arguments).first() {
                let source = source_of(program, root, ScriptLanguage::Python);
                push_site(reading, node, callee, source);
            }
        }
        // Python 2's `exec code`, which tree-sitter keeps as a statement.
        "exec_statement" => {
            if let Some(program) = node.field("code") {
                let source = source_of(&program, root, ScriptLanguage::Python);
                push_site(reading, node, "exec", source);
            }
        }
        // `run = eval; run(x)` and `map(eval, items)` hand the builtin on.
        "identifier" => {
            let text = node.text();
            if matches!(text.as_ref(), "eval" | "exec") && python_name_is_handed_on(node) {
                push_site(reading, node, text.as_ref(), DynamicSource::Unverified);
            }
        }
        // tree-sitter-python reads a backtick expression as a string, so no
        // grammar error marks it. Python 3 refuses it; Python 2 evaluates it.
        "string" if python2 && node.text().starts_with('`') => {
            reading.python2_backticks = true;
        }
        _ => {}
    }
    Ok(())
}

/// `Err` is nesting past the limit, as for [`js_unwrapped`].
fn python_dynamic_callee<D: ast_grep_core::Doc>(
    function: &ast_grep_core::Node<'_, D>,
    depth: usize,
) -> Result<Option<String>, ()> {
    if depth >= MAX_CALLEE_DEPTH {
        return Err(());
    }
    // `(eval)(x)`.
    if function.kind().as_ref() == "parenthesized_expression" {
        return match function
            .children()
            .find(|child| child.is_named() && child.kind().as_ref() != "comment")
        {
            Some(inner) => python_dynamic_callee(&inner, depth + 1),
            None => Ok(None),
        };
    }
    Ok(python_plain_callee(function))
}

fn python_plain_callee<D: ast_grep_core::Doc>(
    function: &ast_grep_core::Node<'_, D>,
) -> Option<String> {
    match function.kind().as_ref() {
        "identifier" => {
            let name = function.text();
            matches!(name.as_ref(), "eval" | "exec" | "execfile").then(|| name.into_owned())
        }
        "attribute" => {
            let name = function.field("attribute")?.text().into_owned();
            let object = function.field("object")?;
            (matches!(name.as_str(), "eval" | "exec") && python_is_builtins(&object))
                .then_some(name)
        }
        // `getattr(builtins, "eval")(x)`.
        "call" => {
            let getter = function.field("function")?;
            if getter.kind().as_ref() != "identifier" || getter.text().as_ref() != "getattr" {
                return None;
            }
            let arguments = function.field("arguments")?;
            let name = literal_value(
                positional_arguments(&arguments).get(1)?,
                ScriptLanguage::Python,
            )?;
            matches!(name.as_str(), "eval" | "exec").then_some(name)
        }
        _ => None,
    }
}

fn python_is_builtins<D: ast_grep_core::Doc>(object: &ast_grep_core::Node<'_, D>) -> bool {
    match object.kind().as_ref() {
        "identifier" => matches!(object.text().as_ref(), "builtins" | "__builtins__"),
        // `__import__("builtins").eval(x)`.
        "call" => {
            object.field("function").is_some_and(|function| {
                function.kind().as_ref() == "identifier" && function.text().as_ref() == "__import__"
            }) && object.field("arguments").is_some_and(|arguments| {
                positional_arguments(&arguments)
                    .first()
                    .and_then(|name| literal_value(name, ScriptLanguage::Python))
                    .is_some_and(|name| matches!(name.as_str(), "builtins" | "__builtin__"))
            })
        }
        _ => false,
    }
}

fn python_name_is_handed_on<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> bool {
    node.parent()
        .is_some_and(|parent| match parent.kind().as_ref() {
            "assignment" => parent
                .field("right")
                .is_some_and(|right| right.range() == node.range()),
            "keyword_argument" => parent
                .field("value")
                .is_some_and(|value| value.range() == node.range()),
            "argument_list" | "boolean_operator" | "conditional_expression" => true,
            _ => false,
        })
}

// ------------------------------------------------------------ JavaScript ---

fn js_source_constructor(name: &str) -> bool {
    matches!(
        name,
        "Function" | "AsyncFunction" | "GeneratorFunction" | "AsyncGeneratorFunction"
    )
}

fn read_javascript_node<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    reading: &mut DynamicSourceReading,
) -> Result<(), MatchError> {
    match node.kind().as_ref() {
        "call_expression" => {
            let Some(function) = node.field("function") else {
                return Ok(());
            };
            let Some(callee) = js_dynamic_callee(&function)
                .map_err(|()| reading_error(language, "callee nesting limit"))?
            else {
                return Ok(());
            };
            let Some(arguments) = node.field("arguments") else {
                return Ok(());
            };
            // A tag is called with the template's text.
            if arguments.kind().as_ref() == "template_string" {
                let source = source_of(&arguments, root, language);
                push_site(reading, node, callee, source);
            } else {
                push_js_call_site(node, &arguments, callee, root, language, reading);
            }
        }
        "new_expression" => {
            let Some(constructor) = node.field("constructor") else {
                return Ok(());
            };
            let Some(callee) = js_dynamic_constructor(&constructor)
                .map_err(|()| reading_error(language, "callee nesting limit"))?
            else {
                return Ok(());
            };
            if let Some(arguments) = node.field("arguments") {
                push_js_call_site(node, &arguments, callee, root, language, reading);
            }
        }
        // `const run = eval; run(x)`, `[eval].map(...)`, `const F = Function`.
        "identifier" => {
            let name = node.text();
            let handed_on = if js_source_constructor(name.as_ref()) {
                js_name_is_aliased(node)
            } else {
                name.as_ref() == "eval" && js_name_is_handed_on(node)
            };
            if handed_on {
                push_site(reading, node, name.as_ref(), DynamicSource::Unverified);
            }
        }
        // `const { eval: run } = globalThis`.
        "pair_pattern"
            if node
                .field("key")
                .is_some_and(|key| matches!(key.text().as_ref(), "eval" | "Function")) =>
        {
            push_site(reading, node, "eval", DynamicSource::Unverified);
        }
        _ => {}
    }
    Ok(())
}

/// `eval` and the `vm` calls run their first argument. The `Function` family
/// runs its last, and the ones before it are parameter lists, which can hold
/// default-value code, so all of them must be literals.
fn push_js_call_site<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    arguments: &ast_grep_core::Node<'_, D>,
    callee: String,
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    reading: &mut DynamicSourceReading,
) {
    let arguments = positional_arguments(arguments);
    let source_family =
        js_source_constructor(&callee) || callee == "constructor" || callee.contains('\\');
    let program = if source_family {
        arguments.last()
    } else {
        arguments.first()
    };
    let Some(program) = program else {
        return;
    };
    let parameters = arguments.len().saturating_sub(1);
    let source = if source_family
        && (arguments
            .iter()
            .any(|argument| literal_value(argument, language).is_none())
            || arguments[..parameters].iter().any(|argument| {
                literal_value(argument, language).is_some_and(|text| !js_plain_parameters(&text))
            })) {
        DynamicSource::Unverified
    } else {
        source_of(program, root, language)
    };
    push_site(reading, node, callee, source);
}

/// A parameter list of plain names runs nothing. A default value would.
fn js_plain_parameters(text: &str) -> bool {
    text.chars()
        .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '$' | ',' | ' '))
}

fn js_global_object<D: ast_grep_core::Doc>(
    object: &ast_grep_core::Node<'_, D>,
) -> Result<bool, ()> {
    let object = js_unwrapped(object)?;
    Ok(object.kind().as_ref() == "identifier"
        && matches!(
            object.text().as_ref(),
            "globalThis" | "global" | "window" | "self"
        ))
}

/// The expression inside parentheses or a TypeScript cast, which changes
/// nothing at run time.
fn js_wrapped_expression<'tree, D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'tree, D>,
) -> Option<ast_grep_core::Node<'tree, D>> {
    let named = || {
        node.children()
            .filter(|child| child.is_named() && child.kind().as_ref() != "comment")
    };
    match node.kind().as_ref() {
        "as_expression" | "satisfies_expression" | "non_null_expression" => named().next(),
        // `(0, eval)(x)` is an indirect eval. Only the last expression of the
        // sequence is the callee.
        "parenthesized_expression" | "sequence_expression" | "type_assertion" => named().last(),
        _ => None,
    }
}

/// The expression under its wrappers. `Err` is nesting past the limit: nothing
/// is known about that expression, which is not the same as knowing it is not a
/// site. The hook has no stack to spare, and a stack overflow kills it.
fn js_unwrapped<'tree, D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'tree, D>,
) -> Result<ast_grep_core::Node<'tree, D>, ()> {
    let mut node = node.clone();
    for _ in 0..MAX_CALLEE_DEPTH {
        match js_wrapped_expression(&node) {
            Some(inner) => node = inner,
            None => return Ok(node),
        }
    }
    Err(())
}

fn js_global_source_name(name: &str) -> bool {
    name == "eval" || name == "Function"
}

fn js_dynamic_callee<D: ast_grep_core::Doc>(
    function: &ast_grep_core::Node<'_, D>,
) -> Result<Option<String>, ()> {
    let function = js_unwrapped(function)?;
    Ok(match function.kind().as_ref() {
        "identifier" => {
            let name = function.text();
            // `\u0065val` is `eval`, and no name here needs an escape.
            (name.as_ref() == "eval" || js_source_constructor(name.as_ref()) || name.contains('\\'))
                .then(|| name.into_owned())
        }
        "member_expression" => js_member_callee(&function)?,
        "subscript_expression" => js_subscript_callee(&function)?,
        _ => None,
    })
}

fn js_member_callee<D: ast_grep_core::Doc>(
    function: &ast_grep_core::Node<'_, D>,
) -> Result<Option<String>, ()> {
    let (Some(property), Some(object)) = (function.field("property"), function.field("object"))
    else {
        return Ok(None);
    };
    let name = property.text().into_owned();
    let site = match name.as_str() {
        "eval" | "Function" => js_global_object(&object)?,
        // `(() => {}).constructor("...")` is `Function`.
        "constructor" => !matches!(object.kind().as_ref(), "this" | "super"),
        "runInThisContext" | "runInNewContext" | "runInContext" | "compileFunction" => true,
        // `eval.call(null, x)` runs what `eval` runs.
        "call" | "apply" | "bind" => {
            return Ok((object.kind().as_ref() == "identifier"
                && (object.text().as_ref() == "eval"
                    || js_source_constructor(object.text().as_ref())))
            .then(|| object.text().into_owned()));
        }
        _ => false,
    };
    Ok(site.then_some(name))
}

fn js_subscript_callee<D: ast_grep_core::Doc>(
    function: &ast_grep_core::Node<'_, D>,
) -> Result<Option<String>, ()> {
    let (Some(object), Some(index)) = (function.field("object"), function.field("index")) else {
        return Ok(None);
    };
    let Some(name) = static_interpreter_literal(&index, ScriptLanguage::JavaScript, 0) else {
        return Ok(None);
    };
    let site = (js_global_source_name(&name) && js_global_object(&object)?)
        || (name == "constructor" && !matches!(object.kind().as_ref(), "this" | "super"));
    Ok(site.then_some(name))
}

fn js_dynamic_constructor<D: ast_grep_core::Doc>(
    constructor: &ast_grep_core::Node<'_, D>,
) -> Result<Option<String>, ()> {
    let constructor = js_unwrapped(constructor)?;
    Ok(match constructor.kind().as_ref() {
        "identifier" => {
            let name = constructor.text();
            (js_source_constructor(name.as_ref()) || name.contains('\\')).then(|| name.into_owned())
        }
        "member_expression" => {
            let (Some(property), Some(object)) =
                (constructor.field("property"), constructor.field("object"))
            else {
                return Ok(None);
            };
            let name = property.text().into_owned();
            let site = match name.as_str() {
                "Function" => js_global_object(&object)?,
                "Script" => object.text().as_ref() == "vm",
                "constructor" => !matches!(object.kind().as_ref(), "this" | "super"),
                _ => false,
            };
            site.then_some(name)
        }
        "subscript_expression" => js_subscript_callee(&constructor)?,
        _ => None,
    })
}

fn js_name_is_handed_on<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> bool {
    js_name_is_aliased(node)
        || node
            .parent()
            .is_some_and(|parent| matches!(parent.kind().as_ref(), "arguments" | "array"))
}

fn js_name_is_aliased<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> bool {
    node.parent()
        .is_some_and(|parent| match parent.kind().as_ref() {
            "variable_declarator" => parent
                .field("value")
                .is_some_and(|value| value.range() == node.range()),
            "assignment_expression" => parent
                .field("right")
                .is_some_and(|right| right.range() == node.range()),
            // `(x || eval)(y)`. `x instanceof Function` is not a value.
            "binary_expression" => parent
                .field("operator")
                .is_some_and(|operator| matches!(operator.text().as_ref(), "||" | "&&" | "??")),
            "ternary_expression" => parent
                .field("condition")
                .is_none_or(|condition| condition.range() != node.range()),
            _ => false,
        })
}

// ------------------------------------------------------------------ Ruby ---

fn read_ruby_node<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    root: &ast_grep_core::Node<'_, D>,
    reading: &mut DynamicSourceReading,
) {
    if node.kind().as_ref() != "call" {
        return;
    }
    let Some(method) = node.field("method") else {
        return;
    };
    let method = method.text();
    // Block-only forms have no `arguments` field, and no string to run.
    let Some(arguments) = node.field("arguments") else {
        return;
    };
    let arguments = positional_arguments(&arguments);
    let receiver = node.field("receiver");
    let (callee, program) = match method.as_ref() {
        "eval" if receiver.as_ref().is_none_or(ruby_eval_receiver) => ("eval", arguments.first()),
        "instance_eval" => ("instance_eval", arguments.first()),
        "class_eval" => ("class_eval", arguments.first()),
        "module_eval" => ("module_eval", arguments.first()),
        "send" | "__send__" | "public_send" if arguments.first().is_some_and(ruby_names_eval) => {
            ("send", arguments.get(1))
        }
        "call" if receiver.as_ref().is_some_and(ruby_is_eval_method_object) => {
            ("eval", arguments.first())
        }
        _ => return,
    };
    if let Some(program) = program {
        let source = source_of(program, root, ScriptLanguage::Ruby);
        push_site(reading, node, callee, source);
    }
}

fn ruby_eval_receiver<D: ast_grep_core::Doc>(receiver: &ast_grep_core::Node<'_, D>) -> bool {
    matches!(
        receiver.text().as_ref(),
        "Kernel" | "binding" | "TOPLEVEL_BINDING"
    )
}

fn ruby_names_eval<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> bool {
    match node.kind().as_ref() {
        "simple_symbol" => matches!(
            node.text().as_ref(),
            ":eval" | ":instance_eval" | ":class_eval" | ":module_eval"
        ),
        "string" => ruby_string_value(node).is_some_and(|name| {
            matches!(
                name.as_str(),
                "eval" | "instance_eval" | "class_eval" | "module_eval"
            )
        }),
        _ => false,
    }
}

/// `method(:eval).call(x)`.
fn ruby_is_eval_method_object<D: ast_grep_core::Doc>(
    receiver: &ast_grep_core::Node<'_, D>,
) -> bool {
    receiver.kind().as_ref() == "call"
        && receiver
            .field("method")
            .is_some_and(|method| method.text().as_ref() == "method")
        && receiver.field("arguments").is_some_and(|arguments| {
            positional_arguments(&arguments)
                .first()
                .is_some_and(ruby_names_eval)
        })
}

/// A plain `"..."` or `'...'` string with no interpolation. An escape this
/// does not know leaves the value unknown instead of guessing it.
fn ruby_string_value<D: ast_grep_core::Doc>(node: &ast_grep_core::Node<'_, D>) -> Option<String> {
    if node.kind().as_ref() != "string"
        || node
            .dfs()
            .any(|child| child.kind().as_ref() == "interpolation")
    {
        return None;
    }
    let raw = node.text();
    let quote = raw
        .chars()
        .next()
        .filter(|quote| matches!(quote, '"' | '\''))?;
    if raw.len() < 2 || !raw.ends_with(quote) {
        return None;
    }
    decode_quoted(&raw[1..raw.len() - 1], quote)
}

/// Decode a double- or single-quoted Ruby or Perl string body.
fn decode_quoted(body: &str, quote: char) -> Option<String> {
    let mut result = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            result.push(ch);
            continue;
        }
        let escaped = chars.next()?;
        match (quote, escaped) {
            (_, '\\') | ('\'', '\'') | ('"', '"') => result.push(escaped),
            // A single-quoted string keeps any other backslash.
            ('\'', other) => {
                result.push('\\');
                result.push(other);
            }
            ('"', 'n') => result.push('\n'),
            ('"', 't') => result.push('\t'),
            ('"', 'r') => result.push('\r'),
            _ => return None,
        }
    }
    Some(result)
}

// ------------------------------------------------------------------ Perl ---

/// Perl has no grammar here, so this walks the source the way the other Perl
/// scans do: comments and quoted text are skipped, and an `eval` word in code
/// is read by what follows it. The walk is in step with Perl until the first
/// form that can start a false region, and every region after that is unproven.
fn perl_reading(code: &str) -> Result<DynamicSourceReading, MatchError> {
    let bytes = code.as_bytes();
    let mut reading = DynamicSourceReading::default();
    let mut unproven = false;
    let mut read_to = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'#' if index == 0 || bytes[index - 1] != b'$' => {
                let start = index;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                perl_check_skipped(code, start..index, unproven)?;
            }
            // `$'`, `$"` and `` $` `` are variables.
            quote @ (b'"' | b'\'' | b'`')
                if (index == 0 || bytes[index - 1] != b'$')
                    && (quote != b'\''
                        || index == 0
                        || !(bytes[index - 1].is_ascii_alphanumeric()
                            || bytes[index - 1] == b'_')) =>
            {
                let start = index;
                let end = perl_quoted_end(bytes, index);
                index = end.unwrap_or(bytes.len());
                perl_check_skipped(code, start..index, unproven || end.is_none())?;
            }
            b'e' if perl_eval_word_at(bytes, index) => {
                let word_end = index + 4;
                if let Some(site) = perl_eval_site(code, index, word_end) {
                    reading.sites.push(site);
                    if reading.sites.len() > MAX_DYNAMIC_SOURCE_SITES {
                        return Err(reading_error(ScriptLanguage::Perl, "call site limit"));
                    }
                }
                index = word_end;
            }
            _ => {
                unproven = unproven || perl_form_can_desync(bytes, index, &mut read_to);
                index += 1;
            }
        }
    }
    Ok(reading)
}

/// A region the walker skipped hides nothing unless `eval` is in it. Where it
/// is, the region has to be proved real, and a string has to run no code.
fn perl_check_skipped(
    code: &str,
    region: std::ops::Range<usize>,
    unproven: bool,
) -> Result<(), MatchError> {
    let Some(text) = code.get(region) else {
        return Ok(());
    };
    if (unproven && PERL_CANDIDATE.is_match(text))
        || (text.starts_with(['"', '`']) && PERL_INTERPOLATED.is_match(text))
    {
        return Err(reading_error(ScriptLanguage::Perl, "string boundary"));
    }
    Ok(())
}

/// Whether the code at `index` opens text the walker would read as code, with a
/// quote or `#` in it that can start a false region: a quote-like operator, a
/// pattern, POD or a here-document. `read_to` is the end of the last form proved
/// clean. Nothing inside one is opened again, so each byte is scanned once.
fn perl_form_can_desync(bytes: &[u8], index: usize, read_to: &mut usize) -> bool {
    if index < *read_to {
        return false;
    }
    let form = match bytes[index] {
        b'=' => {
            return (index == 0 || bytes[index - 1] == b'\n')
                && bytes.get(index + 1).is_some_and(u8::is_ascii_alphabetic);
        }
        b'<' => return perl_opens_here_document(bytes, index),
        b'/' if perl_slash_opens_pattern(bytes, index) => Some((index, 1)),
        b'm' | b'q' | b's' | b't' | b'y' => perl_quote_like_at(bytes, index),
        _ => None,
    };
    let Some((open, parts)) = form else {
        return false;
    };
    let mut end = perl_quoted_end(bytes, open);
    if parts == 2 {
        end = end.and_then(|first| {
            let bracket = matches!(bytes[open], b'(' | b'[' | b'{' | b'<');
            perl_quoted_end(
                bytes,
                if bracket {
                    perl_skip_space(bytes, first)
                } else {
                    first - 1
                },
            )
        });
    }
    let Some(end) = end else {
        return true;
    };
    *read_to = end;
    bytes[open..end]
        .iter()
        .any(|byte| matches!(byte, b'\'' | b'"' | b'`' | b'#'))
}

/// `<<X`, `<<~X`, `<<"X"` and `<< 'X'`. `1 << 2` and `$x << $y` are shifts.
fn perl_opens_here_document(bytes: &[u8], index: usize) -> bool {
    if !bytes[index..].starts_with(b"<<") {
        return false;
    }
    let name = index + 2 + usize::from(bytes.get(index + 2) == Some(&b'~'));
    bytes
        .get(name)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        || matches!(
            bytes.get(perl_skip_space(bytes, name)),
            Some(b'"' | b'\'' | b'`')
        )
}

/// A `/` after a value divides, and after anything else it opens a pattern. A
/// `}` can end a block as well as a subscript, so it counts as anything else.
fn perl_slash_opens_pattern(bytes: &[u8], index: usize) -> bool {
    let before = bytes[..index].trim_ascii_end();
    let word = before
        .iter()
        .rev()
        .take_while(|byte| perl_word_byte(**byte))
        .count();
    let head = before.len() - word;
    match before.last() {
        Some(b')' | b']') => false,
        Some(_) if word > 0 => {
            !(before[head].is_ascii_digit()
                || (head > 0 && matches!(before[head - 1], b'$' | b'@' | b'%' | b'&')))
        }
        _ => true,
    }
}

/// Where the delimiter of a quote-like operator at `start` sits, and how many
/// delimited parts follow. Any byte can delimit, so `s,a,b,` is one, and so is
/// `s xaxbx`. `$s`, `->s`, `Foo::s`, `-s $file`, `{s}` and `s => 1` are not.
fn perl_quote_like_at(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let before = &bytes[..start];
    if before.ends_with(b"->")
        || before.ends_with(b"::")
        || before.last().is_some_and(|byte| {
            perl_word_byte(*byte) || matches!(byte, b'$' | b'@' | b'%' | b'&' | b'-')
        })
    {
        return None;
    }
    let word = bytes[start..]
        .iter()
        .take_while(|byte| perl_word_byte(**byte))
        .count();
    let parts = match &bytes[start..start + word] {
        b"m" | b"q" | b"qq" | b"qr" | b"qw" | b"qx" => 1,
        b"s" | b"tr" | b"y" => 2,
        _ => return None,
    };
    let open = perl_skip_space(bytes, start + word);
    match *bytes.get(open)? {
        b'#' if open > start + word => None,
        b')' | b']' | b'}' | b'>' => None,
        b'=' if bytes.get(open + 1) == Some(&b'>') => None,
        _ => Some((open, parts)),
    }
}

/// The offset just past the text delimited at `start`, if it closes. A bracket
/// delimiter nests.
fn perl_quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let open = *bytes.get(start)?;
    let close = match open {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        b'<' => b'>',
        byte => byte,
    };
    let mut depth = 0_usize;
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 1,
            byte if byte == close && depth == 0 => return Some(index + 1),
            byte if byte == close => depth -= 1,
            byte if byte == open => depth += 1,
            _ => {}
        }
        index += 1;
    }
    None
}

const fn perl_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn perl_eval_word_at(bytes: &[u8], index: usize) -> bool {
    let word_char = |byte: u8| perl_word_byte(byte);
    let before = &bytes[..index];
    bytes[index..].starts_with(b"eval")
        && bytes.get(index + 4).is_none_or(|byte| !word_char(*byte))
        // `$eval`, `@eval`, `%eval`, `&eval`, `->eval`, `Foo::eval`. `CORE::eval`
        // is the builtin itself.
        && (index == 0
            || before.ends_with(b"CORE::")
            || before.ends_with(b"CORE::GLOBAL::")
            || !(word_char(bytes[index - 1])
                || matches!(bytes[index - 1], b'$' | b'@' | b'%' | b'&' | b'>' | b':')))
}

/// Whether the `{` just before `start` opens a hash subscript: it follows a
/// variable, an arrow or another subscript with no space. `{eval}` anywhere
/// else is a block that runs `$_`.
fn perl_opens_key(bytes: &[u8], start: usize) -> bool {
    let Some(brace) = start.checked_sub(1).filter(|brace| bytes[*brace] == b'{') else {
        return false;
    };
    let before = &bytes[..brace];
    if before.ends_with(b"->") || matches!(before.last(), Some(b'}' | b']')) {
        return true;
    }
    let word = before
        .iter()
        .rev()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(**byte, b'_' | b':'))
        .count();
    word > 0
        && before
            .len()
            .checked_sub(word + 1)
            .is_some_and(|sigil| matches!(before[sigil], b'$' | b'@' | b'%'))
}

fn perl_skip_space(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn perl_eval_site(code: &str, start: usize, word_end: usize) -> Option<DynamicSourceSite> {
    let bytes = code.as_bytes();
    let mut next = perl_skip_space(bytes, word_end);
    // `{eval => 1}` and `$h{eval}` name a key.
    if bytes[next..].starts_with(b"=>")
        || (bytes.get(next) == Some(&b'}') && perl_opens_key(bytes, start))
    {
        return None;
    }
    let parenthesized = bytes.get(next) == Some(&b'(');
    if parenthesized {
        next = perl_skip_space(bytes, next + 1);
    }
    // `eval { ... }` is a block, compiled with the program. Perl's exception
    // handling, not dynamic source.
    if !parenthesized && bytes.get(next) == Some(&b'{') {
        return None;
    }
    let (source, end) = perl_literal_argument(code, next, parenthesized)
        .map_or((DynamicSource::Unverified, next), |(text, end)| {
            (DynamicSource::Literal(text), end)
        });
    Some(DynamicSourceSite {
        callee: "eval".to_string(),
        source,
        start,
        end,
    })
}

/// The value of a lone quoted string at `start`, and where the argument ends.
/// Interpolation in a double-quoted string, or anything after the string, is a
/// value this cannot know.
fn perl_literal_argument(code: &str, start: usize, parenthesized: bool) -> Option<(String, usize)> {
    let bytes = code.as_bytes();
    let quote = *bytes.get(start)?;
    if !matches!(quote, b'"' | b'\'') {
        return None;
    }
    let end = perl_quoted_end(bytes, start)?;
    let body = code.get(start + 1..end - 1)?;
    if quote == b'"' && body.contains(['$', '@']) {
        return None;
    }
    let mut after = perl_skip_space(bytes, end);
    if parenthesized {
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        after = perl_skip_space(bytes, after + 1);
    }
    let closes = after >= bytes.len()
        || matches!(bytes[after], b';' | b'}')
        || bytes[after..].starts_with(b"or ")
        || bytes[after..].starts_with(b"||");
    if !closes || body.len() > MAX_DYNAMIC_LITERAL_BYTES {
        return None;
    }
    Some((decode_quoted(body, char::from(quote))?, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(code: &str, language: ScriptLanguage) -> DynamicSourceReading {
        dynamic_source_reading(code, language, false, Duration::from_secs(5)).unwrap()
    }

    fn sources(code: &str, language: ScriptLanguage) -> Vec<(String, DynamicSource)> {
        read(code, language)
            .sites
            .into_iter()
            .map(|site| (site.callee, site.source))
            .collect()
    }

    fn literal(callee: &str, text: &str) -> Vec<(String, DynamicSource)> {
        vec![(callee.to_string(), DynamicSource::Literal(text.to_string()))]
    }

    fn unverified(callee: &str) -> Vec<(String, DynamicSource)> {
        vec![(callee.to_string(), DynamicSource::Unverified)]
    }

    #[test]
    fn a_literal_reading_returns_its_constant_strings() {
        let strings = |code, language| {
            literal_source_reading(code, language, Duration::from_secs(5))
                .unwrap()
                .strings
        };
        assert_eq!(
            strings("f('a', \"b\")\ng(f'{x} c')", ScriptLanguage::Python),
            ["a", "b"]
        );
        assert_eq!(
            strings("x = `a` + 'b' + `${c}`", ScriptLanguage::JavaScript),
            ["a", "b"]
        );
        assert_eq!(
            strings("`a b`; %x{c d}; `#{e}`; f 'g'", ScriptLanguage::Ruby),
            ["a b", "c d", "g"]
        );
        assert_eq!(
            read("eval('a')", ScriptLanguage::Python).strings,
            Vec::<String>::new()
        );
    }

    #[test]
    fn python_calls_are_read_by_their_source() {
        use ScriptLanguage::Python as P;
        assert_eq!(sources("eval('1+1')", P), literal("eval", "1+1"));
        assert_eq!(sources("exec(\"a = 1\")", P), literal("exec", "a = 1"));
        assert_eq!(sources("eval(x)", P), unverified("eval"));
        assert_eq!(
            sources("exec(__import__('base64').b64decode('eA=='))", P),
            unverified("exec")
        );
        assert_eq!(
            sources("exec(compile('a = 1', 'f', 'exec'))", P),
            unverified("exec")
        );
        assert_eq!(
            sources("import builtins\nbuiltins.eval(x)", P),
            unverified("eval")
        );
        assert_eq!(
            sources("__import__('builtins').exec(x)", P),
            unverified("exec")
        );
        assert_eq!(
            sources("import builtins\ngetattr(builtins, 'eval')(x)", P),
            unverified("eval")
        );
        assert_eq!(sources("run = eval\nrun(x)", P), unverified("eval"));
        assert_eq!(sources("list(map(eval, items))", P), unverified("eval"));
    }

    #[test]
    fn python_names_that_are_not_the_builtins_are_not_sites() {
        use ScriptLanguage::Python as P;
        for code in [
            "model.eval()",
            "df.eval('a + b')",
            "re.compile('x')",
            "ast.literal_eval(x)",
            "cursor.execute('select 1')",
            "configure(eval=True)",
            "print('eval(x)')",
            "# eval(x)\nprint(1)",
            "def evaluate(x):\n    return x",
        ] {
            assert_eq!(sources(code, P), Vec::new(), "{code}");
        }
    }

    #[test]
    fn a_name_bound_once_to_a_literal_is_that_literal() {
        use ScriptLanguage::{JavaScript as J, Python as P, Ruby as R};
        assert_eq!(
            sources("code = 'a = 1'\nexec(code)", P),
            literal("exec", "a = 1")
        );
        assert_eq!(
            sources("const s = '1+1'; eval(s);", J),
            literal("eval", "1+1")
        );
        assert_eq!(sources("s = '1+1'\neval(s)", R), literal("eval", "1+1"));

        // Rebound, mutated, conditional, or used before it is bound.
        assert_eq!(
            sources("code = 'a'\ncode = read()\nexec(code)", P),
            unverified("exec")
        );
        assert_eq!(
            sources("code = 'a'\nprint(code)\nexec(code)", P),
            unverified("exec")
        );
        assert_eq!(
            sources("if flag:\n    code = 'a'\nexec(code)", P),
            unverified("exec")
        );
        assert_eq!(sources("exec(code)\ncode = 'a'", P), unverified("exec"));
    }

    #[test]
    fn python_backticks_are_noted_only_for_python_2_receivers() {
        let code = "x = `1 + 1`";
        let budget = Duration::from_secs(5);
        let python2 = dynamic_source_reading(code, ScriptLanguage::Python, true, budget).unwrap();
        assert!(python2.python2_backticks);
        let python3 = dynamic_source_reading(code, ScriptLanguage::Python, false, budget).unwrap();
        assert!(!python3.python2_backticks);

        for code in [
            "print('it`s')",
            "# it`s\nprint(1)",
            "print(\"\"\"`x`\"\"\")",
        ] {
            let reading =
                dynamic_source_reading(code, ScriptLanguage::Python, true, budget).unwrap();
            assert!(!reading.python2_backticks, "{code}");
        }
    }

    #[test]
    fn javascript_calls_are_read_by_their_source() {
        for language in [ScriptLanguage::JavaScript, ScriptLanguage::TypeScript] {
            assert_eq!(sources("eval('1+1')", language), literal("eval", "1+1"));
            assert_eq!(sources("eval(x)", language), unverified("eval"));
            assert_eq!(
                sources("eval(Buffer.from('eA==', 'base64').toString())", language),
                unverified("eval")
            );
            assert_eq!(sources("(0, eval)(x)", language), unverified("eval"));
            assert_eq!(sources("globalThis.eval(x)", language), unverified("eval"));
            assert_eq!(
                sources("globalThis['eval'](x)", language),
                unverified("eval")
            );
            assert_eq!(
                sources("new Function('return 1')()", language),
                literal("Function", "return 1")
            );
            assert_eq!(
                sources("new Function('a', 'return a')", language),
                literal("Function", "return a")
            );
            assert_eq!(
                sources("new Function(a, 'return 1')", language),
                unverified("Function")
            );
            assert_eq!(
                sources("Function('return 1')()", language),
                literal("Function", "return 1")
            );
            assert_eq!(
                sources("Function`return 1`()", language),
                literal("Function", "return 1")
            );
            assert_eq!(
                sources("Function`${x}`()", language),
                unverified("Function")
            );
            assert_eq!(
                sources("(() => {}).constructor('return 1')()", language),
                literal("constructor", "return 1")
            );
            assert_eq!(
                sources("vm.runInThisContext(x)", language),
                unverified("runInThisContext")
            );
            assert_eq!(sources("new vm.Script(x)", language), unverified("Script"));
            assert_eq!(
                sources("const run = eval; run(x);", language),
                unverified("eval")
            );
        }
    }

    #[test]
    fn javascript_names_that_are_not_the_globals_are_not_sites() {
        for code in [
            "redis.eval('return 1')",
            "page.eval(x)",
            "this.constructor(x)",
            "new this.constructor(x)",
            "x instanceof Function",
            "function evaluate(x) { return x; }",
            "console.log('eval(x)')",
            "`eval(\"1+1\")`",
            "// eval(x)\nconsole.log(1)",
            "_.runInContext()",
        ] {
            assert_eq!(
                sources(code, ScriptLanguage::JavaScript),
                Vec::new(),
                "{code}"
            );
        }
    }

    #[test]
    fn ruby_string_forms_are_sites_and_block_forms_are_not() {
        use ScriptLanguage::Ruby as R;
        assert_eq!(sources("eval('1+1')", R), literal("eval", "1+1"));
        assert_eq!(sources("eval \"1+1\"", R), literal("eval", "1+1"));
        assert_eq!(sources("eval(x)", R), unverified("eval"));
        assert_eq!(
            sources("eval(Base64.decode64('eA=='))", R),
            unverified("eval")
        );
        assert_eq!(sources("eval(\"#{x}\")", R), unverified("eval"));
        assert_eq!(sources("Kernel.eval(x)", R), unverified("eval"));
        assert_eq!(sources("binding.eval(x)", R), unverified("eval"));
        assert_eq!(
            sources("obj.instance_eval(x)", R),
            unverified("instance_eval")
        );
        assert_eq!(
            sources("Foo.class_eval('def a; end')", R),
            literal("class_eval", "def a; end")
        );
        assert_eq!(sources("Foo.module_eval(x)", R), unverified("module_eval"));
        assert_eq!(sources("send(:eval, x)", R), unverified("send"));
        assert_eq!(sources("method(:eval).call(x)", R), unverified("eval"));

        for code in [
            "obj.instance_eval { foo }",
            "Foo.class_eval do\n  def a; end\nend",
            "Dentaku.eval(x)",
            "puts 'eval(x)'",
            "# eval(x)\nputs 1",
        ] {
            assert_eq!(sources(code, R), Vec::new(), "{code}");
        }
    }

    #[test]
    fn perl_string_eval_is_a_site_and_a_block_is_not() {
        use ScriptLanguage::Perl as P;
        assert_eq!(sources("eval('1+1');", P), literal("eval", "1+1"));
        assert_eq!(sources("eval \"1+1\";", P), literal("eval", "1+1"));
        assert_eq!(sources("eval '1+1' or die;", P), literal("eval", "1+1"));
        assert_eq!(sources("eval $x;", P), unverified("eval"));
        assert_eq!(sources("eval($x);", P), unverified("eval"));
        assert_eq!(sources("eval;", P), unverified("eval"));
        assert_eq!(sources("eval \"$x\";", P), unverified("eval"));
        assert_eq!(sources("eval('1' . $x);", P), unverified("eval"));
        assert_eq!(
            sources("eval(decode_base64('eA=='));", P),
            unverified("eval")
        );
        assert_eq!(sources("eval <<'CODE';\n1;\nCODE\n", P), unverified("eval"));
        assert_eq!(sources("print 1; eval(q{1+1});", P), unverified("eval"));

        for code in [
            "eval { die 'x' };",
            "eval {\n  print 1;\n};\nwarn $@ if $@;",
            "my $eval = 1;",
            "$h{eval} = 1;",
            "my %h = (eval => 1);",
            "$obj->eval($x);",
            "print 'eval($x)';",
            "print \"eval(\\$x)\";",
            "# eval($x)\nprint 1;",
            "don't(); print 1;",
        ] {
            assert_eq!(sources(code, P), Vec::new(), "{code}");
        }
    }

    /// Rows that do not end in a site read as `Unverified`, all of them, so a
    /// red run names every shape it lost.
    fn not_unverified<'a>(rows: &[(&'a str, ScriptLanguage)]) -> Vec<&'a str> {
        rows.iter()
            .filter(|(code, language)| {
                !dynamic_source_reading(code, *language, false, Duration::from_secs(5)).is_ok_and(
                    |reading| {
                        reading
                            .sites
                            .iter()
                            .any(|site| site.source == DynamicSource::Unverified)
                    },
                )
            })
            .map(|(code, _)| *code)
            .collect()
    }

    fn readable<'a>(rows: &[(&'a str, ScriptLanguage)]) -> Vec<&'a str> {
        rows.iter()
            .filter(|(code, language)| {
                dynamic_source_reading(code, *language, false, Duration::from_secs(5)).is_ok()
            })
            .map(|(code, _)| *code)
            .collect()
    }

    fn with_sites<'a>(rows: &[(&'a str, ScriptLanguage)]) -> Vec<&'a str> {
        rows.iter()
            .filter(|(code, language)| !sources(code, *language).is_empty())
            .map(|(code, _)| *code)
            .collect()
    }

    #[test]
    fn perl_text_the_walker_cannot_place_is_an_error() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            readable(&[
                ("$x =~ /'/;\neval $ENV{P};\n", P),
                ("$x =~ /'/;\neval $ENV{P};\nprint 'y';\n", P),
                ("$x =~ tr/'/\"/;\neval $ENV{P};\n", P),
                ("$x =~ s/'/ /;\neval $ENV{P};\n", P),
                ("$x =~ /#/; eval $ENV{P};\n", P),
                ("=pod\n\n'tis here.\n\n=cut\neval $ENV{P};\n", P),
                ("my $s = q( ' );\neval $ENV{P};\n", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn each_perl_form_ends_the_string_proof() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            readable(&[
                // Quote-like, across lines.
                ("my $s = q(\n'\n);\neval $ENV{P};\nprint 'y';\n", P),
                ("$x =~ m{\n  '\n}x;\neval $ENV{P};\nprint 'y';\n", P),
                // Any delimiter.
                ("s,',b,;\neval $ENV{P};\nprint 'y';\n", P),
                ("y;';x;;\neval $ENV{P};\nprint 'y';\n", P),
                ("s= '=b=;\neval $ENV{P};\nprint 'y';\n", P),
                ("s x 'xbx;\neval $ENV{P};\nprint 'y';\n", P),
                ("my $s = q' ';\neval $ENV{P};\nprint 'y';\n", P),
                ("my $s = q#a#; eval $ENV{P};\n", P),
                // Only the second part holds the quote.
                ("s{a}\n  {'};\neval $ENV{P};\nprint 'y';\n", P),
                ("s/a/'/;\neval $ENV{P};\nprint 'y';\n", P),
                // Patterns.
                ("$x =~ /\n'\n/x;\neval $ENV{P};\nprint 'y';\n", P),
                ("split /'/, $x;\neval $ENV{P};\nprint 'y';\n", P),
                (
                    "if ($x) { print 1 }\n/'/ and print 2;\neval $ENV{P};\nprint 'y';\n",
                    P
                ),
                // POD and here-documents.
                ("=pod\n\n'tis\n\n=cut\neval $ENV{P};\nprint 'y';\n", P),
                ("print <<T;\n'tis\nT\neval $ENV{P};\nprint 'y';\n", P),
                ("print <<\"T\";\n'tis\nT\neval $ENV{P};\nprint 'y';\n", P),
                ("print <<~T;\n  'tis\n  T\neval $ENV{P};\nprint 'y';\n", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn code_a_perl_string_runs_is_not_a_closed_string() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            readable(&[
                ("print \"@{[ eval $ENV{P} ]}\";\n", P),
                ("print \"${\\ eval $ENV{P} }\";\n", P),
                ("print \"${ eval $ENV{P} }\";\n", P),
                ("print \"$h{eval $ENV{P}}\";\n", P),
                ("print \"$a[eval $ENV{P}]\";\n", P),
                ("print \"@{[ map { $_ } eval $ENV{P} ]}\";\n", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn a_perl_message_that_names_eval_stays_clean() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            with_sites(&[
                // `%s` in a string is no quote-like operator.
                ("printf \"%s: eval failed, don't retry\\n\", $x;\n", P),
                // Before the first form the walk is still in step.
                ("print \"eval failed\\n\";\n$x =~ /'/;\n", P),
                // Division, a file test, keys, a shift and a plain name.
                (
                    "$a = $b / 2;\nprint \"it's\\n\";\n$c = $d / 3;\nprint \"eval\\n\";\n",
                    P
                ),
                ("if (-s $f) { print \"eval: it's\\n\"; }\n", P),
                ("my %h = (s => 1, y => 2, q => 3);\nprint \"eval\\n\";\n", P),
                ("$h{s} = 1;\nprint \"eval\\n\";\n", P),
                ("$n = 1 << 2;\nprint \"eval\\n\";\n", P),
                ("print \"${n} eval failed\\n\";\n", P),
                ("print \"$x[0]: eval failed\\n\";\n", P),
                // Forms with no quote in them change nothing.
                ("my $s = q(plain);\nprint \"eval\\n\";\n", P),
                ("$x =~ s/a/b/;\nprint \"eval\\n\";\n", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn a_perl_quote_that_hides_no_eval_stays_clean() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            with_sites(&[
                ("eval { $x =~ /'/ };", P),
                ("eval { $x =~ /'/ };\nprint 1;\n", P),
                ("eval { $s =~ tr/'/x/ };", P),
                ("eval { $x =~ /#/ };\nprint 'done';\n", P),
                ("print \"eval\";\n$x =~ /y/;\n", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn perl_punctuation_variables_open_no_string() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            not_unverified(&[
                ("print $\"; eval $ENV{P};", P),
                ("print $'; eval $ENV{P};", P),
                ("print $`; eval $ENV{P};", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn perl_eval_word_forms_are_sites() {
        use ScriptLanguage::Perl as P;
        assert_eq!(
            not_unverified(&[
                ("CORE::eval $ENV{P};", P),
                ("CORE::eval($ENV{P});", P),
                ("CORE::GLOBAL::eval($ENV{P});", P),
                ("for ($ENV{P}) {eval}", P),
                ("$_ = $ENV{P}; {eval}", P),
                ("print map {eval} @list;", P),
                // An apostrophe after a word opens no string.
                ("=pod\n\nIt's here.\n\n=cut\neval $ENV{P};\n", P),
                ("my $s = q(it's);\neval $ENV{P};\n", P),
            ]),
            Vec::<&str>::new()
        );
        assert_eq!(
            with_sites(&[
                ("$h{eval} = 1;", P),
                ("$h->{eval} = 1;", P),
                ("$h->{a}{eval} = 1;", P),
                ("$h[0]{eval} = 1;", P),
                ("$$h{eval} = 1;", P),
                ("@h{eval} = (1);", P),
                ("Foo::eval($x);", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn a_callee_past_the_nesting_limit_is_an_error() {
        use ScriptLanguage::{JavaScript as J, Python as P};
        let parens = format!("{}eval{}(x)", "(".repeat(12), ")".repeat(12));
        let sequences = format!("{}eval{}(x)", "(0, ".repeat(12), ")".repeat(12));
        let global = format!("{}globalThis{}", "(".repeat(12), ")".repeat(12));
        let member = format!("{global}.eval(x)");
        let subscript = format!("{global}[\"eval\"](x)");
        let new_member = format!("new {global}.Function(x)");
        let new_name = format!("new {}Function{}(x)", "(".repeat(12), ")".repeat(12));
        assert_eq!(
            readable(&[
                (parens.as_str(), J),
                (sequences.as_str(), J),
                (parens.as_str(), P),
                (member.as_str(), J),
                (subscript.as_str(), J),
                (new_member.as_str(), J),
                (new_name.as_str(), J),
            ]),
            Vec::<&str>::new()
        );
        assert_eq!(sources("((globalThis)).eval(x)", J), unverified("eval"));
        assert_eq!(sources("new ((Function))(x)", J), unverified("Function"));
        assert_eq!(sources("(((eval)))(x)", J), unverified("eval"));
        assert_eq!(sources("(((eval)))(x)", P), unverified("eval"));
    }

    #[test]
    fn an_unfinished_parse_is_an_error_not_a_clean_reading() {
        use ScriptLanguage::{JavaScript as J, Python as P, Ruby as R};
        assert_eq!(
            readable(&[
                ("def x(\neval('1+1')", R),
                ("def f(\nexec('1')", P),
                ("class {\neval('1+1')", J),
            ]),
            Vec::<&str>::new()
        );
        // A site that already denies needs no more.
        assert_eq!(sources("eval(x)\n)(", J), unverified("eval"));
        // A literal that does not parse is a string.
        assert!(literal_source_reading("eval is )( no code", P, Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn python_callee_shapes_are_sites() {
        use ScriptLanguage::Python as P;
        assert_eq!(
            not_unverified(&[
                ("(exec)(x)", P),
                ("((eval))(x)", P),
                ("Thread(target=exec, args=(x,)).start()", P),
                ("(a or eval)(x)", P),
                ("(eval if a else print)(x)", P),
            ]),
            Vec::<&str>::new()
        );
        assert_eq!(
            with_sites(&[
                ("f(eval=1)", P),
                ("f(exec=x)", P),
                ("x = y.eval", P),
                ("(print)(x)", P),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn javascript_callee_shapes_are_sites() {
        use ScriptLanguage::{JavaScript as J, TypeScript as T};
        assert_eq!(
            not_unverified(&[
                ("eval.call(null, x)", J),
                ("eval.apply(null, [x])", J),
                ("eval.bind(null)(x)", J),
                ("Function.call(null, x)()", J),
                ("Function.apply(null, [x])()", J),
                ("const F = Function; F(x)();", J),
                ("const F = Function; new F(x)();", J),
                ("(() => {})['constructor'](x)();", J),
                ("[]['filter']['constructor'](x)();", J),
                ("(() => {})[`constructor`](x)();", J),
                ("const f = () => {}; new f.constructor(x)();", J),
                ("const f = () => {}; new f['constructor'](x)();", J),
                ("const { eval: run } = globalThis; run(x);", J),
                ("(a || eval)(x)", J),
                ("(a ? eval : print)(x)", J),
                ("\\u0065val(x)", J),
                ("\\u{65}val(x)", J),
                ("new \\u0046unction(x)()", J),
                ("(globalThis as any).eval(x)", T),
                ("(<any>globalThis).eval(x)", T),
                ("globalThis!.eval(x)", T),
                ("(eval as any)(x)", T),
                ("(Function as any)(x)()", T),
                ("new (Function as any)(x)()", T),
            ]),
            Vec::<&str>::new()
        );
        assert_eq!(
            with_sites(&[
                ("x instanceof Function", J),
                ("new this.constructor(x)", J),
                ("x.constructor.name", J),
                ("x.call(null, y)", J),
                ("const o = { eval: 1 };", J),
                ("(print as any)(x)", T),
                ("const s = '\\u0041';", J),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn function_parameters_are_judged_as_well_as_the_body() {
        use ScriptLanguage::JavaScript as J;
        assert_eq!(
            not_unverified(&[
                ("new Function('a = process.env.P', 'return a')", J),
                ("new Function('a = eval(b)', 'return a')", J),
                ("Function('{ a } = b', 'return a')", J),
            ]),
            Vec::<&str>::new()
        );
        assert_eq!(
            sources("new Function('a, b', 'return a + b')", J),
            literal("Function", "return a + b")
        );
    }

    #[test]
    fn a_form_that_can_rebind_unseen_ends_the_literal_proof() {
        use ScriptLanguage::{JavaScript as J, Python as P, Ruby as R};
        assert_eq!(
            not_unverified(&[
                ("code = 'a'\nglobals()['code'] = read()\nexec(code)", P),
                ("code = 'a'\nglobals()[name] = read()\nexec(code)", P),
                ("code = 'a'\nlocals()[name] = read()\nexec(code)", P),
                ("code = 'a'\nvars()[name] = read()\nexec(code)", P),
                ("code = 'a'\nsetattr(mod, name, read())\nexec(code)", P),
                ("code = 'a'\nfrom m import *\nexec(code)", P),
                ("code = 'a'\nexec('code = read()')\nexec(code)", P),
                ("let s = 'a'; ({ s } = o); eval(s);", J),
                ("let s = 'a'; [s] = o; eval(s);", J),
                ("let s = 'a'; globalThis.s = x; eval(s);", J),
                ("let s = 'a'; globalThis[name] = x; eval(s);", J),
                ("var s = 'a'; with (o) { eval(s); }", J),
                ("var s = 'a'; eval('s = x'); eval(s);", J),
                ("s = 'a'\nbinding.local_variable_set(:s, x)\neval(s)", R),
                ("s = 'a'\neval('s = x')\neval(s)", R),
            ]),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn only_a_language_with_a_reader_leaves_the_posix_eval_view() {
        use ScriptLanguage::{Go, JavaScript, Perl, Php, Python, Ruby, TypeScript};
        for language in [JavaScript, TypeScript, Python, Ruby, Perl] {
            assert!(reads_dynamic_source(language), "{language:?}");
        }
        for language in [Php, Go] {
            assert!(!reads_dynamic_source(language), "{language:?}");
        }
    }

    /// The reader's own limit. The evaluator never reaches it for a heredoc:
    /// `active_heredocs` stops at the same size, so a larger body is not proved
    /// inert and keeps its outer-shell reading.
    #[test]
    fn the_size_limit_is_an_error_not_a_clean_reading() {
        let code = format!("eval(x)\n{}", "a = 1\n".repeat(MAX_DYNAMIC_SOURCE_BYTES));
        assert!(
            dynamic_source_reading(&code, ScriptLanguage::Python, false, Duration::from_secs(5))
                .is_err()
        );
    }

    #[test]
    fn a_body_with_no_candidate_is_not_parsed() {
        assert_eq!(
            dynamic_source_reading("print(1)", ScriptLanguage::Python, false, Duration::ZERO)
                .unwrap(),
            DynamicSourceReading::default()
        );
    }
}

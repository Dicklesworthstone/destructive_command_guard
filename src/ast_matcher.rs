//! Default policy for executable heredoc and inline-script source.
//!
//! Source recovery and the configurable AST corpus live in
//! `ast_source_analysis.rs`. This entry point also revalidates Python's
//! temporary-directory producer grants before the evaluator can use them.
//! An unknown or replaced factory keeps the existing recursive-deletion rule.

#[path = "ast_matcher/bash_temp_policy.rs"]
mod bash_temp_policy;
#[path = "ast_matcher/dynamic_source.rs"]
mod dynamic_source;
#[path = "ast_source_analysis.rs"]
mod source_analysis;
#[path = "ast_matcher/tempfile_provenance.rs"]
mod tempfile_provenance;

pub use source_analysis::*;

pub(crate) use bash_temp_policy::literal_temp_rm;
pub(crate) use dynamic_source::{
    DynamicSource, DynamicSourceReading, DynamicSourceSite, dynamic_source_reading,
    has_dynamic_source_candidates, literal_source_reading,
};

use crate::heredoc::ScriptLanguage;
use std::ops::Deref;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// The default matcher used by the CLI and hooks, including producer provenance.
/// Explicit `AstMatcher` corpora remain independently configurable as before.
#[derive(Debug, Default)]
pub struct DefaultPolicyMatcher;

/// The entry point used by the evaluator after executable-source extraction.
pub static DEFAULT_MATCHER: LazyLock<DefaultPolicyMatcher> =
    LazyLock::new(DefaultPolicyMatcher::default);

impl Deref for DefaultPolicyMatcher {
    type Target = source_analysis::DefaultPolicyMatcher;

    fn deref(&self) -> &Self::Target {
        &source_analysis::DEFAULT_MATCHER
    }
}

impl DefaultPolicyMatcher {
    /// Match executable source and revalidate its temporary producer exemptions.
    ///
    /// # Errors
    ///
    /// Returns the source matcher's parsing, availability, or timeout error.
    /// An incomplete producer proof instead withholds the optional exemption.
    pub fn find_matches(
        &self,
        code: &str,
        language: ScriptLanguage,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let matches = source_analysis::DEFAULT_MATCHER.find_matches(code, language)?;
        let matches = bash_temp_policy::refine(
            code,
            language,
            matches,
            source_analysis::protected_scan_budget(),
        );
        complete_python_deletion_matches(
            code,
            language,
            matches,
            source_analysis::protected_scan_budget(),
        )
    }

    /// Match source with an explicit budget. The producer proof uses only the
    /// time remaining after source matching, never an additional time envelope.
    ///
    /// # Errors
    ///
    /// Returns the source matcher's parsing, availability, or timeout error.
    pub fn find_matches_with_timeout(
        &self,
        code: &str,
        language: ScriptLanguage,
        timeout: Duration,
    ) -> Result<Vec<PatternMatch>, MatchError> {
        let started = Instant::now();
        let matches =
            source_analysis::DEFAULT_MATCHER.find_matches_with_timeout(code, language, timeout)?;
        let matches = bash_temp_policy::refine(
            code,
            language,
            matches,
            timeout.saturating_sub(started.elapsed()),
        );
        complete_python_deletion_matches(
            code,
            language,
            matches,
            timeout.saturating_sub(started.elapsed()),
        )
    }

    /// Return the first blocking match from the complete default policy.
    #[must_use]
    pub fn has_blocking_match(&self, code: &str, language: ScriptLanguage) -> Option<PatternMatch> {
        self.find_matches(code, language)
            .ok()?
            .into_iter()
            .find(|hit| hit.severity.blocks_by_default())
    }
}

// These are invocations of a statically named deletion member, not mere
// lookups. Keep both quote spellings explicit: matching must not depend on a
// grammar's treatment of quote tokens. Like the existing $M.rmtree pattern,
// the receiver is deliberately not restricted to one module variable name.
const PYTHON_REFLECTIVE_DELETE_CALLEES: [&str; 7] = [
    "getattr($M, 'rmtree')",
    "getattr($M, \"rmtree\")",
    "$B.getattr($M, 'rmtree')",
    "$B.getattr($M, \"rmtree\")",
    "$M.__dict__['rmtree']",
    "$M.__dict__[\"rmtree\"]",
    "$M.rmtree.__call__",
];

static PYTHON_REFLECTIVE_DELETE_MATCHER: LazyLock<AstMatcher> = LazyLock::new(|| {
    // Reuse the registered rule, including its target refinement, rather than
    // harvesting a receiver's first literal ('rmtree') as the deletion path.
    // Explicit user-created AstMatcher corpora remain unchanged.
    let meta = source_analysis::default_patterns()
        .remove(&ScriptLanguage::Python)
        .and_then(|patterns| {
            patterns
                .into_iter()
                .find(|meta| meta.rule_id == "heredoc.python.shutil_rmtree")
        })
        .expect("the default Python corpus registers its recursive-deletion rule");
    let mut patterns = Vec::new();
    for callee in PYTHON_REFLECTIVE_DELETE_CALLEES {
        for pattern in [format!("{callee}($$$)"), format!("({callee})($$$)")] {
            let mut pattern_meta = meta.clone();
            pattern_meta.pattern_str = pattern;
            patterns.push(pattern_meta);
        }
    }
    AstMatcher::with_patterns(std::collections::HashMap::from([(
        ScriptLanguage::Python,
        patterns,
    )]))
});

fn complete_python_deletion_matches(
    code: &str,
    language: ScriptLanguage,
    mut matches: Vec<PatternMatch>,
    budget: Duration,
) -> Result<Vec<PatternMatch>, MatchError> {
    let started = Instant::now();
    if language == ScriptLanguage::Python
        && code.contains("rmtree")
        && ["getattr", "__dict__", "__call__"]
            .iter()
            .any(|name| code.contains(name))
    {
        // The ordinary AST worker supplies byte bounds, cancellation and the
        // error contract. An incomplete extra scan is not an empty success.
        let extra = PYTHON_REFLECTIVE_DELETE_MATCHER.find_matches_with_timeout(
            code,
            language,
            budget.saturating_sub(started.elapsed()),
        )?;
        let mut seen: std::collections::HashSet<_> = matches
            .iter()
            .map(|hit| (hit.start, hit.end, hit.rule_id.clone()))
            .collect();
        for hit in extra {
            if seen.insert((hit.start, hit.end, hit.rule_id.clone())) {
                matches.push(hit);
            }
        }
        // Keep the original finding's precedence on a tie. The supplemental
        // corpus also resolves imported aliases; do not duplicate those hits.
        matches.sort_by_key(|hit| hit.start);
    }
    // A reflected call gets exactly the existing descendant and factory
    // policies. New .temp matches must not bypass factory/dependency proofs.
    // Share the remaining budget; do not grant the proof a fresh deadline.
    Ok(tempfile_provenance::validate(
        code,
        language,
        matches,
        budget.saturating_sub(started.elapsed()),
    ))
}

/// Recover literal shell values only from source with execution evidence.
///
/// #560 was caused by promoting every unowned string containing backticks or
/// dollar-parens to a complete shell program. A tuple, regex replacement, or
/// opaque text-editing helper does not establish that execution context. This
/// gate is NOT a source exemption: the evaluator still checks named sinks,
/// interpreter operations, protected writes, and the original outer command.
///
/// Be conservative when a program refers to execution APIs, aliases them, or
/// uses reflective/computed dispatch: retain the complete original recovery,
/// including every indirect literal and exec/eval dependency. This is a
/// program-level evidence screen, not a proof of non-execution or a taint analysis.
/// Unknown helper calls alone do not establish a shell-command role in an
/// isolated interpreter program. An unproved outer consumer still requires
/// the original recovery: even a print-only program can feed a later shell.
///
/// The screen runs INSIDE the existing worker's permit and deadline, including
/// parsing. No extra worker or fresh time envelope is created. A failed or
/// incomplete screen keeps the original fail-closed analysis, not an allowance.
pub(crate) fn interpreter_literal_shell_commands(
    code: &str,
    language: ScriptLanguage,
    allow_documentation_literals: impl FnOnce() -> Option<bool> + Send + 'static,
    budget: Duration,
) -> Result<Vec<ReconstructedCommand>, MatchError> {
    // The source analyzer owns the only source copy, parse, worker permit and
    // deadline. Screen its parsed tree instead of reparsing a captured copy in
    // the outer-consumer callback. That callback still runs first and once.
    source_analysis::interpreter_literal_shell_commands_with_execution_evidence(
        code,
        language,
        allow_documentation_literals,
        budget,
        true,
    )
}

/// [`interpreter_literal_shell_commands`] for a program the outer shell
/// expands before the interpreter reads it (an unquoted heredoc body). Its
/// backquotes run at that expansion whatever the program then does with the
/// string, so no candidate is screened or cut as text only a later shell
/// might run: every one is judged whole.
pub(crate) fn expanded_interpreter_literal_shell_commands(
    code: &str,
    language: ScriptLanguage,
    allow_documentation_literals: impl FnOnce() -> Option<bool> + Send + 'static,
    budget: Duration,
) -> Result<Vec<ReconstructedCommand>, MatchError> {
    source_analysis::interpreter_literal_shell_commands_with_execution_evidence(
        code,
        language,
        allow_documentation_literals,
        budget,
        false,
    )
}

// Retain the previous two-parse composition only as a differential oracle.
#[cfg(test)]
fn literal_recovery_scope(
    code: &str,
    language: ScriptLanguage,
    isolated_source: bool,
) -> Option<bool> {
    // No source-local absence of execution APIs proves where stdout or a
    // generated file goes. Keep the caller's stricter interpretation before
    // attempting this screen, including pipelines, wrappers and later readers.
    if !isolated_source {
        return Some(false);
    }
    literal_source_has_execution_evidence(code, language).then_some(true)
}

// Independent bounds on this optional screen. Crossing either withholds the
// screen, leaving the existing source analyzer's hard bounds and errors intact.
const LITERAL_EVIDENCE_MAX_BYTES: usize = 256 * 1024;
const LITERAL_EVIDENCE_MAX_NODES: usize = 4096;

#[cfg(test)]
fn literal_source_has_execution_evidence(code: &str, language: ScriptLanguage) -> bool {
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    if code.len() > LITERAL_EVIDENCE_MAX_BYTES {
        return true;
    }
    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        _ => return true,
    };
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
    let ast = {
        let _parse = crate::perf::phase(crate::perf::ProfilePhase::AstParse);
        AstGrep::try_new(code, grammar)
    };
    let Ok(ast) = ast else {
        return true;
    };
    literal_root_has_execution_evidence(&ast.root(), language)
}

/// Whether a Python or JavaScript program may start a process or evaluate
/// code at all: an execution API name under any arguments (a closed
/// `subprocess.run([...])` included), or any shape the evidence screen cannot
/// read. Other languages, oversized programs and parse failures answer yes.
///
/// Used where a program's capability, not its literals, is the question: an
/// interpreter that reads its program from its own heredoc cannot run what
/// another heredoc wrote unless that program can execute something (#591).
pub(crate) fn program_may_execute_code(code: &str, language: ScriptLanguage) -> bool {
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    if code.len() > LITERAL_EVIDENCE_MAX_BYTES {
        return true;
    }
    let grammar = match language {
        ScriptLanguage::Python => SupportLang::Python,
        ScriptLanguage::JavaScript => SupportLang::JavaScript,
        _ => return true,
    };
    let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
    let ast = {
        let _parse = crate::perf::phase(crate::perf::ProfilePhase::AstParse);
        AstGrep::try_new(code, grammar)
    };
    let Ok(ast) = ast else {
        return true;
    };
    root_has_execution_evidence(&ast.root(), language, false)
}

/// Inspect the recovery worker's tree; do not derive a new source exemption.
/// A negative answer still requires the caller's independent outer-consumer
/// proof. All original node, syntax, callee and identifier checks remain here.
fn literal_root_has_execution_evidence<D: ast_grep_core::Doc>(
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> bool {
    root_has_execution_evidence(root, language, true)
}

/// The evidence scan. `exempt_closed_calls` lets a [`closed_process_call`]
/// pass, which is right when the question is whether some *other* literal
/// may run, and wrong when it is whether the program can run anything.
fn root_has_execution_evidence<D: ast_grep_core::Doc>(
    root: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    exempt_closed_calls: bool,
) -> bool {
    for (index, node) in root.dfs().enumerate() {
        if index >= LITERAL_EVIDENCE_MAX_NODES || node.is_error() || node.is_missing() {
            return true;
        }
        let kind = node.kind();
        if matches!(kind.as_ref(), "call" | "call_expression") {
            let Some(function) = node.field("function") else {
                return true;
            };
            if !matches!(
                function.kind().as_ref(),
                "identifier" | "attribute" | "member_expression"
            ) || language == ScriptLanguage::JavaScript
                && node
                    .field("arguments")
                    .is_none_or(|arguments| arguments.kind().as_ref() != "arguments")
            {
                // Computed calls, returned callables, tagged templates, and
                // parenthesized dispatch keep the original conservative scan.
                return true;
            }
        }
        if language == ScriptLanguage::JavaScript
            && matches!(
                kind.as_ref(),
                "import_statement" | "new_expression" | "subscript_expression"
            )
        {
            // ESM imports and computed members may expose/alias execution
            // capabilities without a literal terminal method name.
            return true;
        }
        if language == ScriptLanguage::Python
            && kind.as_ref() == "import_from_statement"
            && node.text().contains('*')
        {
            return true;
        }
        if matches!(kind.as_ref(), "identifier" | "property_identifier") {
            let name = node.text();
            // Python normalizes Unicode names; JavaScript accepts identifier
            // escapes. Unmodeled spellings cannot exclude an execution API.
            if !name.is_ascii()
                || name.contains('\\')
                || name.starts_with("__")
                || (literal_execution_name(name.as_ref())
                    && !(exempt_closed_calls
                        && closed_process_call(&node, name.as_ref(), language)))
            {
                return true;
            }
        }
    }
    false
}

/// Whether `name_node` names the callee of a process call that no string
/// with shell substitution syntax can reach: `subprocess.run(['git', 'show',
/// 'origin/main:f'], capture_output=True)`, `re.compile(r'\s+$')` (#560).
///
/// The callee is a process API ([`closed_process_call_name`]) under a plain
/// dotted name, and every argument is a literal (a string, number, boolean
/// or `None`, or a list, tuple or keyword argument of those) whose value
/// holds no backquote and no `$(`. No other value of the program can reach
/// such a call, and the named-sink scanners judge its own arguments, so it
/// is no evidence that some other literal runs. A reference that is not a
/// call (`f = os.system`), a computed receiver, a variable or a call among
/// the arguments, and code evaluation or reflection under any arguments all
/// remain evidence.
fn closed_process_call<D: ast_grep_core::Doc>(
    name_node: &ast_grep_core::Node<'_, D>,
    name: &str,
    language: ScriptLanguage,
) -> bool {
    let Some(parent) = name_node.parent() else {
        return false;
    };
    let (callee, attribute_form) = match parent.kind().as_ref() {
        "call" | "call_expression" => (name_node.clone(), false),
        "attribute" | "member_expression" => {
            let terminal = match language {
                ScriptLanguage::Python => parent.field("attribute"),
                _ => parent.field("property"),
            };
            if terminal.is_none_or(|terminal| terminal.range() != name_node.range())
                || parent
                    .field("object")
                    .is_none_or(|object| !plain_dotted_name(&object, 0))
            {
                return false;
            }
            (parent, true)
        }
        _ => return false,
    };
    let Some(call) = callee.parent() else {
        return false;
    };
    let Some(arguments) = call.field("arguments") else {
        return false;
    };
    let closed = closed_process_call_name(name, attribute_form)
        && matches!(call.kind().as_ref(), "call" | "call_expression")
        && call
            .field("function")
            .is_some_and(|function| function.range() == callee.range())
        && matches!(arguments.kind().as_ref(), "argument_list" | "arguments")
        && arguments
            .children()
            .filter(|argument| argument.is_named() && argument.kind().as_ref() != "comment")
            .all(|argument| closed_literal_argument(&argument, language, 0));
    if !closed {
        return false;
    }
    // `re.compile(…)` builds a pattern and `fork()` copies this program; any
    // other call runs a command line, which must not be one that can run a
    // file this program may have written (`['sh', 'm.sh']`, `'./gen'`).
    (attribute_form && name == "compile")
        || matches!(name, "fork" | "forkpty")
        || closed_call_command_line(&arguments, language)
            .is_some_and(|line| !crate::heredoc::shell_text_may_run_generated_code(&line))
}

/// The command line a [`closed_process_call`] runs, as shell text: string
/// arguments as written (a command string), list items as quoted words
/// (`['git', 'show', 'x']`), in argument order, from the positional arguments
/// and Python's `args=`. Under a `shell=` keyword a list's items are joined
/// as written, since its first item is a command string. `None` when there
/// is none, or when an `executable=` keyword names the program separately.
fn closed_call_command_line<D: ast_grep_core::Doc>(
    arguments: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
) -> Option<String> {
    fn word<D: ast_grep_core::Doc>(
        node: &ast_grep_core::Node<'_, D>,
        language: ScriptLanguage,
    ) -> Option<String> {
        match node.kind().as_ref() {
            "string" | "template_string" | "concatenated_string" => {
                source_analysis::static_interpreter_literal(node, language, 0)
            }
            "integer" | "float" | "number" => Some(node.text().to_string()),
            _ => None,
        }
    }
    let through_shell = arguments.children().any(|argument| {
        argument.kind().as_ref() == "keyword_argument"
            && argument
                .field("name")
                .is_some_and(|keyword| keyword.text().as_ref() == "shell")
    });
    let mut parts: Vec<String> = Vec::new();
    for argument in arguments
        .children()
        .filter(|argument| argument.is_named() && argument.kind().as_ref() != "comment")
    {
        let value = match argument.kind().as_ref() {
            "keyword_argument" => {
                let keyword = argument.field("name")?;
                match keyword.text().as_ref() {
                    "executable" => return None,
                    "args" => argument.field("value")?,
                    _ => continue,
                }
            }
            _ => argument,
        };
        match value.kind().as_ref() {
            "list" | "tuple" | "array" => {
                let words: Option<Vec<String>> = value
                    .children()
                    .filter(|item| item.is_named() && item.kind().as_ref() != "comment")
                    .map(|item| word(&item, language))
                    .collect();
                let words = words?;
                parts.push(if through_shell {
                    words.join(" ")
                } else {
                    shell_words::join(words)
                });
            }
            _ => parts.push(word(&value, language)?),
        }
    }
    let line = parts.join(" ");
    (!line.trim().is_empty()).then_some(line)
}

/// The [`literal_execution_name`]s that start a process rather than evaluate
/// code or look a callable up: `system`, `run`, `Popen`, `spawn*`, `exec*`
/// other than `exec` itself, and `compile` when it is a method (`re.compile`;
/// the builtin `compile` makes code for `exec`).
fn closed_process_call_name(name: &str, attribute_form: bool) -> bool {
    (name.starts_with("exec") && !matches!(name, "exec" | "execfile"))
        || name.starts_with("spawn")
        || name.starts_with("popen")
        || matches!(
            name,
            "system"
                | "Popen"
                | "run"
                | "call"
                | "check_call"
                | "check_output"
                | "getoutput"
                | "getstatusoutput"
                | "create_subprocess_shell"
                | "create_subprocess_exec"
                | "posix_spawn"
                | "posix_spawnp"
                | "fork"
                | "forkpty"
                | "startfile"
        )
        || (attribute_form && name == "compile")
}

/// `os`, `subprocess`, `asyncio.subprocess`: identifiers joined by member
/// access, with no call, subscript or other expression a value could hide in.
fn plain_dotted_name<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    depth: usize,
) -> bool {
    if depth >= 16 {
        return false;
    }
    match node.kind().as_ref() {
        "identifier" => true,
        "attribute" | "member_expression" => node
            .field("object")
            .is_some_and(|object| plain_dotted_name(&object, depth + 1)),
        _ => false,
    }
}

/// An argument of a [`closed_process_call`]: a literal whose decoded value has
/// no shell substitution syntax, or a list, tuple or keyword argument of them.
fn closed_literal_argument<D: ast_grep_core::Doc>(
    node: &ast_grep_core::Node<'_, D>,
    language: ScriptLanguage,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match node.kind().as_ref() {
        "integer" | "float" | "number" | "true" | "false" | "none" | "null" => true,
        "string" | "template_string" | "concatenated_string" => {
            source_analysis::static_interpreter_literal(node, language, 0)
                .is_some_and(|value| !value.contains('`') && !value.contains("$("))
        }
        "list" | "tuple" | "array" | "parenthesized_expression" => node
            .children()
            .filter(|item| item.is_named() && item.kind().as_ref() != "comment")
            .all(|item| closed_literal_argument(&item, language, depth + 1)),
        "keyword_argument" => node
            .field("value")
            .is_some_and(|value| closed_literal_argument(&value, language, depth + 1)),
        _ => false,
    }
}

fn literal_execution_name(name: &str) -> bool {
    // References count, not just direct calls: f = os.system; f(value), imports
    // with aliases, and methods in nested callbacks retain the original scan.
    // Names are deliberately a superset: an unrelated run()/call() may still
    // need review, but a familiar execution API never gains a new exemption.
    name.starts_with("exec")
        || name.starts_with("spawn")
        || name.starts_with("popen")
        || matches!(
            name,
            "system"
                | "popen"
                | "Popen"
                | "run"
                | "call"
                | "check_call"
                | "check_output"
                | "getoutput"
                | "getstatusoutput"
                | "create_subprocess_shell"
                | "create_subprocess_exec"
                | "shell"
                | "sh"
                | "bash"
                | "zsh"
                | "dash"
                | "ksh"
                | "fish"
                | "posix_spawn"
                | "posix_spawnp"
                | "fork"
                | "forkpty"
                | "startfile"
                | "pexpect"
                | "pty"
                | "eval"
                | "compile"
                | "getattr"
                | "setattr"
                | "delattr"
                | "globals"
                | "locals"
                | "vars"
                | "import_module"
                | "importlib"
                | "runpy"
                | "ctypes"
                | "Function"
                | "AsyncFunction"
                | "GeneratorFunction"
                | "constructor"
                | "Reflect"
                | "global"
                | "globalThis"
                | "window"
                | "process"
                | "module"
                | "require"
        )
}

#[cfg(test)]
mod shared_literal_ast_tests {
    use super::*;

    type Snapshot = Result<Vec<(String, usize, usize)>, String>;

    fn snapshot(result: Result<Vec<ReconstructedCommand>, MatchError>) -> Snapshot {
        result
            .map(|commands| {
                commands
                    .into_iter()
                    .map(|command| (command.command, command.start, command.end))
                    .collect()
            })
            .map_err(|error| error.to_string())
    }

    fn incumbent(code: &str, language: ScriptLanguage, isolated: bool) -> Snapshot {
        let result = match literal_recovery_scope(code, language, isolated) {
            Some(allow_documentation) => source_analysis::interpreter_literal_shell_commands_inner(
                code,
                language,
                allow_documentation,
            ),
            None => Ok(Vec::new()),
        };
        snapshot(result)
    }

    fn shared(code: &str, language: ScriptLanguage, isolated: bool) -> Snapshot {
        snapshot(
            source_analysis::interpreter_literal_shell_commands_inner_with_execution_evidence(
                code, language, isolated, true,
            ),
        )
    }

    fn execution_source(language: ScriptLanguage, lines: usize) -> String {
        match language {
            ScriptLanguage::Python => format!(
                "import os\n{}command = 'echo $(git reset --hard)'\ndispatch = os.system\ndispatch(command)\n",
                "value = 1\n".repeat(lines),
            ),
            ScriptLanguage::JavaScript => format!(
                "const cp = require('child_process');\n{}const command = 'echo $(git reset --hard)';\nconst dispatch = cp.execSync; dispatch(command);\n",
                "var value = 1;\n".repeat(lines),
            ),
            _ => unreachable!("the fixture covers the two literal-recovery languages"),
        }
    }

    #[test]
    fn shared_literal_ast_matches_the_two_parse_execution_reference() {
        for language in [ScriptLanguage::Python, ScriptLanguage::JavaScript] {
            for lines in [0, 40, 300] {
                let source = execution_source(language, lines);
                for isolated in [false, true] {
                    let expected = incumbent(&source, language, isolated);
                    let actual = shared(&source, language, isolated);
                    assert_eq!(actual, expected, "{language:?}, {lines}, {isolated}");
                    let commands = actual.expect("complete execution fixture");
                    assert!(
                        commands
                            .iter()
                            .any(|(command, _, _)| { command == "echo $(git reset --hard)" }),
                        "an indirect executable payload must survive AST sharing"
                    );
                    for (_, start, end) in commands {
                        assert!(source.get(start..end).is_some(), "original UTF-8 byte span");
                    }
                }
            }
        }
    }

    #[test]
    fn shared_literal_ast_preserves_data_and_outer_consumer_boundaries() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "text = ('echo $(git reset --hard)', 'data')\nprint(text)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const text = ['echo $(git reset --hard)', 'data']; console.log(text);",
            ),
            (
                ScriptLanguage::Python,
                "text = 'élève $(git reset --hard)'\nedit(text)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const text = 'élève $(git reset --hard)'; edit(text);",
            ),
        ] {
            for isolated in [false, true] {
                let actual = shared(source, language, isolated);
                assert_eq!(actual, incumbent(source, language, isolated), "{source}");
                let commands = actual.expect("complete literal fixture");
                assert_eq!(commands.is_empty(), isolated, "{source}");
            }
        }
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os\nf = getattr(os, 'system')\nf('$(git reset --hard)')",
            ),
            (
                ScriptLanguage::Python,
                "def f(value):\n    os.system(value)\nf('$(git reset --hard)')",
            ),
            (
                ScriptLanguage::JavaScript,
                "const f = cp['execSync']; f('$(git reset --hard)');",
            ),
            (ScriptLanguage::JavaScript, "tag`echo $(git reset --hard)`;"),
        ] {
            let actual = shared(source, language, true);
            assert_eq!(actual, incumbent(source, language, true), "{source}");
            assert!(
                !actual.expect("complete reflective fixture").is_empty(),
                "{source}"
            );
        }
    }

    #[test]
    fn shared_literal_ast_keeps_incomplete_analysis_and_cheap_gates() {
        let oversized = format!(
            "#{}\ntext = '$(git reset --hard)'",
            "x".repeat(LITERAL_EVIDENCE_MAX_BYTES)
        );
        // Past the evidence screen's node bound and denser than one node per
        // source byte, which bounds the recovery's tree at any length.
        let many_nodes = format!(
            "{}text = '$(git reset --hard)'",
            "0;".repeat(4 * LITERAL_EVIDENCE_MAX_NODES)
        );
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os\ntext = '$(git reset --hard)'\nos.system(",
            ),
            (
                ScriptLanguage::JavaScript,
                "const text = '$(git reset --hard)'; cp.execSync(",
            ),
            (ScriptLanguage::Python, oversized.as_str()),
            (ScriptLanguage::Python, many_nodes.as_str()),
        ] {
            for isolated in [false, true] {
                let actual = shared(source, language, isolated);
                assert_eq!(
                    actual,
                    incumbent(source, language, isolated),
                    "{language:?}"
                );
                assert!(
                    actual.is_err(),
                    "an incomplete tree cannot become empty success"
                );
            }
        }
        for source in [
            "text = '$(git reset --hard)'",
            "import os\ntext = '$(git reset --hard)'\nos.system(text)",
        ] {
            assert!(matches!(
                interpreter_literal_shell_commands(
                    source,
                    ScriptLanguage::Python,
                    || panic!("zero budget must stop before the callback or parser"),
                    Duration::ZERO,
                ),
                Err(MatchError::Timeout { .. })
            ));
        }
        assert!(
            interpreter_literal_shell_commands(
                "print('ordinary text')",
                ScriptLanguage::Python,
                || panic!("the no-candidate fast path must not run the callback"),
                Duration::ZERO,
            )
            .expect("no candidates need no recovery budget")
            .is_empty()
        );
    }

    #[test]
    fn shared_literal_worker_preserves_the_outer_callback_contract() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A callback declining an unsupported extraction must run before the
        // interpreter parser. These deliberately malformed programs would be
        // errors if tree construction moved ahead of that decision.
        for (language, source) in [
            (ScriptLanguage::Python, "print('$(git reset --hard)'"),
            (ScriptLanguage::JavaScript, "edit('$(git reset --hard)'"),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&calls);
            let commands = interpreter_literal_shell_commands(
                source,
                language,
                move || {
                    observed.fetch_add(1, Ordering::Relaxed);
                    None
                },
                Duration::from_secs(5),
            )
            .expect("unsupported extraction stays with its original analysis path");
            assert!(commands.is_empty());
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }

        // Exercise the actual worker for both consumer modes, not just the
        // inner recovery function. Verify source spans and payloads after the
        // worker has released its source, tree, and permit.
        for language in [ScriptLanguage::Python, ScriptLanguage::JavaScript] {
            let source = execution_source(language, 40);
            for isolated in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&calls);
                let actual = snapshot(interpreter_literal_shell_commands(
                    &source,
                    language,
                    move || {
                        observed.fetch_add(1, Ordering::Relaxed);
                        Some(isolated)
                    },
                    Duration::from_secs(5),
                ));
                let expected = incumbent(&source, language, isolated);
                assert!(
                    expected.as_ref().is_ok_and(|commands| !commands.is_empty()),
                    "the execution reference must be complete and nonempty"
                );
                assert_eq!(actual, expected, "{language:?}, isolated={isolated}");
                assert_eq!(calls.load(Ordering::Relaxed), 1);
            }
        }
    }

    /// Same-process paired component comparison, not a shipping hook gate.
    /// Timed work includes each strategy's parser(s), scans and output allocation.
    /// Fixture construction and output comparison are outside both timers.
    #[test]
    #[ignore = "paired component benchmark; run release with --test-threads=1"]
    fn paired_shared_literal_ast_benchmark() {
        use std::hint::black_box;

        const RUNS: usize = 60;
        const WARMUP: usize = 6;
        for (shape, language, lines, isolated) in [
            ("python_small", ScriptLanguage::Python, 0, true),
            ("python_40", ScriptLanguage::Python, 40, true),
            ("python_300", ScriptLanguage::Python, 300, true),
            ("javascript_small", ScriptLanguage::JavaScript, 0, true),
            ("javascript_40", ScriptLanguage::JavaScript, 40, true),
            ("javascript_300", ScriptLanguage::JavaScript, 300, true),
            ("unproved_consumer_300", ScriptLanguage::Python, 300, false),
        ] {
            let source = execution_source(language, lines);
            let expected = incumbent(&source, language, isolated).expect("reference completes");
            assert!(
                !expected.is_empty(),
                "do not benchmark missing recovery as success"
            );
            let mut old_ns = Vec::with_capacity(RUNS);
            let mut shared_ns = Vec::with_capacity(RUNS);
            for pair in 0..WARMUP + RUNS {
                for use_shared in [pair % 2 == 0, pair % 2 != 0] {
                    let started = Instant::now();
                    let actual = if use_shared {
                        shared(black_box(&source), language, isolated)
                    } else {
                        incumbent(black_box(&source), language, isolated)
                    };
                    let elapsed_ns = started.elapsed().as_nanos();
                    assert_eq!(actual.as_ref(), Ok(&expected), "{shape}");
                    if pair >= WARMUP {
                        if use_shared {
                            shared_ns.push(elapsed_ns);
                        } else {
                            old_ns.push(elapsed_ns);
                        }
                    }
                    let _ = black_box(actual);
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "kind": "paired_shared_literal_ast",
                    "scope": "in_process_literal_recovery",
                    "reference_source": "36596fab6ca26aa5d40a70f4acbdced3db0d1886",
                    "reference": "previous_composition_with_shared_predicates",
                    "shape": shape,
                    "source_bytes": source.len(),
                    "runs": RUNS,
                    "warmup": WARMUP,
                    "old_ns": old_ns,
                    "shared_ns": shared_ns,
                })
            );
        }
    }
}

#[cfg(test)]
mod literal_execution_evidence_tests {
    use super::*;

    #[test]
    fn python_reflective_rmtree_uses_the_existing_path_policy() {
        #[derive(serde::Deserialize)]
        struct Case {
            id: String,
            decision: String,
            source: String,
        }
        let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/python_reflective_rmtree.json"
        )))
        .expect("valid reflective-deletion verdict fixtures");
        assert!(!cases.is_empty());
        for case in cases {
            let matches = DEFAULT_MATCHER
                .find_matches_with_timeout(
                    &case.source,
                    ScriptLanguage::Python,
                    Duration::from_secs(5),
                )
                .unwrap_or_else(|error| panic!("{}: {error:?}", case.id));
            assert_eq!(
                matches.iter().any(|hit| hit.severity.blocks_by_default()),
                case.decision == "deny",
                "{}: {}",
                case.id,
                case.source,
            );
        }
    }

    #[test]
    fn reflective_deletion_budget_exhaustion_is_not_a_clean_result() {
        assert!(
            complete_python_deletion_matches(
                "import shutil\ngetattr(shutil, 'rmtree')('/tmp')",
                ScriptLanguage::Python,
                Vec::new(),
                Duration::ZERO,
            )
            .is_err()
        );
        assert!(
            complete_python_deletion_matches(
                "print('ready')",
                ScriptLanguage::Python,
                Vec::new(),
                Duration::ZERO,
            )
            .expect("unrelated source does not start a supplemental scan")
            .is_empty()
        );
    }

    #[test]
    fn reflective_deletion_merge_preserves_primary_rule_identity() {
        let source = "import shutil\nfrom shutil import rmtree as wipe\nwipe('/tmp')\ngetattr(shutil, 'copy')";
        let original = source_analysis::DEFAULT_MATCHER
            .find_matches_with_timeout(source, ScriptLanguage::Python, Duration::from_secs(5))
            .expect("complete primary deletion analysis");
        let primary = original
            .iter()
            .find(|hit| hit.rule_id == "heredoc.python.shutil_rmtree")
            .expect("the imported deletion has the established rule")
            .clone();
        let matches = complete_python_deletion_matches(
            source,
            ScriptLanguage::Python,
            original,
            Duration::from_secs(5),
        )
        .expect("complete supplemental scan");
        assert_eq!(
            matches.iter().filter(|hit| **hit == primary).count(),
            1,
            "do not duplicate or replace the primary finding",
        );
    }

    #[test]
    fn unproved_outer_consumers_keep_the_original_recovery_560() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "text = 'echo $(git reset --hard)'\nprint(text)",
            ),
            (
                ScriptLanguage::JavaScript,
                "const text = 'echo $(git reset --hard)'; console.log(text);",
            ),
        ] {
            assert_eq!(literal_recovery_scope(source, language, false), Some(false));
            assert_eq!(literal_recovery_scope(source, language, true), None);
        }
    }

    #[test]
    fn python_data_literals_do_not_establish_shell_execution_560() {
        for source in [
            "import re\ns = re.sub(r'x$', \"it's `tool --help`\", 'x')",
            "y = ('x', \"it's `tool --help`\")",
            "y = f('x', \"it's `tool --help`\")",
            "rep('''use core::fav;\nfn with_store<R>(\n/// The items `zone` belongs to (`list_items`).''')",
            "import sys\nnew = ('echo $(date)\\n' '(cd t && task >\"$W/out-$SHA.log\")\\n' + old)",
            "text = \"os.system('echo $(date)')\"\nwrite_example(text)",
            "# os.system and eval are documentation, not references\ny = ('$(date)', 'text')",
        ] {
            assert!(
                !literal_source_has_execution_evidence(source, ScriptLanguage::Python),
                "interpreter data was promoted to a shell program: {source}"
            );
        }
    }

    #[test]
    fn javascript_data_literals_do_not_establish_shell_execution_560() {
        for source in [
            "const text = \"it's `tool --help`\"; edit(text);",
            "const pair = ['x', \"it's `tool --help`\"];",
            "const text = 'fn with_store<R>( `zone`'; rep(text);",
            "const text = '(task >\"$W/out.log\") $(date)'; edit(text);",
            "const text = \"execSync('echo $(date)')\"; writeExample(text);",
        ] {
            assert!(
                !literal_source_has_execution_evidence(source, ScriptLanguage::JavaScript),
                "interpreter data was promoted to a shell program: {source}"
            );
        }
    }

    #[test]
    fn direct_indirect_and_reflective_execution_keep_full_recovery_560() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import os\ns = 'echo $(date); task >\"$W/out\"'\nos.system(s)",
            ),
            (
                ScriptLanguage::Python,
                "from os import system as dispatch\ns = 'echo $(date)'\ndispatch(s)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess as p\nf = p.run\nf('echo $(date)', shell=True)",
            ),
            (
                ScriptLanguage::Python,
                "import os\nos.posix_spawn('/bin/sh', ['sh', '-c', 'echo $(date)'], {})",
            ),
            (
                ScriptLanguage::Python,
                "import os\nf = getattr(os, 'sys' + 'tem')\nf('echo $(date)')",
            ),
            (
                ScriptLanguage::Python,
                "import os\ns = 'git reset --hard'\nexec('os.system(s)')",
            ),
            (
                ScriptLanguage::Python,
                "from helpers import *\nf('echo $(date)')",
            ),
            (
                ScriptLanguage::Python,
                "def helper(s):\n    os.system(s)\nhelper('echo $(date)')",
            ),
            (ScriptLanguage::Python, "ｅxec('echo $(date)')"),
            (
                ScriptLanguage::JavaScript,
                "const cp = require('child_process'); const s = 'echo $(date)'; cp.execSync(s);",
            ),
            (
                ScriptLanguage::JavaScript,
                "import {execSync as dispatch} from 'node:child_process'; dispatch('echo $(date)');",
            ),
            (
                ScriptLanguage::JavaScript,
                "const f = cp['exe' + 'cSync']; f('echo $(date)');",
            ),
            (ScriptLanguage::JavaScript, "Function('return process')();"),
            (ScriptLanguage::JavaScript, "tag`echo $(date)`;"),
            (ScriptLanguage::JavaScript, r"e\u0076al('echo $(date)');"),
            (
                ScriptLanguage::JavaScript,
                "const handler = value => cp.execSync(value); handler('echo $(date)');",
            ),
        ] {
            assert!(
                literal_source_has_execution_evidence(source, language),
                "execution evidence must retain every original recovery rule: {source}"
            );
        }
    }

    #[test]
    fn incomplete_evidence_is_not_an_absence_proof_560() {
        for (language, source) in [
            (ScriptLanguage::Python, "f('$(date)'"),
            (ScriptLanguage::JavaScript, "edit('$(date)'"),
            (ScriptLanguage::Ruby, "puts '$(date)'"),
        ] {
            assert!(literal_source_has_execution_evidence(source, language));
        }
        let large = format!("#{}", "x".repeat(LITERAL_EVIDENCE_MAX_BYTES));
        assert!(literal_source_has_execution_evidence(
            &large,
            ScriptLanguage::Python
        ));
        let many_nodes = "pass\n".repeat(LITERAL_EVIDENCE_MAX_NODES);
        assert!(literal_source_has_execution_evidence(
            &many_nodes,
            ScriptLanguage::Python
        ));
    }

    #[test]
    fn data_volume_does_not_invent_an_execution_use_560() {
        let source = "text = 'example $(date) with `tool --help`'\n".repeat(160);
        assert!(!literal_source_has_execution_evidence(
            &source,
            ScriptLanguage::Python
        ));
        let with_sink = format!("{source}os.system(text)\n");
        assert!(literal_source_has_execution_evidence(
            &with_sink,
            ScriptLanguage::Python
        ));
    }

    /// A process call whose every argument is a literal without substitution
    /// syntax runs a fixed command line. That is no evidence that another
    /// literal runs, unless the command line can run a file the program
    /// wrote (#560).
    #[test]
    fn closed_process_calls_count_only_when_they_can_run_generated_code_560() {
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import subprocess\nc = subprocess.run(['git', 'show', 'origin/main:F.md'], capture_output=True, text=True, check=True).stdout\nb = \"it's `x`\"",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.check_output(['git', 'diff', '--stat'], cwd='/w')\nb = '`x`'",
            ),
            (
                ScriptLanguage::Python,
                "import re\np = re.compile(r'Some\\(x\\)')\nt = 'Option<(A, B)> `x`'",
            ),
            (
                ScriptLanguage::JavaScript,
                "cp.execSync('git status'); const t = 'it is `x`';",
            ),
        ] {
            assert!(
                !literal_source_has_execution_evidence(source, language),
                "a closed call became evidence: {source}"
            );
            // The capability question keeps every execution name.
            assert!(
                program_may_execute_code(source, language),
                "a process call must still count as a capability: {source}"
            );
        }
        for (language, source) in [
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['sh', 'm.sh'])",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['./m.sh'])",
            ),
            (ScriptLanguage::Python, "import os\nos.system('bash m.sh')"),
            (
                ScriptLanguage::Python,
                "import os\nos.system('git status; ./m.sh')",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['git', '-c', 'core.pager=sh', 'log'])",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['env', 'PATH=.', 'ls'])",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run('make', shell=True)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['git status; sh m.sh'], shell=True)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['ls'], executable='/bin/sh')",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(['echo', '$(date)'])",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nsubprocess.run(args)",
            ),
            (
                ScriptLanguage::Python,
                "import subprocess\nrun = subprocess.run",
            ),
            (
                ScriptLanguage::Python,
                "import os\nos.execv('/bin/git', ['git', 'log'])",
            ),
            (ScriptLanguage::Python, "code = compile('x', 'f', 'exec')"),
            (ScriptLanguage::JavaScript, "cp.execSync('sh m.sh');"),
            (
                ScriptLanguage::JavaScript,
                "cp.spawnSync('git', ['-c', 'alias.x=!sh', 'x']);",
            ),
        ] {
            assert!(
                literal_source_has_execution_evidence(source, language),
                "this call can run what the program wrote: {source}"
            );
        }
    }
}

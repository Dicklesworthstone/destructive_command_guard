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

/// Literal ranges whose shell-looking bytes are only documentation (#544).
///
/// This small proof covers straight-line Python/JavaScript text edits. Every
/// expression must use concrete text/scalar values, known string methods, or
/// the standard print/file APIs below. One opaque call, escaped value, rebound
/// API, or unsupported statement withdraws the proof for the entire program.
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
        Vec::new()
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

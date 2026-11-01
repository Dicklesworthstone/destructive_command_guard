//! Recheck name-based Python cleanup grants at the default policy boundary.
//!
//! A callable named `mkdtemp` is not necessarily the standard-library factory.
//! This positive proof only keeps an existing producer exemption when an
//! immutable, dominating import establishes that identity. It never grants a
//! new exemption, changes literal-path policy, or resolves the host filesystem.

use super::{PatternMatch, ScriptLanguage, Severity};
use ast_grep_core::{AstGrep, Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const TEMP_RULE: &str = "heredoc.python.shutil_rmtree.temp";
const DELETE_RULE: &str = "heredoc.python.shutil_rmtree";
const MAX_SOURCE_BYTES: usize = 256 * 1024;
const MAX_NODES: usize = 40_000;
const MAX_IMPORTS: usize = 256;
const MAX_DEPTH: usize = 128;

type Span = (usize, usize);

fn needs_proof(code: &str, hit: &PatternMatch) -> bool {
    hit.rule_id == TEMP_RULE
        && code.get(hit.start..hit.end).is_some_and(|text| {
            (text.contains("mkdtemp") || text.contains("TemporaryDirectory"))
                && !has_literal_first_target(text)
        })
}

/// Preserve a grant the AST engine already established for a literal target.
/// This is NOT a path-safety check: it is used only after `TEMP_RULE` matched.
/// A factory name in a filename or a later argument must not make that grant
/// depend on another AST parse, the whole-program proof, or its time budget.
///
/// Recognize only a simple callee and a complete constant first target (also
/// `path=`). Reject calls, attributes, subscripts, interpolations and operators
/// other than string concatenation. Unsupported spellings keep the existing
/// bounded AST proof. The byte/depth caps are independent of that proof's
/// optional budget, so exhaustion cannot revoke these already-proved literals.
fn has_literal_first_target(text: &str) -> bool {
    if text.len() > MAX_SOURCE_BYTES {
        return false;
    }
    LiteralTarget {
        bytes: text.as_bytes(),
        cursor: 0,
    }
    .parse()
    .is_some()
}

struct LiteralTarget<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> LiteralTarget<'a> {
    fn space(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.cursor += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.cursor) != Some(&byte) {
            return false;
        }
        self.cursor += 1;
        true
    }

    fn identifier(&mut self) -> Option<&'a [u8]> {
        let start = self.cursor;
        let first = *self.bytes.get(start)?;
        if first != b'_' && !first.is_ascii_alphabetic() {
            return None;
        }
        self.cursor += 1;
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
        {
            self.cursor += 1;
        }
        Some(&self.bytes[start..self.cursor])
    }

    fn string(&mut self) -> Option<()> {
        let mut prefix = [0; 2];
        let mut length = 0;
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(u8::is_ascii_alphabetic)
        {
            *prefix.get_mut(length)? = self.bytes[self.cursor].to_ascii_lowercase();
            length += 1;
            self.cursor += 1;
        }
        // In particular, f-strings and template strings can execute code.
        if !matches!(&prefix[..length], b"" | b"r" | b"u" | b"b" | b"br" | b"rb") {
            return None;
        }
        let quote = *self.bytes.get(self.cursor)?;
        if !matches!(quote, b'\'' | b'"') {
            return None;
        }
        let width = if self
            .bytes
            .get(self.cursor..self.cursor + 3)
            .is_some_and(|bytes| bytes == [quote; 3])
        {
            3
        } else {
            1
        };
        self.cursor += width;
        while let Some(&byte) = self.bytes.get(self.cursor) {
            if self
                .bytes
                .get(self.cursor..self.cursor + width)
                .is_some_and(|end| end.iter().all(|byte| *byte == quote))
            {
                self.cursor += width;
                return Some(());
            }
            if byte == b'\\' {
                self.cursor += 1;
                self.bytes.get(self.cursor)?;
            } else if width == 1 && matches!(byte, b'\n' | b'\r') {
                return None;
            }
            self.cursor += 1;
        }
        None
    }

    /// The callee's opening parenthesis must belong to this WHOLE call, not
    /// `receiver('literal', ...).rmtree(factory())`. Balance the remaining
    /// arguments without evaluating them, declining interpolated strings.
    fn finish_call(&mut self) -> Option<()> {
        let mut depth = 1;
        while let Some(&byte) = self.bytes.get(self.cursor) {
            match byte {
                b'\'' | b'"' => self.string()?,
                b'#' => {
                    while self
                        .bytes
                        .get(self.cursor)
                        .is_some_and(|byte| *byte != b'\n')
                    {
                        self.cursor += 1;
                    }
                }
                b'(' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return None;
                    }
                    self.cursor += 1;
                }
                b')' => {
                    self.cursor += 1;
                    depth -= 1;
                    if depth == 0 {
                        self.space();
                        return (self.cursor == self.bytes.len()).then_some(());
                    }
                }
                _ if byte == b'_' || byte.is_ascii_alphabetic() => {
                    let start = self.cursor;
                    self.identifier()?;
                    if matches!(self.bytes.get(self.cursor), Some(b'\'' | b'"')) {
                        self.cursor = start;
                        self.string()?;
                    }
                }
                _ => self.cursor += 1,
            }
        }
        None
    }

    fn parse(&mut self) -> Option<()> {
        self.space();
        self.identifier()?;
        self.space();
        while self.take(b'.') {
            self.space();
            self.identifier()?;
            self.space();
        }
        if !self.take(b'(') {
            return None;
        }
        self.space();
        let start = self.cursor;
        if self.identifier() == Some(b"path".as_slice()) {
            self.space();
            if !self.take(b'=') {
                self.cursor = start;
            }
        } else {
            self.cursor = start;
        }

        let mut depth = 0;
        let mut operand = true;
        let mut adjacent = false;
        loop {
            self.space();
            if operand {
                if self.take(b'(') {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return None;
                    }
                    continue;
                }
                self.string()?;
                operand = false;
                adjacent = true;
            } else if self.bytes.get(self.cursor) == Some(&b')') {
                if depth == 0 {
                    return self.finish_call();
                }
                self.cursor += 1;
                depth -= 1;
                adjacent = false;
            } else if depth == 0 && self.bytes.get(self.cursor) == Some(&b',') {
                return self.finish_call();
            } else if self.take(b'+') {
                operand = true;
                adjacent = false;
            } else if adjacent {
                self.string()?;
            } else {
                return None;
            }
        }
    }
}

/// Tighten only existing producer grants. All unrelated matches, including
/// every established blocking result, retain their identity and precedence.
pub(super) fn validate(
    code: &str,
    language: ScriptLanguage,
    mut matches: Vec<PatternMatch>,
    budget: Duration,
) -> Vec<PatternMatch> {
    if language != ScriptLanguage::Python {
        return matches;
    }
    // Keep the exact candidate indices as well as their deduplicated spans.
    // The proof does not resize matches, so applying the result needs neither
    // another fragment scan nor a clone of the candidate set. Preserve the
    // literal-target exclusions and duplicate-span findings independently.
    let mut candidate_indices = Vec::new();
    let mut candidates = HashSet::new();
    for (index, hit) in matches.iter().enumerate() {
        if needs_proof(code, hit) {
            candidate_indices.push(index);
            candidates.insert((hit.start, hit.end));
        }
    }
    if candidates.is_empty() {
        return matches;
    }
    let proved = prove_bounded(code, candidates, budget).unwrap_or_default();
    for index in candidate_indices {
        let hit = &mut matches[index];
        if !proved.contains(&(hit.start, hit.end)) {
            // Restore the registered recursive-deletion rule, not a novel rule
            // that could bypass an existing per-rule policy or allowlist.
            hit.rule_id = DELETE_RULE.to_string();
            hit.reason = "shutil.rmtree() target is not a proven temporary directory".to_string();
            hit.severity = Severity::Critical;
            hit.suggestion = Some(
                "Use a literal temporary descendant or an unmodified tempfile factory".to_string(),
            );
        }
    }
    matches
}

fn prove_bounded(code: &str, candidates: HashSet<Span>, budget: Duration) -> Option<HashSet<Span>> {
    if budget.is_zero() || code.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let started = Instant::now();
    let source = code.to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let (sender, receiver) = mpsc::sync_channel(1);
    let profile = crate::perf::capture_profile();
    let _worker = thread::Builder::new()
        .name("dcg-tempfile-proof".to_string())
        .spawn(move || {
            let _profile = profile.enter();
            let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstMatch);
            let result = prove(&source, &candidates, started, budget, &worker_cancel);
            let _ = sender.send(result);
        })
        .ok()?;
    let result = budget
        .checked_sub(started.elapsed())
        .and_then(|remaining| receiver.recv_timeout(remaining).ok())
        .flatten();
    // A late success is not proof within the caller's time envelope.
    cancel.store(true, Ordering::Relaxed);
    if started.elapsed() > budget {
        None
    } else {
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportKind {
    Module,
    Mkdtemp,
    TemporaryDirectory,
    // tempfile shares os/path module objects with other imports. Replacing
    // os.path.abspath can make the real mkdtemp return an existing root.
    // These handles may veto a factory grant, but never establish one.
    DependencyModule,
    DependencyCarrier,
}

struct Import {
    name: String,
    kind: ImportKind,
    statement: Range<usize>,
    container: Range<usize>,
}

#[derive(Default)]
struct Proof {
    imports: Vec<Import>,
}

fn prove(
    code: &str,
    candidates: &HashSet<Span>,
    started: Instant,
    budget: Duration,
    cancel: &AtomicBool,
) -> Option<HashSet<Span>> {
    prove_with_binding_index::<true>(code, candidates, started, budget, cancel)
}

// The false specialization retains the two-walk incumbent for in-module
// differential tests and paired benchmarks. Runtime callers always use true;
// the compiler removes the unused strategy, not any security predicate.
#[allow(clippy::too_many_lines)] // Keep import collection and binding validation together.
fn prove_with_binding_index<const INDEX_BINDINGS: bool>(
    code: &str,
    candidates: &HashSet<Span>,
    started: Instant,
    budget: Duration,
    cancel: &AtomicBool,
) -> Option<HashSet<Span>> {
    if code.len() > MAX_SOURCE_BYTES || budget.is_zero() {
        return None;
    }
    let check = |index: usize| {
        index < MAX_NODES && !cancel.load(Ordering::Relaxed) && started.elapsed() <= budget
    };
    let ast = {
        let _phase = crate::perf::phase(crate::perf::ProfilePhase::AstParse);
        AstGrep::try_new(code, SupportLang::Python).ok()?
    };
    let root = ast.root();
    let mut proof = Proof::default();
    let mut declarations: HashMap<String, Option<ImportKind>> = HashMap::new();
    let mut handles = HashSet::new();
    let mut import_ranges = Vec::new();
    let mut calls = Vec::new();
    let mut binding_uses = Vec::new();
    let mut immutable = true;

    for (index, node) in root.dfs().enumerate() {
        if !check(index) || node.is_error() || node.is_missing() {
            return None;
        }
        // CPython normalizes names with NFKC. Do not mistake a differently
        // spelled identifier for proof that a trusted binding is untouched.
        if node.kind() == "identifier" && !node.text().is_ascii() {
            immutable = false;
        }
        // Only these kinds can affect reflects_bindings/read_only_use. Retain
        // all of them, even before the first trusted import: a later import
        // can identify an earlier alias or write as relevant. Original DFS
        // indices preserve node-limit accounting; the complete first walk
        // still validates every node, including syntax errors and missing nodes.
        if INDEX_BINDINGS && immutable && matches!(node.kind().as_ref(), "identifier" | "attribute")
        {
            binding_uses.push((index, node.clone()));
        }
        let range = node.range();
        if node.kind() == "call" && candidates.contains(&(range.start, range.end)) {
            calls.push(node.clone());
        }
        if !matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        ) {
            continue;
        }
        if node
            .children()
            .any(|child| child.kind() == "wildcard_import")
        {
            immutable = false;
        }
        let module = node
            .field("module_name")
            .map(|name| name.text().into_owned());
        import_ranges.push(range.clone());
        for imported in node.field_children("name") {
            if declarations.len() >= MAX_IMPORTS || proof.imports.len() >= MAX_IMPORTS {
                immutable = false;
                break;
            }
            let source = imported
                .field("name")
                .unwrap_or_else(|| imported.clone())
                .text()
                .into_owned();
            if module.as_deref() == Some("builtins") && reflective_name(&source)
                || module.as_deref() == Some("sys") && source == "modules"
            {
                immutable = false;
            }
            let name = imported.field("alias").map_or_else(
                || {
                    if module.is_none() {
                        source.split('.').next().unwrap_or(&source).to_string()
                    } else {
                        source.clone()
                    }
                },
                |alias| alias.text().into_owned(),
            );
            let kind = match (module.as_deref(), source.as_str()) {
                (None, "tempfile") => Some(ImportKind::Module),
                (Some("tempfile"), "mkdtemp") => Some(ImportKind::Mkdtemp),
                (Some("tempfile"), "TemporaryDirectory") => Some(ImportKind::TemporaryDirectory),
                (None, "os" | "os.path" | "posixpath" | "ntpath" | "genericpath")
                | (Some("os"), "path")
                | (
                    Some(
                        "os.path" | "posixpath" | "ntpath" | "genericpath" | "shutil" | "pathlib"
                        | "pathlib._local",
                    ),
                    "os" | "genericpath",
                )
                | (Some("tempfile"), "_os") => Some(ImportKind::DependencyModule),
                (None, "shutil" | "pathlib" | "pathlib._local") | (Some("tempfile"), "_shutil") => {
                    Some(ImportKind::DependencyCarrier)
                }
                _ => None,
            };
            declarations
                .entry(name.clone())
                .and_modify(|existing| {
                    if *existing != kind {
                        *existing = None;
                    }
                })
                .or_insert(kind);
            if let Some(kind) = kind {
                handles.insert(name.clone());
                if let Some(container) = node.parent() {
                    proof.imports.push(Import {
                        name,
                        kind,
                        statement: range.clone(),
                        container: container.range(),
                    });
                }
            }
        }
    }
    proof
        .imports
        .retain(|import| declarations.get(&import.name) == Some(&Some(import.kind)));
    import_ranges.sort_unstable_by_key(|range| range.start);
    if immutable && !proof.imports.is_empty() {
        immutable = if INDEX_BINDINGS {
            bindings_are_immutable(
                binding_uses.into_iter(),
                &declarations,
                &handles,
                &import_ranges,
                &check,
            )?
        } else {
            bindings_are_immutable(
                root.dfs().enumerate(),
                &declarations,
                &handles,
                &import_ranges,
                &check,
            )?
        };
    }
    let mut proved = HashSet::new();
    for call in calls {
        if !check(0) {
            return None;
        }
        let Some(target) = deletion_target(&call) else {
            continue;
        };
        // This is an existing .temp match. A complete static literal has
        // already passed the engine's descendant/traversal check. Factory
        // names inside a literal filename do not change that established grant.
        if literal_target(&target, 0) || immutable && proof.directory(&target) {
            let range = call.range();
            proved.insert((range.start, range.end));
        }
    }
    Some(proved)
}

fn bindings_are_immutable<'a, D: Doc + 'a>(
    nodes: impl Iterator<Item = (usize, Node<'a, D>)>,
    declarations: &HashMap<String, Option<ImportKind>>,
    handles: &HashSet<String>,
    import_ranges: &[Range<usize>],
    check: &impl Fn(usize) -> bool,
) -> Option<bool> {
    for (index, node) in nodes {
        if !check(index) {
            return None;
        }
        let range = node.range();
        let before = import_ranges.partition_point(|import| import.start <= range.start);
        if before > 0 && range.end <= import_ranges[before - 1].end {
            continue;
        }
        if reflects_bindings(&node) {
            return Some(false);
        }
        if node.kind() == "identifier" && handles.contains(node.text().as_ref()) {
            let kind = declarations.get(node.text().as_ref()).copied().flatten();
            if !kind.is_some_and(|kind| read_only_use(&node, kind)) {
                return Some(false);
            }
        }
    }
    Some(true)
}

fn reflective_name(name: &str) -> bool {
    matches!(
        name,
        "exec"
            | "eval"
            | "getattr"
            | "setattr"
            | "delattr"
            | "vars"
            | "globals"
            | "locals"
            | "__builtins__"
            | "__import__"
            | "__setattr__"
            | "__delattr__"
            | "__getattribute__"
            | "import_module"
    )
}

fn reflects_bindings<D: Doc>(node: &Node<'_, D>) -> bool {
    // A reference can be captured and invoked under a different name later.
    // Merely checking direct exec/eval calls would miss that mutation route.
    if node.kind() == "identifier" && reflective_name(node.text().as_ref()) {
        return true;
    }
    node.kind() == "attribute"
        && node.field("attribute").is_some_and(|name| {
            reflective_name(name.text().as_ref())
                || matches!(
                    name.text().as_ref(),
                    "__dict__"
                        | "__code__"
                        | "__globals__"
                        | "__defaults__"
                        | "__kwdefaults__"
                        | "modules"
                )
        })
}

// These path bytes already passed the engine's descendant check. Preserve the
// existing grant only for a whole constant expression, never for a literal
// inside a call, attribute, or interpolation. No new path allowance is derived.
fn literal_target<D: Doc>(node: &Node<'_, D>, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    match node.kind().as_ref() {
        "string" => !node.dfs().any(|child| child.kind() == "interpolation"),
        "concatenated_string" => node
            .children()
            .filter(|child| child.is_named() && child.kind() != "comment")
            .all(|child| literal_target(&child, depth + 1)),
        "binary_operator" => {
            node.field("operator")
                .is_some_and(|operator| operator.text() == "+")
                && node
                    .field("left")
                    .is_some_and(|left| literal_target(&left, depth + 1))
                && node
                    .field("right")
                    .is_some_and(|right| literal_target(&right, depth + 1))
        }
        _ => false,
    }
}

fn read_only_use<D: Doc>(name: &Node<'_, D>, kind: ImportKind) -> bool {
    if kind == ImportKind::DependencyModule {
        return dependency_read_only_use(name);
    }
    let Some(parent) = name.parent() else {
        return false;
    };
    if kind == ImportKind::DependencyCarrier {
        // shutil/pathlib can expose the same os module. Their other members
        // are not tempfile dependencies: capturing shutil.rmtree as a local
        // deletion alias must retain its established cleanup policy.
        return parent.kind() == "attribute"
            && parent
                .field("object")
                .is_some_and(|object| object.range() == name.range())
            && parent.field("attribute").is_some_and(|attribute| {
                let member = attribute.text();
                !member.starts_with("__")
                    && (!matches!(
                        member.as_ref(),
                        "os" | "_os" | "posixpath" | "ntpath" | "genericpath" | "_local"
                    ) || dependency_read_only_use(name))
            });
    }
    if kind != ImportKind::Module {
        return parent.kind() == "call"
            && parent
                .field("function")
                .is_some_and(|function| function.range() == name.range());
    }
    if parent.kind() != "attribute"
        || !parent
            .field("object")
            .is_some_and(|object| object.range() == name.range())
        || !parent.field("attribute").is_some_and(|attribute| {
            matches!(
                attribute.text().as_ref(),
                "mkdtemp"
                    | "TemporaryDirectory"
                    | "mkstemp"
                    | "TemporaryFile"
                    | "NamedTemporaryFile"
                    | "SpooledTemporaryFile"
                    | "gettempdir"
                    | "gettempdirb"
                    | "gettempprefix"
                    | "gettempprefixb"
            )
        })
    {
        return false;
    }
    parent.parent().is_some_and(|call| {
        call.kind() == "call"
            && call
                .field("function")
                .is_some_and(|function| function.range() == parent.range())
    })
}

/// A shared dependency may be called, not replaced or handed to unknown code.
/// Follow the whole attribute chain: checking only `os.path` would mistake
/// `os.path.abspath = ...` and `shutil.os.path.abspath = ...` for reads.
/// The whole-body pass also catches a write after the call in a loop, or a
/// write through a second import of the same module. No host imports run here.
fn dependency_read_only_use<D: Doc>(name: &Node<'_, D>) -> bool {
    let mut value = name.clone();
    for _ in 0..MAX_DEPTH {
        let Some(parent) = value.parent() else {
            return false;
        };
        if parent.kind() == "attribute"
            && parent
                .field("object")
                .is_some_and(|object| object.range() == value.range())
        {
            let Some(attribute) = parent.field("attribute") else {
                return false;
            };
            if attribute.text().starts_with("__") {
                return false;
            }
            value = parent;
            continue;
        }
        if parent.kind() == "parenthesized_expression" {
            value = parent;
            continue;
        }
        if parent.kind() == "call" {
            return parent
                .field("function")
                .is_some_and(|function| function.range() == value.range());
        }
        // Known immutable module constants can be read without exposing a
        // module or callable. Preserve ordinary os.name checks and path
        // separators, but not writes, deletes, or ambiguous binding positions.
        let scalar = value.kind() == "attribute"
            && value.field("attribute").is_some_and(|attribute| {
                matches!(
                    attribute.text().as_ref(),
                    "name"
                        | "sep"
                        | "altsep"
                        | "curdir"
                        | "pardir"
                        | "pathsep"
                        | "defpath"
                        | "extsep"
                        | "devnull"
                )
            });
        return scalar
            && (matches!(
                parent.kind().as_ref(),
                "argument_list"
                    | "keyword_argument"
                    | "comparison_operator"
                    | "binary_operator"
                    | "return_statement"
                    | "expression_statement"
            ) || parent.kind() == "assignment"
                && parent
                    .field("right")
                    .is_some_and(|right| right.range() == value.range()));
    }
    false
}

fn deletion_target<'a, D: Doc>(call: &Node<'a, D>) -> Option<Node<'a, D>> {
    let arguments = call.field("arguments")?;
    let mut target = None;
    let mut positional = false;
    for argument in arguments
        .children()
        .filter(|node| node.is_named() && node.kind() != "comment")
    {
        match argument.kind().as_ref() {
            "list_splat" | "dictionary_splat" => return None,
            "keyword_argument" => {
                if argument
                    .field("name")
                    .is_some_and(|name| name.text() == "path")
                {
                    if target.is_some() {
                        return None;
                    }
                    target = argument.field("value");
                }
            }
            _ if !positional => {
                if target.is_some() {
                    return None;
                }
                positional = true;
                target = Some(argument);
            }
            _ => {}
        }
    }
    let mut target = target?;
    for _ in 0..MAX_DEPTH {
        if target.kind() != "parenthesized_expression" {
            return Some(target);
        }
        target = {
            let mut children = target
                .children()
                .filter(|node| node.is_named() && node.kind() != "comment");
            let inner = children.next()?;
            if children.next().is_some() {
                return None;
            }
            inner
        };
    }
    None
}

impl Proof {
    fn directory<D: Doc>(&self, target: &Node<'_, D>) -> bool {
        let (call, takes_name) = if target.kind() == "attribute"
            && target
                .field("attribute")
                .is_some_and(|name| name.text() == "name")
        {
            let Some(object) = target.field("object") else {
                return false;
            };
            (object, true)
        } else {
            (target.clone(), false)
        };
        if call.kind() != "call" {
            return false;
        }
        let Some(function) = call.field("function") else {
            return false;
        };
        match self.factory(&function) {
            Some(ImportKind::TemporaryDirectory) => true,
            Some(ImportKind::Mkdtemp) => !takes_name,
            _ => false,
        }
    }

    fn factory<D: Doc>(&self, function: &Node<'_, D>) -> Option<ImportKind> {
        let (name, member) = match function.kind().as_ref() {
            "identifier" => (function.clone(), None),
            "attribute" => {
                let object = function.field("object")?;
                if object.kind() != "identifier" {
                    return None;
                }
                (
                    object,
                    Some(function.field("attribute")?.text().into_owned()),
                )
            }
            _ => return None,
        };
        for imported in &self.imports {
            if imported.name.as_str() != name.text().as_ref()
                || imported.statement.end > function.range().start
            {
                continue;
            }
            let kind = match (imported.kind, member.as_deref()) {
                (ImportKind::Module, Some("mkdtemp")) | (ImportKind::Mkdtemp, None) => {
                    ImportKind::Mkdtemp
                }
                (ImportKind::Module, Some("TemporaryDirectory"))
                | (ImportKind::TemporaryDirectory, None) => ImportKind::TemporaryDirectory,
                _ => continue,
            };
            let mut ancestor = function.parent();
            for _ in 0..MAX_DEPTH {
                let Some(node) = ancestor else {
                    break;
                };
                if node.kind() == "class_definition" {
                    break;
                }
                if node.range() == imported.container {
                    if node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "class_definition")
                    {
                        break;
                    }
                    return Some(kind);
                }
                ancestor = node.parent();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Case {
        id: String,
        decision: String,
        source: String,
        #[serde(default)]
        analysis_error: Option<String>,
    }

    fn checked_case_matches(
        case: &Case,
        result: Result<Vec<PatternMatch>, super::super::MatchError>,
    ) -> Option<Vec<PatternMatch>> {
        if let Some(expected) = &case.analysis_error {
            assert_eq!(
                case.decision, "deny",
                "{}: incomplete work cannot allow",
                case.id
            );
            match result {
                Err(super::super::MatchError::Unavailable { language, detail }) => {
                    assert_eq!(language, ScriptLanguage::Python, "{}", case.id);
                    assert_eq!(&detail, expected, "{}", case.id);
                }
                other => panic!(
                    "{}: expected explicit incomplete analysis, got {other:?}",
                    case.id
                ),
            }
            // CLI/hook fixtures separately require a blocking wire verdict.
            // Incomplete analysis supplies no completed proof candidates.
            None
        } else {
            Some(result.unwrap_or_else(|error| panic!("{}: {error:?}", case.id)))
        }
    }

    #[test]
    fn literal_target_recognizer_never_borrows_nested_literals() {
        for target in [
            "mkdtemp()",
            "tempfile.mkdtemp()",
            "tempfile.TemporaryDirectory().name",
            "Path('/tmp/mkdtemp-cache').parent",
            "'/tmp/mkdtemp-cache'[:-1]",
            "'/tmp/mkdtemp-cache'.replace('cache', '..')",
            "('/tmp/mkdtemp-cache',)[0]",
            "('/tmp/mkdtemp-cache',)",
            "'/tmp/mkdtemp-cache' + suffix",
            "prefix + '/tmp/mkdtemp-cache'",
            "'/tmp/mkdtemp-cache' if ready else '/tmp'",
            "'/tmp/mkdtemp-cache' and '/tmp'",
            "f'/tmp/{mkdtemp()}'",
            "rf'/tmp/{mkdtemp()}'",
            "f'/tmp/mkdtemp-cache'",
            "t'/tmp/{mkdtemp()}'",
            "*['/tmp/mkdtemp-cache']",
            "**{'path': '/tmp/mkdtemp-cache'}",
            "(lambda: '/tmp/mkdtemp-cache')()",
            "('/tmp/mkdtemp-cache')('/tmp')",
            "'/tmp/mkdtemp-cache'('/tmp')",
            "('/tmp/mkdtemp-cache'",
            "'/tmp/mkdtemp-cache",
            "'/tmp/mkdtemp-cache' +",
        ] {
            for prefix in ["", "path="] {
                let source = format!("shutil.rmtree({prefix}{target})");
                assert!(
                    !has_literal_first_target(&source),
                    "only a complete constant target can skip the factory proof: {source}"
                );
            }
        }
        for source in [
            "receiver('/tmp/mkdtemp-cache').rmtree(tempfile.mkdtemp())",
            "receiver('/tmp/mkdtemp-cache', ready=True).rmtree(tempfile.mkdtemp())",
            "receiver('/tmp/mkdtemp-cache', onerror=lambda: '(text)').rmtree(mkdtemp())",
            "receiver(path='/tmp/mkdtemp-cache').rmtree(mkdtemp())",
            "shutil.rmtree(ignore_errors=True, path=tempfile.mkdtemp())",
            "shutil.rmtree(path=tempfile.mkdtemp(), onerror='/tmp/mkdtemp-cache')",
            "shutil.rmtree('/tmp/mkdtemp-cache', onerror=f'{callback()}')",
        ] {
            assert!(!has_literal_first_target(source), "{source}");
        }
        let nested = format!(
            "shutil.rmtree({}'/tmp/mkdtemp-cache'{})",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1),
        );
        assert!(!has_literal_first_target(&nested));
        assert!(!has_literal_first_target(&" ".repeat(MAX_SOURCE_BYTES + 1)));
    }

    #[test]
    fn exhausted_factory_proof_preserves_constant_cleanup_targets() {
        for target in [
            "'/tmp/mkdtemp-cache'",
            "\"/tmp/TemporaryDirectory-cache\"",
            "r'/tmp/mkdtemp-cache'",
            "u'/tmp/mkdtemp-cache'",
            "b'/tmp/mkdtemp-cache'",
            "br'/tmp/mkdtemp-cache'",
            "RB'/tmp/mkdtemp-cache'",
            "'''/tmp/mkdtemp-cache'''",
            "\"\"\"/tmp/TemporaryDirectory-cache\"\"\"",
            "('/tmp/mkdtemp-cache')",
            "(('/tmp/mkdtemp-cache'))",
            "'/tmp/' 'mkdtemp-cache'",
            "'/tmp/' + 'mkdtemp-cache'",
            "('/tmp/' + 'mkdtemp-cache')",
            "'/tmp/' + ('mkdtemp-cache')",
            "('/tmp/') + 'mkdtemp-cache'",
            "'/tmp/' + ('mkdtemp-' 'cache')",
            "'/private/./var//tmp/TemporaryDirectory-cache/.'",
        ] {
            for prefix in ["", "path="] {
                let source = format!("import shutil\nshutil.rmtree({prefix}{target})");
                let original = super::super::source_analysis::DEFAULT_MATCHER
                    .find_matches_with_timeout(
                        &source,
                        ScriptLanguage::Python,
                        Duration::from_secs(5),
                    )
                    .expect("the original AST path policy must complete");
                // Do not broaden path policy for spellings the engine itself
                // does not exempt. The independent proof cannot change their
                // verdict in either direction, even with no remaining time.
                let denied = original.iter().any(|hit| hit.severity.blocks_by_default());
                let actual = validate(&source, ScriptLanguage::Python, original, Duration::ZERO);
                assert_eq!(
                    actual.iter().any(|hit| hit.severity.blocks_by_default()),
                    denied,
                    "factory analysis must not change a constant-target verdict: {source}",
                );
                assert!(has_literal_first_target(&format!(
                    "shutil.rmtree({prefix}{target})"
                )));
            }
        }
    }

    #[test]
    fn factory_proof_exhaustion_does_not_weaken_other_matches() {
        let source = "import shutil, tempfile\nshutil.rmtree('/tmp/mkdtemp-cache')\nshutil.rmtree(tempfile.mkdtemp())\nshutil.rmtree('/tmp')";
        let original = super::super::source_analysis::DEFAULT_MATCHER
            .find_matches_with_timeout(source, ScriptLanguage::Python, Duration::from_secs(5))
            .expect("complete initial AST matches");
        let actual = validate(source, ScriptLanguage::Python, original, Duration::ZERO);
        for (call, denied) in [
            ("shutil.rmtree('/tmp/mkdtemp-cache')", false),
            ("shutil.rmtree(tempfile.mkdtemp())", true),
            ("shutil.rmtree('/tmp')", true),
        ] {
            let start = source
                .find(call)
                .expect("fixture contains each complete call");
            assert_eq!(
                actual
                    .iter()
                    .any(|hit| hit.start == start && hit.severity.blocks_by_default()),
                denied,
                "each deletion keeps its own proof requirement: {call}",
            );
        }
    }

    #[test]
    fn default_policy_tempfile_provenance_verdicts() {
        let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/python_tempfile_provenance.json"
        )))
        .expect("valid shared verdict fixtures");
        assert!(!cases.is_empty());
        for case in cases {
            let result = super::super::DEFAULT_MATCHER.find_matches_with_timeout(
                &case.source,
                ScriptLanguage::Python,
                Duration::from_secs(5),
            );
            let Some(matches) = checked_case_matches(&case, result) else {
                continue;
            };
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
    fn exhausted_proof_withholds_only_candidate_exemptions() {
        for (source, denied) in [
            (
                "import shutil, tempfile\nshutil.rmtree(tempfile.mkdtemp())",
                true,
            ),
            ("import shutil\nshutil.rmtree('/tmp/build')", false),
            ("import shutil\nshutil.rmtree('/tmp/mkdtemp-cache')", false),
            (
                "import shutil\nshutil.rmtree('/tmp/TemporaryDirectory-cache')",
                false,
            ),
            (
                "import shutil\nshutil.rmtree('/tmp/' + 'mkdtemp-cache')",
                false,
            ),
            (
                "import shutil\nshutil.rmtree(path='/tmp/mkdtemp-cache')",
                false,
            ),
            (
                "from shutil import rmtree as wipe\nwipe('/tmp/mkdtemp-cache')",
                false,
            ),
            (
                "import shutil\nshutil.rmtree('/tmp/cache', onerror=mkdtemp)",
                false,
            ),
            (
                "import shutil\nshutil.rmtree('/tmp/cache', onerror=lambda *args: mkdtemp())",
                false,
            ),
            ("import shutil\nshutil.rmtree('/tmp/.')", true),
            (
                "import shutil\nshutil.rmtree('/tmp/mkdtemp-cache/..')",
                true,
            ),
            (
                "import shutil\nshutil.rmtree('/tmp/mkdtemp-cache/../../etc')",
                true,
            ),
            (
                "import shutil\nshutil.rmtree(Path('/tmp/mkdtemp-cache').parent)",
                true,
            ),
            ("import shutil\nshutil.rmtree(path=mkdtemp())", true),
            ("import shutil\nshutil.rmtree('/tmp')", true),
        ] {
            let original = super::super::source_analysis::DEFAULT_MATCHER
                .find_matches_with_timeout(source, ScriptLanguage::Python, Duration::from_secs(5))
                .expect("complete source classification before withholding the optional proof");
            let matches = validate(source, ScriptLanguage::Python, original, Duration::ZERO);
            assert_eq!(
                matches.iter().any(|hit| hit.severity.blocks_by_default()),
                denied,
                "{source}",
            );
        }
    }

    #[test]
    fn deterministic_proof_limits_never_establish_safety() {
        let source = "x=0\n".repeat(MAX_NODES / 2 + 1);
        assert!(source.len() < MAX_SOURCE_BYTES);
        assert!(
            prove(
                &source,
                &HashSet::new(),
                Instant::now(),
                Duration::from_secs(60),
                &AtomicBool::new(false),
            )
            .is_none()
        );
        assert!(
            prove_bounded(
                &" ".repeat(MAX_SOURCE_BYTES + 1),
                HashSet::new(),
                Duration::from_secs(5),
            )
            .is_none()
        );
        assert!(
            prove(
                "import tempfile",
                &HashSet::new(),
                Instant::now(),
                Duration::from_secs(5),
                &AtomicBool::new(true),
            )
            .is_none()
        );
    }

    fn candidate_spans(source: &str) -> HashSet<Span> {
        super::super::source_analysis::DEFAULT_MATCHER
            .find_matches_with_timeout(source, ScriptLanguage::Python, Duration::from_secs(60))
            .expect("complete source classification for the proof comparison")
            .iter()
            .filter(|hit| needs_proof(source, hit))
            .map(|hit| (hit.start, hit.end))
            .collect()
    }

    fn compare_proof_strategies(source: &str, candidates: &HashSet<Span>) {
        let cancelled = AtomicBool::new(false);
        let budget = Duration::from_secs(60);
        let incumbent = prove_with_binding_index::<false>(
            source,
            candidates,
            Instant::now(),
            budget,
            &cancelled,
        );
        let indexed = prove(source, candidates, Instant::now(), budget, &cancelled);
        assert_eq!(indexed, incumbent, "{source}");
    }

    #[test]
    fn indexed_binding_proof_matches_two_walk_incumbent() {
        let cases: Vec<Case> = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/python_tempfile_provenance.json"
        )))
        .expect("valid shared verdict fixtures");
        let mut compared_candidates = 0;
        for case in cases {
            let result = super::super::source_analysis::DEFAULT_MATCHER.find_matches_with_timeout(
                &case.source,
                ScriptLanguage::Python,
                Duration::from_secs(60),
            );
            let Some(matches) = checked_case_matches(&case, result) else {
                continue;
            };
            let candidates: HashSet<_> = matches
                .iter()
                .filter(|hit| needs_proof(&case.source, hit))
                .map(|hit| (hit.start, hit.end))
                .collect();
            compared_candidates += candidates.len();
            compare_proof_strategies(&case.source, &candidates);
        }
        assert!(
            compared_candidates > 0,
            "the differential proof must not be vacuous"
        );
        for lines in [1, 40, 300] {
            let source = format!(
                "import shutil, tempfile\n{}shutil.rmtree(tempfile.mkdtemp())\n",
                "value = (1, 2, 3, 'quoted os.path.abspath = unsafe')\n".repeat(lines),
            );
            let candidates = candidate_spans(&source);
            assert!(!candidates.is_empty());
            compare_proof_strategies(&source, &candidates);
            let proved = prove(
                &source,
                &candidates,
                Instant::now(),
                Duration::from_secs(60),
                &AtomicBool::new(false),
            )
            .expect("complete bounded proof");
            assert_eq!(
                proved, candidates,
                "literal data must not poison a real factory"
            );
        }
    }

    #[test]
    fn binding_index_keeps_uses_before_imports_and_after_cleanup() {
        for source in [
            "def poison():\n    os.path.abspath = lambda path: '/etc'\nimport os, shutil, tempfile\npoison()\nshutil.rmtree(tempfile.mkdtemp())\n",
            "import os, shutil, tempfile\nfor step in range(2):\n    shutil.rmtree(tempfile.mkdtemp())\n    os.path.abspath = lambda path: '/etc'\n",
            "reflect = globals\nimport shutil, tempfile\nshutil.rmtree(tempfile.mkdtemp())\n",
        ] {
            let candidates = candidate_spans(source);
            // Exercise the proof directly even when another source-analysis
            // backstop has already withheld the preliminary .temp exemption.
            let ast = AstGrep::try_new(source, SupportLang::Python).expect("valid Python fixture");
            let cleanup_calls: HashSet<_> = ast
                .root()
                .dfs()
                .filter(|node| {
                    node.kind() == "call"
                        && node
                            .field("function")
                            .is_some_and(|callee| callee.text() == "shutil.rmtree")
                })
                .map(|node| {
                    let range = node.range();
                    (range.start, range.end)
                })
                .collect();
            assert!(!cleanup_calls.is_empty());
            compare_proof_strategies(source, &candidates);
            compare_proof_strategies(source, &cleanup_calls);
            let proved = prove(
                source,
                &cleanup_calls,
                Instant::now(),
                Duration::from_secs(60),
                &AtomicBool::new(false),
            )
            .expect("complete negative proof");
            assert!(
                proved.is_empty(),
                "a shared or reflective mutation must withhold the grant"
            );
        }
    }

    #[test]
    fn indexed_validation_preserves_duplicate_spans_and_unrelated_hits() {
        let source = "mkdtemp";
        let candidate = PatternMatch {
            rule_id: TEMP_RULE.to_string(),
            reason: "preliminary producer exemption".to_string(),
            matched_text_preview: source.to_string(),
            start: 0,
            end: source.len(),
            line_number: 1,
            severity: Severity::Medium,
            suggestion: None,
        };
        let mut unrelated = candidate.clone();
        unrelated.rule_id = "heredoc.python.other".to_string();
        unrelated.severity = Severity::High;
        let mut not_a_candidate = candidate.clone();
        not_a_candidate.end = 0;
        let original = vec![
            unrelated.clone(),
            candidate.clone(),
            not_a_candidate.clone(),
            candidate,
        ];
        assert_eq!(
            validate(
                source,
                ScriptLanguage::Bash,
                original.clone(),
                Duration::ZERO
            ),
            original,
        );
        let result = validate(source, ScriptLanguage::Python, original, Duration::ZERO);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], unrelated);
        assert_eq!(result[2], not_a_candidate);
        for index in [1, 3] {
            assert_eq!(result[index].rule_id, DELETE_RULE);
            assert_eq!(result[index].severity, Severity::Critical);
            assert_eq!(result[index].start, 0);
            assert_eq!(result[index].end, source.len());
        }
        assert_eq!(result[1], result[3]);
    }

    #[test]
    fn indexed_proof_retains_incomplete_analysis_refusal() {
        let oversized = " ".repeat(MAX_SOURCE_BYTES + 1);
        let too_many_nodes = "value = 0\n".repeat(MAX_NODES / 2 + 1);
        assert!(too_many_nodes.len() < MAX_SOURCE_BYTES);
        for (source, budget, cancelled) in [
            ("import tempfile", Duration::ZERO, false),
            ("import tempfile", Duration::from_secs(60), true),
            (oversized.as_str(), Duration::from_secs(60), false),
            (too_many_nodes.as_str(), Duration::from_secs(60), false),
            ("import tempfile\nvalue = (", Duration::from_secs(60), false),
        ] {
            let candidates = HashSet::new();
            let cancel = AtomicBool::new(cancelled);
            let incumbent = prove_with_binding_index::<false>(
                source,
                &candidates,
                Instant::now(),
                budget,
                &cancel,
            );
            let indexed = prove(source, &candidates, Instant::now(), budget, &cancel);
            assert!(incumbent.is_none(), "incumbent accepted incomplete input");
            assert!(indexed.is_none(), "index accepted incomplete input");
        }
    }

    /// Component-only comparison: each sample parses the same source afresh.
    /// Includes index construction and its allocation; excludes fixture setup,
    /// candidate discovery, and result comparison equally for both strategies.
    /// Does not measure worker spawning, fresh hook processes, or history I/O.
    #[test]
    #[ignore = "paired component benchmark; run in release mode without competing builds"]
    #[allow(clippy::too_many_lines)] // Keep the paired setup, verification, and raw samples together.
    fn paired_tempfile_binding_index_benchmark() {
        use std::hint::black_box;

        const RUNS: usize = 50;
        const WARMUP: usize = 5;
        for (shape, body) in [
            ("small", "value = (1, 2, 3)\n".to_string()),
            (
                "literal_heavy_40",
                "value = (1, 2, 3, 'os.path.abspath = unsafe')\n".repeat(40),
            ),
            (
                "literal_heavy_300",
                "value = (1, 2, 3, 'os.path.abspath = unsafe')\n".repeat(300),
            ),
            (
                "binding_dense_300",
                "value = max(min(left, right), abs(other))\n".repeat(300),
            ),
        ] {
            let source =
                format!("import shutil, tempfile\n{body}shutil.rmtree(tempfile.mkdtemp())\n");
            let candidates = candidate_spans(&source);
            assert!(!candidates.is_empty());
            let cancelled = AtomicBool::new(false);
            let mut old_samples = Vec::with_capacity(RUNS);
            let mut indexed_samples = Vec::with_capacity(RUNS);
            for pair in 0..RUNS + WARMUP {
                let mut results = Vec::with_capacity(2);
                for indexed in [pair % 2 == 0, pair % 2 != 0] {
                    let started = Instant::now();
                    let result = if indexed {
                        prove(
                            black_box(&source),
                            black_box(&candidates),
                            started,
                            Duration::from_secs(60),
                            &cancelled,
                        )
                    } else {
                        prove_with_binding_index::<false>(
                            black_box(&source),
                            black_box(&candidates),
                            started,
                            Duration::from_secs(60),
                            &cancelled,
                        )
                    };
                    let elapsed = started.elapsed().as_nanos();
                    if pair >= WARMUP {
                        if indexed {
                            indexed_samples.push(elapsed);
                        } else {
                            old_samples.push(elapsed);
                        }
                    }
                    results.push(black_box(result));
                }
                assert_eq!(results[0], results[1], "{shape}");
                assert_eq!(results[0].as_ref(), Some(&candidates), "{shape}");
            }
            let median = |samples: &[u128]| {
                let mut sorted = samples.to_vec();
                sorted.sort_unstable();
                sorted[sorted.len() / 2]
            };
            println!(
                "{}",
                serde_json::json!({
                    "kind": "paired_tempfile_binding_index",
                    "scope": "in_process_ast_proof",
                    "reference_source_blob": "53ec6cbc0fa35a333197a706ac42d5968cb97141",
                    "baseline": "two_walk_strategy_shared_semantic_checks",
                    "shape": shape,
                    "source_bytes": source.len(),
                    "runs": RUNS,
                    "warmup": WARMUP,
                    "old_median_ns": median(&old_samples),
                    "indexed_median_ns": median(&indexed_samples),
                    "old_ns": old_samples,
                    "indexed_ns": indexed_samples,
                })
            );
        }
    }
}

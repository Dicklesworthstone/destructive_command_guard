//! Bounded Python path facts for single-target deletion (#626).
//!
//! This pass shares the pattern worker's tree and deadline. Values are proofs:
//! joins need known operands, control-flow joins require safety on every path,
//! and deferred scopes never inherit a caller's path values. Possible deletion
//! callables survive lost proofs so indirection cannot erase a finding. This
//! code executes neither Python nor filesystem queries.

use super::{
    CompiledPattern, MatchError, PatternMatch, ScriptLanguage, Severity, check_ast_timeout,
    is_temp_scratch_path, truncate_preview,
};
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

const MAX_NODES: usize = 40_000;
const MAX_DEPTH: usize = 128;
const MAX_VALUE_BYTES: usize = 256 * 1024;
const OS_UNLINK: u8 = 1;
const OS_REMOVE: u8 = 2;
const OS_RMDIR: u8 = 4;
const PATH_UNLINK: u8 = 8;
const PATH_RMDIR: u8 = 16;

fn rule(kind: u8) -> &'static str {
    match kind {
        OS_UNLINK => "heredoc.python.os_unlink",
        OS_REMOVE => "heredoc.python.os_remove",
        OS_RMDIR => "heredoc.python.os_rmdir",
        PATH_UNLINK => "heredoc.python.pathlib_unlink",
        PATH_RMDIR => "heredoc.python.pathlib_rmdir",
        _ => unreachable!("one registered deletion kind"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Path {
    // Share immutable bytes across aliases and branch snapshots. A large
    // constant followed by many assignments must not amplify memory use.
    Literal(Arc<str>),
    // An allocation's source location, never a guessed host pathname.
    Fresh { origin: usize, relative: Arc<str> },
}

impl Path {
    fn safe(&self) -> bool {
        match self {
            Self::Literal(path) => is_temp_scratch_path(path) && clean(path),
            Self::Fresh { relative, .. } => {
                clean(relative)
                    && !relative.starts_with('/')
                    && relative.split('/').any(|part| !matches!(part, "" | "."))
            }
        }
    }

    fn join(&self, other: &Self) -> Option<Self> {
        let Self::Literal(right) = other else {
            return None;
        };
        if !clean(right) {
            return None;
        }
        // pathlib and os.path.join reset on an absolute operand.
        if right.starts_with('/') {
            return Some(Self::Literal(right.clone()));
        }
        let append = |left: &str| {
            (left.len() + right.len() < MAX_VALUE_BYTES).then(|| format!("{left}/{right}"))
        };
        match self {
            Self::Literal(left) if clean(left) => Some(Self::Literal(append(left)?.into())),
            Self::Fresh { origin, relative } => Some(Self::Fresh {
                origin: *origin,
                relative: if relative.is_empty() {
                    right.clone()
                } else {
                    append(relative)?.into()
                },
            }),
            _ => None,
        }
    }

    fn origin(&self) -> Option<usize> {
        match self {
            Self::Fresh { origin, .. } => Some(*origin),
            Self::Literal(_) => None,
        }
    }
}

fn clean(path: &str) -> bool {
    path.len() <= MAX_VALUE_BYTES
        && !path.contains(['\\', ':', '$', '`', '\0'])
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| part == "..")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Symbol {
    Os,
    OsPath,
    Pathlib,
    Tempfile,
    PathClass,
    Join,
    Mkdtemp,
    TemporaryDirectory,
    Str,
    Print,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Delete {
    kinds: u8,
    receiver: Option<Path>,
    bound: bool,
    trusted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Value {
    #[default]
    Unknown,
    Scalar,
    None,
    Text(Path),
    Path(Path),
    Directory(Path),
    Symbol(Symbol),
    PossibleOs,
    Delete(Delete),
    Join(Path),
    PathRead,
    LocalFunction {
        preserves: bool,
    },
}

impl Value {
    fn immutable_import(&self) -> bool {
        matches!(
            self,
            Self::Symbol(_)
                | Self::Delete(Delete {
                    receiver: None,
                    bound: false,
                    trusted: true,
                    ..
                })
        )
    }

    fn path(&self) -> Option<&Path> {
        match self {
            Self::Text(path) | Self::Path(path) => Some(path),
            _ => None,
        }
    }

    fn lost(&self) -> Self {
        match self {
            Self::Delete(call) => Self::Delete(Delete {
                kinds: call.kinds,
                receiver: None,
                bound: call.bound,
                trusted: false,
            }),
            Self::Symbol(Symbol::Os) | Self::PossibleOs => Self::PossibleOs,
            _ => Self::Unknown,
        }
    }

    fn merge(&self, other: &Self) -> Self {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (Self::Delete(left), Self::Delete(right)) => Self::Delete(Delete {
                kinds: left.kinds | right.kinds,
                receiver: None,
                bound: left.bound && right.bound,
                trusted: false,
            }),
            (Self::Delete(_), _) => self.lost(),
            (_, Self::Delete(_)) => other.lost(),
            (Self::Symbol(Symbol::Os) | Self::PossibleOs, _)
            | (_, Self::Symbol(Symbol::Os) | Self::PossibleOs) => Self::PossibleOs,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Env {
    values: HashMap<String, Value>,
    trusted: bool,
}

impl Env {
    fn get(&self, name: &str) -> Value {
        self.values.get(name).cloned().unwrap_or_default()
    }

    fn merge(&self, other: &Self) -> Self {
        let mut merged = Self {
            values: HashMap::new(),
            trusted: self.trusted && other.trusted,
        };
        for name in self.values.keys().chain(other.values.keys()) {
            merged
                .values
                .insert(name.clone(), self.get(name).merge(&other.get(name)));
        }
        merged
    }

    fn forget(&mut self) {
        for value in self.values.values_mut() {
            *value = value.lost();
        }
    }
}

#[derive(Default)]
struct Args {
    positional: Vec<Value>,
    keywords: HashMap<String, Value>,
    uncertain: bool,
}

impl Args {
    fn target(&self) -> Option<&Path> {
        if self.uncertain
            || self.positional.len() > 1
            || !self.positional.is_empty() && self.keywords.contains_key("path")
        {
            return None;
        }
        self.positional
            .first()
            .or_else(|| self.keywords.get("path"))?
            .path()
    }
}

pub(super) struct Scan<'a> {
    rules: Vec<&'a CompiledPattern>,
    matches: &'a mut Vec<PatternMatch>,
    newlines: &'a [usize],
    started: Instant,
    timeout: Duration,
    budget_ms: u64,
    cancel: &'a AtomicBool,
    remaining: usize,
    immutable: HashMap<String, Value>,
    possible: HashMap<String, Value>,
    deferred_depth: usize,
    deferred_findings: HashSet<(usize, usize, u8)>,
    outer_invalidated: bool,
    seen: HashMap<(usize, usize, u8), bool>,
    existing: HashMap<(usize, usize, u8), usize>,
}

impl<'a> Scan<'a> {
    pub(super) fn new(
        rules: Vec<&'a CompiledPattern>,
        matches: &'a mut Vec<PatternMatch>,
        newlines: &'a [usize],
        started: Instant,
        timeout: Duration,
        budget_ms: u64,
        cancel: &'a AtomicBool,
    ) -> Self {
        let mut existing = HashMap::new();
        for (index, hit) in matches.iter().enumerate() {
            for kind in [OS_UNLINK, OS_REMOVE, OS_RMDIR, PATH_UNLINK, PATH_RMDIR] {
                if hit.rule_id.strip_suffix(".temp").unwrap_or(&hit.rule_id) == rule(kind) {
                    existing.entry((hit.start, hit.end, kind)).or_insert(index);
                }
            }
        }
        Self {
            rules,
            matches,
            newlines,
            started,
            timeout,
            budget_ms,
            cancel,
            remaining: MAX_NODES,
            immutable: HashMap::new(),
            possible: HashMap::new(),
            deferred_depth: 0,
            deferred_findings: HashSet::new(),
            outer_invalidated: false,
            seen: HashMap::new(),
            existing,
        }
    }

    fn check<D: Doc>(&mut self, node: &Node<'_, D>, depth: usize) -> Result<(), MatchError> {
        check_ast_timeout(self.started, self.timeout, self.budget_ms, self.cancel)?;
        if depth >= MAX_DEPTH || self.remaining == 0 {
            return Err(MatchError::Unavailable {
                language: ScriptLanguage::Python,
                detail: "Python path-binding analysis exhausted its traversal limit".to_string(),
            });
        }
        self.remaining -= 1;
        if node.is_error() || node.is_missing() {
            return Err(MatchError::ParseError {
                language: ScriptLanguage::Python,
                detail: "Python path-binding analysis encountered invalid syntax".to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn run<D: Doc>(&mut self, root: Node<'_, D>) -> Result<(), MatchError> {
        let mut writes = HashSet::new();
        let mut imported = HashMap::new();
        let mut aliases = Vec::new();
        let mut trusted = true;
        // Whole-body identity proof includes later loop mutations and helper
        // bodies. Reflection/NFKC and shared-object writes revoke grants.
        for node in root.dfs() {
            self.check(&node, 0)?;
            let kind = node.kind();
            if kind == "identifier"
                && (!node.text().is_ascii()
                    || super::python_reflective_name(node.text().as_ref())
                    || matches!(node.text().as_ref(), "setattr" | "delattr" | "__import__"))
                || matches!(
                    kind.as_ref(),
                    "wildcard_import" | "global_statement" | "nonlocal_statement"
                )
                || kind == "attribute"
                    && node.field("attribute").is_some_and(|member| {
                        matches!(
                            member.text().as_ref(),
                            "__dict__"
                                | "__globals__"
                                | "__code__"
                                | "modules"
                                | "symlink"
                                | "symlink_to"
                                | "link_to"
                        )
                    })
            {
                trusted = false;
            }
            if matches!(kind.as_ref(), "import_statement" | "import_from_statement") {
                for (name, value) in import_values(&node) {
                    self.possible_binding(&name, value.lost());
                    imported
                        .entry(name)
                        .and_modify(|old: &mut Value| *old = old.merge(&value))
                        .or_insert(value);
                }
            }
            if matches!(kind.as_ref(), "assignment" | "named_expression")
                && let Some(target) = binding_target(&node)
                && let Some(value) = node.field("right").or_else(|| node.field("value"))
            {
                aliases.push((target, value));
            }
            if let Some(target) = binding_target(&node) {
                self.names(&target, &mut writes, 0)?;
                if target
                    .dfs()
                    .any(|part| matches!(part.kind().as_ref(), "attribute" | "subscript"))
                {
                    trusted = false;
                }
            }
            if matches!(kind.as_ref(), "parameters" | "lambda_parameters") {
                self.names(&node, &mut writes, 0)?;
            }
            if kind == "delete_statement" {
                for target in named(&node) {
                    self.names(&target, &mut writes, 0)?;
                    if target
                        .dfs()
                        .any(|part| matches!(part.kind().as_ref(), "attribute" | "subscript"))
                    {
                        trusted = false;
                    }
                }
            }
        }
        // Deferred bodies read globals when called, not at their textual
        // definition. Collect only POSSIBLE destructive capabilities across
        // the body, including forward alias chains. These facts can add a
        // denial but never establish a safe target or trusted module.
        loop {
            let previous = self.possible.clone();
            for (target, value) in &aliases {
                let value = self.capability(value, &previous, 0)?;
                if matches!(value, Value::Delete(_) | Value::PossibleOs) {
                    let mut names = HashSet::new();
                    self.names(target, &mut names, 0)?;
                    for name in names {
                        self.possible_binding(&name, value.clone());
                    }
                }
            }
            if self.possible == previous {
                break;
            }
        }
        let imported_names: HashSet<_> = imported.keys().cloned().collect();
        imported.retain(|name, value| !writes.contains(name) && value.immutable_import());
        for (name, symbol) in [("str", Symbol::Str), ("print", Symbol::Print)] {
            if !writes.contains(name) && !imported_names.contains(name) {
                imported.insert(name.to_string(), Value::Symbol(symbol));
            }
        }
        self.immutable = imported;
        let mut env = Env {
            values: HashMap::new(),
            trusted,
        };
        for name in ["str", "print"] {
            if let Some(value) = self.immutable.get(name) {
                env.values.insert(name.to_string(), value.clone());
            }
        }
        self.visit(root, &mut env, 0)?;
        if self.outer_invalidated {
            // A function may run after an opaque top-level operation has
            // changed a module dependency. Its definition-time imports cannot
            // then establish a future target. Only deferred positive findings
            // are revoked; already-completed straight-line deletions retain
            // their original statement-order proof.
            for &(start, end, kind) in &self.deferred_findings {
                if let Some(&index) = self.existing.get(&(start, end, kind))
                    && let Some(meta) = self.rules.iter().find(|meta| meta.rule_id == rule(kind))
                {
                    let hit = &mut self.matches[index];
                    hit.rule_id.clone_from(&meta.rule_id);
                    hit.reason.clone_from(&meta.reason);
                    hit.severity = meta.severity;
                }
            }
        }
        Ok(())
    }

    fn invalidate(&mut self, env: &mut Env) {
        env.trusted = false;
        env.forget();
        if self.deferred_depth == 0 {
            self.outer_invalidated = true;
        }
    }

    fn possible_binding(&mut self, name: &str, value: Value) {
        if matches!(value, Value::Delete(_) | Value::PossibleOs) {
            self.possible
                .entry(name.to_string())
                .and_modify(|old| *old = old.merge(&value))
                .or_insert(value);
        }
    }

    fn capability<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        known: &HashMap<String, Value>,
        depth: usize,
    ) -> Result<Value, MatchError> {
        self.check(node, depth)?;
        let value = match node.kind().as_ref() {
            "identifier" => known.get(node.text().as_ref()).cloned().unwrap_or_default(),
            "attribute" => {
                let object = if let Some(object) = node.field("object") {
                    self.capability(&object, known, depth + 1)?
                } else {
                    Value::Unknown
                };
                let member = node
                    .field("attribute")
                    .map(|member| member.text().into_owned())
                    .unwrap_or_default();
                attribute(object, &member).lost()
            }
            "assignment" | "named_expression" => {
                if let Some(value) = node.field("right").or_else(|| node.field("value")) {
                    self.capability(&value, known, depth + 1)?
                } else {
                    Value::Unknown
                }
            }
            "parenthesized_expression"
            | "conditional_expression"
            | "boolean_operator"
            | "tuple"
            | "list"
            | "expression_list" => {
                let mut value = Value::Unknown;
                for child in named(node) {
                    value = value.merge(&self.capability(&child, known, depth + 1)?);
                }
                value
            }
            _ => Value::Unknown,
        };
        Ok(value.lost())
    }

    fn names<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        names: &mut HashSet<String>,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(node, depth)?;
        match node.kind().as_ref() {
            "identifier" => {
                names.insert(node.text().into_owned());
            }
            "default_parameter" | "typed_default_parameter" => {
                if let Some(name) = node.field("name") {
                    self.names(&name, names, depth + 1)?;
                }
            }
            "parameters"
            | "lambda_parameters"
            | "typed_parameter"
            | "tuple_pattern"
            | "list_pattern"
            | "pattern_list"
            | "list_splat_pattern"
            | "dictionary_splat_pattern"
            | "parenthesized_expression"
            | "as_pattern_target"
            | "tuple"
            | "list"
            | "expression_list" => {
                for child in named(node).filter(|child| child.kind() != "type") {
                    self.names(&child, names, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn assign<D: Doc>(
        &mut self,
        target: &Node<'_, D>,
        value: Value,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.target_effects(target, env, depth)?;
        self.bind(target, value, env, depth)
    }

    // Attribute receivers and subscript indices execute even in a store or
    // delete target. Binding-position collection alone would miss p.unlink()
    // in `items[p.unlink()] = value`.
    fn target_effects<D: Doc>(
        &mut self,
        target: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(target, depth)?;
        match target.kind().as_ref() {
            "attribute" => {
                if let Some(object) = target.field("object") {
                    self.eval(&object, env, depth + 1)?;
                }
            }
            "subscript" => {
                for child in named(target) {
                    self.eval(&child, env, depth + 1)?;
                }
            }
            "identifier" => {}
            _ => {
                for child in named(target).filter(|child| child.kind() != "type") {
                    self.target_effects(&child, env, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    fn bind<D: Doc>(
        &mut self,
        target: &Node<'_, D>,
        value: Value,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        if matches!(
            target.kind().as_ref(),
            "as_pattern_target" | "parenthesized_expression"
        ) {
            let children: Vec<_> = named(target).collect();
            if children.len() == 1 {
                return self.bind(&children[0], value, env, depth + 1);
            }
        }
        let mut names = HashSet::new();
        self.names(target, &mut names, depth)?;
        let scalar = target.kind() == "identifier";
        for name in names {
            let old = env.get(&name);
            env.values.insert(
                name,
                if value == Value::Unknown {
                    old.lost()
                } else if scalar {
                    value.clone()
                } else {
                    Value::Unknown
                },
            );
        }
        Ok(())
    }

    fn deferred(&self, env: &Env) -> Env {
        let mut local = Env {
            values: self.possible.clone(),
            trusted: env.trusted,
        };
        for (name, value) in &env.values {
            if self.immutable.get(name) == Some(value) && value.immutable_import() {
                local.values.insert(name.clone(), value.clone());
            } else if matches!(value, Value::Delete(_) | Value::PossibleOs) {
                let possible = value.lost();
                local
                    .values
                    .entry(name.clone())
                    .and_modify(|old| *old = old.merge(&possible))
                    .or_insert(possible);
            }
        }
        local
    }

    fn locals<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(node, depth)?;
        if let Some(target) = binding_target(node) {
            self.bind(&target, Value::Unknown, env, depth + 1)?;
        }
        if matches!(
            node.kind().as_ref(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            return Ok(());
        }
        if matches!(
            node.kind().as_ref(),
            "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
        ) {
            // Comprehension iteration targets are local to the comprehension.
            // Only walrus targets bind in the containing function's scope.
            return self.walrus_locals(node, env, depth + 1);
        }
        if matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        ) {
            for (name, _) in import_values(node) {
                env.values.insert(name, Value::Unknown);
            }
        }
        for child in named(node) {
            self.locals(&child, env, depth + 1)?;
        }
        Ok(())
    }

    fn walrus_locals<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(node, depth)?;
        if matches!(
            node.kind().as_ref(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            return Ok(());
        }
        if node.kind() == "named_expression"
            && let Some(name) = node.field("name")
        {
            self.bind(&name, Value::Unknown, env, depth + 1)?;
        }
        for child in named(node) {
            self.walrus_locals(&child, env, depth + 1)?;
        }
        Ok(())
    }

    fn parameter_defaults<D: Doc>(
        &mut self,
        parameters: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<HashMap<String, Value>, MatchError> {
        self.check(parameters, depth)?;
        let mut defaults = HashMap::new();
        for parameter in named(parameters) {
            self.check(&parameter, depth + 1)?;
            let default = matches!(
                parameter.kind().as_ref(),
                "default_parameter" | "typed_default_parameter"
            )
            .then(|| parameter.field("value"))
            .flatten();
            for child in named(&parameter) {
                // Capture in definition order: a later default may rebind a
                // name used by an earlier one. No default proves the actual
                // argument a caller will pass, so retain only may-call facts.
                let value = self.eval(&child, env, depth + 1)?;
                if default
                    .as_ref()
                    .is_some_and(|default| default.range() == child.range())
                    && matches!(value, Value::Delete(_) | Value::PossibleOs)
                    && let Some(name) = parameter.field("name")
                {
                    defaults.insert(name.text().into_owned(), value.lost());
                }
            }
        }
        Ok(defaults)
    }

    fn visit<D: Doc>(
        &mut self,
        node: Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(&node, depth)?;
        match node.kind().as_ref() {
            "import_statement" | "import_from_statement" => {
                for (name, value) in import_values(&node) {
                    env.values.insert(name, value);
                }
            }
            "function_definition" | "class_definition" | "lambda" => {
                let is_function = node.kind() == "function_definition";
                if node.kind() == "class_definition" {
                    // Class construction may invoke a metaclass or a base's
                    // __init_subclass__ without an explicit call expression.
                    self.invalidate(env);
                }
                let body = node.field("body");
                let parameters = node.field("parameters");
                let mut defaults = HashMap::new();
                for child in named(&node) {
                    if body
                        .as_ref()
                        .is_none_or(|body| body.range() != child.range())
                    {
                        if parameters
                            .as_ref()
                            .is_some_and(|parameters| parameters.range() == child.range())
                        {
                            defaults = self.parameter_defaults(&child, env, depth + 1)?;
                        } else {
                            self.eval(&child, env, depth + 1)?;
                        }
                    }
                }
                let mut local = self.deferred(env);
                if let Some(parameters) = node.field("parameters") {
                    self.bind(&parameters, Value::Unknown, &mut local, depth + 1)?;
                }
                if let Some(body) = body {
                    self.locals(&body, &mut local, depth + 1)?;
                    for (name, possible) in defaults {
                        local
                            .values
                            .entry(name)
                            .and_modify(|old| *old = old.merge(&possible))
                            .or_insert(possible);
                    }
                    self.deferred_depth += 1;
                    let visited = self.visit(body, &mut local, depth + 1);
                    self.deferred_depth -= 1;
                    visited?;
                }
                if let Some(name) = node.field("name") {
                    env.values.insert(
                        name.text().into_owned(),
                        if is_function {
                            Value::LocalFunction {
                                preserves: local.trusted,
                            }
                        } else {
                            Value::Unknown
                        },
                    );
                }
            }
            "if_statement" => {
                if let Some(condition) = node.field("condition") {
                    self.eval(&condition, env, depth + 1)?;
                }
                let base = env.clone();
                let mut branches = Vec::new();
                if let Some(body) = node.field("consequence") {
                    let mut branch = base.clone();
                    self.visit(body, &mut branch, depth + 1)?;
                    branches.push(branch);
                }
                let mut exhaustive = false;
                let mut fallthrough = base;
                for alternative in node.field_children("alternative") {
                    exhaustive |= alternative.kind() == "else_clause";
                    self.check(&alternative, depth + 1)?;
                    if let Some(condition) = alternative.field("condition") {
                        self.eval(&condition, &mut fallthrough, depth + 1)?;
                    }
                    let mut branch = fallthrough.clone();
                    for body in named(&alternative).filter(|child| child.kind() == "block") {
                        self.visit(body, &mut branch, depth + 1)?;
                    }
                    branches.push(branch);
                }
                if !exhaustive {
                    branches.push(fallthrough);
                }
                if let Some(mut merged) = branches.pop() {
                    for branch in branches {
                        merged = merged.merge(&branch);
                    }
                    *env = merged;
                }
            }
            "for_statement" | "while_statement" => {
                if let Some(iterable) = node.field("right") {
                    self.eval(&iterable, env, depth + 1)?;
                }
                let mut entry = env.clone();
                loop {
                    let mut branch = entry.clone();
                    if let Some(condition) = node.field("condition") {
                        self.eval(&condition, &mut branch, depth + 1)?;
                    }
                    if let Some(target) = node.field("left") {
                        self.assign(&target, Value::Unknown, &mut branch, depth + 1)?;
                    }
                    if let Some(body) = node.field("body") {
                        self.visit(body, &mut branch, depth + 1)?;
                    }
                    let merged = entry.merge(&branch);
                    if merged == entry {
                        break;
                    }
                    entry = merged;
                }
                if let Some(alternative) = node.field("alternative") {
                    let mut branch = entry.clone();
                    self.visit(alternative, &mut branch, depth + 1)?;
                    entry = entry.merge(&branch);
                }
                *env = entry;
            }
            "try_statement" | "match_statement" => {
                // Exceptional edges and pattern captures can bind at many
                // points. Unsupported edges cannot carry positive facts.
                env.forget();
                let base = env.clone();
                let mut merged = base.clone();
                for child in named(&node) {
                    let mut branch = base.clone();
                    self.visit(child, &mut branch, depth + 1)?;
                    merged = merged.merge(&branch);
                }
                *env = merged;
            }
            "with_statement" => {
                let mut managed = HashSet::new();
                let mut opaque = false;
                for clause in named(&node).filter(|child| child.kind() == "with_clause") {
                    for item in named(&clause) {
                        let expression = item.field("value").unwrap_or(item);
                        match self.eval(&expression, env, depth + 1)? {
                            Value::Directory(path) if env.trusted => {
                                if let Some(origin) = path.origin() {
                                    managed.insert(origin);
                                }
                            }
                            _ => {
                                // __enter__ executes even for an identifier,
                                // with no explicit call node in the source.
                                opaque = true;
                                self.invalidate(env);
                            }
                        }
                    }
                }
                if let Some(body) = node.field("body") {
                    self.visit(body, env, depth + 1)?;
                }
                for value in env.values.values_mut() {
                    let path = match value {
                        Value::Directory(path) => Some(&*path),
                        Value::Delete(call) => call.receiver.as_ref(),
                        _ => value.path(),
                    };
                    if path
                        .and_then(Path::origin)
                        .is_some_and(|origin| managed.contains(&origin))
                    {
                        *value = value.lost();
                    }
                }
                if opaque {
                    // __exit__ has the same opaque-code boundary.
                    self.invalidate(env);
                }
            }
            "decorated_definition" => {
                // Applying the decorator happens before a deferred body can
                // run. Do not grant that body a pre-decoration factory proof.
                self.invalidate(env);
                for child in named(&node) {
                    self.visit(child, env, depth + 1)?;
                }
                // Applying a decorator invokes arbitrary code even when its
                // source is just a name. The following statement cannot rely
                // on the preceding path or factory bindings.
                self.invalidate(env);
            }
            "delete_statement" => {
                for target in named(&node) {
                    self.assign(&target, Value::Unknown, env, depth + 1)?;
                }
            }
            "module" | "block" | "else_clause" | "elif_clause" | "finally_clause"
            | "except_clause" => {
                if let Some(alias) = node.field("alias") {
                    self.assign(&alias, Value::Unknown, env, depth + 1)?;
                }
                for child in named(&node) {
                    self.visit(child, env, depth + 1)?;
                }
            }
            _ => {
                self.eval(&node, env, depth + 1)?;
            }
        }
        Ok(())
    }

    fn eval<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Value, MatchError> {
        self.check(node, depth)?;
        let value = match node.kind().as_ref() {
            "identifier" => env.get(node.text().as_ref()),
            "none" => Value::None,
            "true" | "false" | "integer" | "float" => Value::Scalar,
            "string" | "concatenated_string" => {
                // Decode Python, not shell quoting. Visit interpolation calls
                // even though the resulting string's value remains unknown.
                if let Some(text) =
                    super::super::static_interpreter_literal(node, ScriptLanguage::Python, 0)
                {
                    if text.len() <= MAX_VALUE_BYTES {
                        Value::Text(Path::Literal(text.into()))
                    } else {
                        Value::Unknown
                    }
                } else {
                    for child in named(node) {
                        self.eval(&child, env, depth + 1)?;
                    }
                    Value::Unknown
                }
            }
            "parenthesized_expression" | "expression_statement" => {
                let mut value = Value::Unknown;
                for child in named(node) {
                    value = self.eval(&child, env, depth + 1)?;
                }
                value
            }
            "assignment" | "named_expression" | "augmented_assignment" => {
                if let Some(right) = node.field("right").or_else(|| node.field("value")) {
                    let target = node.field("left").or_else(|| node.field("name"));
                    if node.kind() == "augmented_assignment" {
                        if let Some(target) = &target {
                            self.target_effects(target, env, depth + 1)?;
                        }
                    }
                    let mut value = self.eval(&right, env, depth + 1)?;
                    if let Some(target) = target {
                        if node.kind() == "augmented_assignment" {
                            value = Value::Unknown;
                            self.bind(&target, value.clone(), env, depth + 1)?;
                        } else {
                            self.assign(&target, value.clone(), env, depth + 1)?;
                        }
                    }
                    if let Some(annotation) = node.field("type") {
                        self.eval(&annotation, env, depth + 1)?;
                    }
                    value
                } else {
                    Value::Unknown
                }
            }
            "attribute" => {
                let object = if let Some(object) = node.field("object") {
                    self.eval(&object, env, depth + 1)?
                } else {
                    Value::Unknown
                };
                let member = node
                    .field("attribute")
                    .map(|member| member.text().into_owned())
                    .unwrap_or_default();
                attribute(object, &member)
            }
            "binary_operator" => {
                let left = if let Some(left) = node.field("left") {
                    self.eval(&left, env, depth + 1)?
                } else {
                    Value::Unknown
                };
                let right = if let Some(right) = node.field("right") {
                    self.eval(&right, env, depth + 1)?
                } else {
                    Value::Unknown
                };
                let operator = node
                    .field("operator")
                    .map(|operator| operator.text().into_owned())
                    .unwrap_or_default();
                match (operator.as_str(), left, right) {
                    ("/", Value::Path(left), right) => right
                        .path()
                        .and_then(|right| left.join(right))
                        .map_or(Value::Unknown, Value::Path),
                    ("+", Value::Text(Path::Literal(left)), Value::Text(Path::Literal(right)))
                        if left.len() + right.len() <= MAX_VALUE_BYTES =>
                    {
                        Value::Text(Path::Literal(format!("{left}{right}").into()))
                    }
                    _ => Value::Unknown,
                }
            }
            "conditional_expression" => {
                let children: Vec<_> = named(node).collect();
                if children.len() == 3 {
                    self.eval(&children[1], env, depth + 1)?;
                    let mut other = env.clone();
                    let left = self.eval(&children[0], env, depth + 1)?;
                    let right = self.eval(&children[2], &mut other, depth + 1)?;
                    *env = env.merge(&other);
                    left.merge(&right)
                } else {
                    Value::Unknown
                }
            }
            "boolean_operator" => {
                if let (Some(left), Some(right)) = (node.field("left"), node.field("right")) {
                    let left = self.eval(&left, env, depth + 1)?;
                    let mut branch = env.clone();
                    let right = self.eval(&right, &mut branch, depth + 1)?;
                    *env = env.merge(&branch);
                    left.merge(&right)
                } else {
                    Value::Unknown
                }
            }
            "as_pattern" => {
                let value = if let Some(expression) = named(node).next() {
                    self.eval(&expression, env, depth + 1)?
                } else {
                    Value::Unknown
                };
                if let Some(alias) = node.field("alias") {
                    let bound = if let Value::Directory(path) = &value {
                        Value::Text(path.clone())
                    } else {
                        Value::Unknown
                    };
                    self.assign(&alias, bound, env, depth + 1)?;
                }
                value
            }
            "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression" => {
                let mut local = if node.kind() == "generator_expression" {
                    self.deferred(env)
                } else {
                    env.clone()
                };
                for child in named(node) {
                    if child.kind() == "for_in_clause" {
                        for right in child.field_children("right") {
                            self.eval(&right, &mut local, depth + 1)?;
                        }
                        if let Some(left) = child.field("left") {
                            self.assign(&left, Value::Unknown, &mut local, depth + 1)?;
                        }
                    } else if child.kind() == "if_clause" {
                        self.eval(&child, &mut local, depth + 1)?;
                    }
                }
                if let Some(body) = node.field("body") {
                    self.eval(&body, &mut local, depth + 1)?;
                }
                // Walrus targets belong to the outer scope, including in a
                // deferred generator. Their previous values are no proof.
                for child in node
                    .dfs()
                    .filter(|child| child.kind() == "named_expression")
                {
                    self.check(&child, depth + 1)?;
                    if let Some(name) = child.field("name") {
                        self.assign(&name, Value::Unknown, env, depth + 1)?;
                    }
                }
                Value::Unknown
            }
            "function_definition" | "class_definition" | "lambda" => {
                self.visit(node.clone(), env, depth + 1)?;
                Value::Unknown
            }
            "call" => self.call(node, env, depth + 1)?,
            _ => {
                for child in named(node) {
                    self.eval(&child, env, depth + 1)?;
                }
                Value::Unknown
            }
        };
        Ok(value)
    }

    fn arguments<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Args, MatchError> {
        let mut args = Args::default();
        if let Some(arguments) = node.field("arguments") {
            for argument in named(&arguments) {
                self.check(&argument, depth)?;
                if argument.kind() == "keyword_argument" {
                    if let (Some(name), Some(value)) =
                        (argument.field("name"), argument.field("value"))
                    {
                        let value = self.eval(&value, env, depth + 1)?;
                        args.uncertain |= args
                            .keywords
                            .insert(name.text().into_owned(), value)
                            .is_some();
                    } else {
                        args.uncertain = true;
                    }
                } else {
                    args.uncertain |=
                        matches!(argument.kind().as_ref(), "list_splat" | "dictionary_splat");
                    args.positional.push(self.eval(&argument, env, depth + 1)?);
                }
            }
        } else {
            args.uncertain = true;
        }
        Ok(args)
    }

    fn call<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Value, MatchError> {
        let function = if let Some(function) = node.field("function") {
            let value = self.eval(&function, env, depth + 1)?;
            if value == Value::Unknown {
                // A source-visible helper may install a global alias only at
                // runtime. Lost reaching facts cannot erase that capability.
                // This fallback supplies only untrusted may-call identities.
                let possible = std::mem::take(&mut self.possible);
                let value = self.capability(&function, &possible, depth + 1);
                self.possible = possible;
                value?
            } else {
                value
            }
        } else {
            Value::Unknown
        };
        let args = self.arguments(node, env, depth + 1)?;
        let plain = !args.uncertain && args.keywords.is_empty();
        let value = match function {
            Value::Delete(call) => {
                let target = if call.bound {
                    call.receiver.as_ref()
                } else {
                    args.target()
                };
                let safe = env.trusted
                    && call.trusted
                    && !args.uncertain
                    && (!call.bound || args.positional.is_empty())
                    && target.is_some_and(Path::safe);
                self.record(node, call.kinds, safe);
                Value::Unknown
            }
            Value::Symbol(Symbol::PathClass) if plain && !args.positional.is_empty() => {
                fold_paths(&args.positional).map_or(Value::Unknown, Value::Path)
            }
            Value::Symbol(Symbol::Str) if plain && args.positional.len() == 1 => args.positional[0]
                .path()
                .cloned()
                .map_or(Value::Unknown, Value::Text),
            Value::Symbol(Symbol::Join) if plain && !args.positional.is_empty() => {
                fold_paths(&args.positional).map_or(Value::Unknown, Value::Text)
            }
            Value::Join(base) if plain => {
                let mut values = vec![Value::Path(base)];
                values.extend(args.positional);
                fold_paths(&values).map_or(Value::Unknown, Value::Path)
            }
            Value::Symbol(factory @ (Symbol::Mkdtemp | Symbol::TemporaryDirectory))
                if env.trusted && factory_arguments(&args) =>
            {
                let path = Path::Fresh {
                    origin: node.range().start,
                    relative: Arc::from(""),
                };
                if factory == Symbol::Mkdtemp {
                    Value::Text(path)
                } else {
                    Value::Directory(path)
                }
            }
            Value::PathRead | Value::Symbol(Symbol::Print) => Value::Unknown,
            Value::LocalFunction { preserves: true } => Value::Unknown,
            _ => {
                // Opaque code can replace bindings or expose module objects.
                // Later grants cannot rely on the old identities.
                self.invalidate(env);
                Value::Unknown
            }
        };
        Ok(value)
    }

    fn record<D: Doc>(&mut self, node: &Node<'_, D>, kinds: u8, safe: bool) {
        let range = node.range();
        for kind in [OS_UNLINK, OS_REMOVE, OS_RMDIR, PATH_UNLINK, PATH_RMDIR] {
            if kinds & kind == 0 {
                continue;
            }
            let Some(meta) = self.rules.iter().find(|meta| meta.rule_id == rule(kind)) else {
                continue;
            };
            // Preserve a direct os pattern's canonical attribution instead of
            // appending an unresolved receiver's duplicate pathlib finding.
            if matches!(kind, PATH_UNLINK | PATH_RMDIR)
                && [OS_UNLINK, OS_REMOVE, OS_RMDIR]
                    .iter()
                    .any(|kind| self.existing.contains_key(&(range.start, range.end, *kind)))
            {
                continue;
            }
            let safe = *self
                .seen
                .entry((range.start, range.end, kind))
                .and_modify(|previous| *previous &= safe)
                .or_insert(safe);
            if safe && self.deferred_depth > 0 {
                self.deferred_findings
                    .insert((range.start, range.end, kind));
            }
            let refined = PatternMatch {
                rule_id: if safe {
                    format!("{}.temp", meta.rule_id)
                } else {
                    meta.rule_id.clone()
                },
                reason: if safe {
                    format!("{} (target is a proven temporary descendant)", meta.reason)
                } else {
                    meta.reason.clone()
                },
                matched_text_preview: truncate_preview(&node.text(), 60),
                start: range.start,
                end: range.end,
                line_number: self.newlines.partition_point(|&pos| pos < range.start) + 1,
                severity: if safe {
                    Severity::Medium
                } else {
                    meta.severity
                },
                suggestion: meta.suggestion.clone(),
            };
            if let Some(&index) = self.existing.get(&(range.start, range.end, kind)) {
                self.matches[index] = refined;
            } else {
                self.existing
                    .insert((range.start, range.end, kind), self.matches.len());
                self.matches.push(refined);
            }
        }
    }
}

fn named<'a, D: Doc>(node: &Node<'a, D>) -> impl Iterator<Item = Node<'a, D>> {
    node.children()
        .filter(|child| child.is_named() && child.kind() != "comment")
}

fn binding_target<'a, D: Doc>(node: &Node<'a, D>) -> Option<Node<'a, D>> {
    match node.kind().as_ref() {
        "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
            node.field("left")
        }
        "named_expression" | "function_definition" | "class_definition" => node.field("name"),
        "as_pattern" | "except_clause" => node.field("alias"),
        _ => None,
    }
}

fn import_values<D: Doc>(node: &Node<'_, D>) -> Vec<(String, Value)> {
    let module = node
        .field("module_name")
        .map(|name| name.text().into_owned());
    let mut values: Vec<_> = node
        .field_children("name")
        .map(|imported| {
            let source = imported
                .field("name")
                .unwrap_or_else(|| imported.clone())
                .text()
                .into_owned();
            let alias = imported.field("alias").map_or_else(
                || {
                    if module.is_none() {
                        source.split('.').next().unwrap_or(&source).to_string()
                    } else {
                        source.clone()
                    }
                },
                |alias| alias.text().into_owned(),
            );
            let value = match (module.as_deref(), source.as_str()) {
                (None, "os") => Value::Symbol(Symbol::Os),
                (None, "os.path") if imported.field("alias").is_none() => Value::Symbol(Symbol::Os),
                (None, "os.path") | (Some("os"), "path") => Value::Symbol(Symbol::OsPath),
                (None, "pathlib") => Value::Symbol(Symbol::Pathlib),
                (None, "tempfile") => Value::Symbol(Symbol::Tempfile),
                (Some("pathlib"), "Path" | "PosixPath") => Value::Symbol(Symbol::PathClass),
                (Some("tempfile"), "mkdtemp") => Value::Symbol(Symbol::Mkdtemp),
                (Some("tempfile"), "TemporaryDirectory") => {
                    Value::Symbol(Symbol::TemporaryDirectory)
                }
                (Some("os.path"), "join") => Value::Symbol(Symbol::Join),
                (Some("os"), "unlink") => deletion(OS_UNLINK, None, false, true),
                (Some("os"), "remove") => deletion(OS_REMOVE, None, false, true),
                (Some("os"), "rmdir") => deletion(OS_RMDIR, None, false, true),
                _ => Value::Unknown,
            };
            (alias, value)
        })
        .collect();
    if module.as_deref() == Some("os")
        && node
            .children()
            .any(|child| child.kind() == "wildcard_import")
    {
        // A wildcard import establishes possible deletion capabilities, never
        // immutable identities or a temporary-path exemption.
        for (name, kind) in [
            ("unlink", OS_UNLINK),
            ("remove", OS_REMOVE),
            ("rmdir", OS_RMDIR),
        ] {
            values.push((name.to_string(), deletion(kind, None, false, false)));
        }
    }
    values
}

fn deletion(kinds: u8, receiver: Option<Path>, bound: bool, trusted: bool) -> Value {
    Value::Delete(Delete {
        kinds,
        receiver,
        bound,
        trusted,
    })
}

fn attribute(object: Value, member: &str) -> Value {
    match (&object, member) {
        // A control-flow join can contain either a module or a captured
        // deletion. Losing the exact receiver must not erase os.remove's
        // possible capability (unlike unlink/rmdir, remove is not a generic
        // pathlib method and otherwise has no unresolved-receiver rule).
        (Value::Delete(_), "remove") => deletion(OS_REMOVE, None, false, false),
        (Value::Symbol(Symbol::Os) | Value::PossibleOs, "unlink" | "remove" | "rmdir") => {
            let kind = match member {
                "unlink" => OS_UNLINK,
                "remove" => OS_REMOVE,
                _ => OS_RMDIR,
            };
            deletion(kind, None, false, object == Value::Symbol(Symbol::Os))
        }
        (Value::Symbol(Symbol::Os), "path") => Value::Symbol(Symbol::OsPath),
        (Value::Symbol(Symbol::Os), "fspath") => Value::Symbol(Symbol::Str),
        (Value::Symbol(Symbol::OsPath), "join") => Value::Symbol(Symbol::Join),
        (Value::Symbol(Symbol::Pathlib), "Path" | "PosixPath") => Value::Symbol(Symbol::PathClass),
        (Value::Symbol(Symbol::Tempfile), "mkdtemp") => Value::Symbol(Symbol::Mkdtemp),
        (Value::Symbol(Symbol::Tempfile), "TemporaryDirectory") => {
            Value::Symbol(Symbol::TemporaryDirectory)
        }
        (Value::Directory(path), "name") => Value::Text(path.clone()),
        (Value::Path(path), "joinpath") => Value::Join(path.clone()),
        (
            Value::Path(_),
            "write_text" | "write_bytes" | "read_text" | "read_bytes" | "exists" | "is_file"
            | "is_dir" | "touch" | "mkdir",
        ) => Value::PathRead,
        (_, "unlink" | "rmdir") => deletion(
            if member == "unlink" {
                PATH_UNLINK
            } else {
                PATH_RMDIR
            },
            object.path().cloned(),
            true,
            matches!(object, Value::Path(_)),
        ),
        _ => Value::Unknown,
    }
}

fn fold_paths(values: &[Value]) -> Option<Path> {
    let mut path = values.first()?.path()?.clone();
    for value in &values[1..] {
        path = path.join(value.path()?)?;
    }
    Some(path)
}

fn factory_arguments(args: &Args) -> bool {
    if args.uncertain || args.positional.len() > 3 {
        return false;
    }
    for (index, name) in ["suffix", "prefix", "dir"].iter().enumerate() {
        if args.positional.get(index).is_some() && args.keywords.contains_key(*name) {
            return false;
        }
        let value = args
            .positional
            .get(index)
            .or_else(|| args.keywords.get(*name));
        match (name, value) {
            (_, None | Some(Value::None)) => {}
            (&"dir", Some(Value::Text(Path::Literal(path))))
                if clean(path) && temp_parent(path) => {}
            (&"suffix" | &"prefix", Some(Value::Text(Path::Literal(path))))
                if clean(path) && !path.contains('/') => {}
            _ => return false,
        }
    }
    args.keywords.iter().all(|(name, value)| {
        matches!(name.as_str(), "prefix" | "suffix" | "dir")
            || matches!(name.as_str(), "ignore_cleanup_errors" | "delete")
                && *value == Value::Scalar
    })
}

fn temp_parent(path: &str) -> bool {
    if is_temp_scratch_path(path) {
        return true;
    }
    let parts: Vec<_> = path
        .split('/')
        .filter(|part| !matches!(*part, "" | "."))
        .collect();
    path.starts_with('/')
        && matches!(
            parts.as_slice(),
            ["tmp"] | ["var", "tmp"] | ["private", "tmp"] | ["private", "var", "tmp"]
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::AstGrep;
    use ast_grep_language::SupportLang;

    #[test]
    fn exhausted_path_proof_is_incomplete_not_an_empty_success() {
        let ast = AstGrep::new("p.unlink()", SupportLang::Python);
        let cancel = AtomicBool::new(false);
        let mut matches = Vec::new();
        let mut scan = Scan::new(
            Vec::new(),
            &mut matches,
            &[],
            Instant::now(),
            Duration::from_secs(5),
            5_000,
            &cancel,
        );
        scan.remaining = 1;
        let error = scan.run(ast.root()).expect_err("proof cannot fit one node");
        assert!(
            error.is_transient(),
            "exhaustion cannot authorize a deletion"
        );
    }

    #[test]
    fn cancelled_path_proof_returns_the_existing_deadline_error() {
        let ast = AstGrep::new("p.unlink()", SupportLang::Python);
        let cancel = AtomicBool::new(true);
        let mut matches = Vec::new();
        let error = Scan::new(
            Vec::new(),
            &mut matches,
            &[],
            Instant::now(),
            Duration::from_secs(5),
            5_000,
            &cancel,
        )
        .run(ast.root())
        .expect_err("cancelled proof must not succeed");
        assert!(error.is_transient());
    }

    #[test]
    fn path_binding_scan_respects_the_registered_corpus() {
        let only_remove: Vec<_> = super::super::default_patterns()
            .remove(&ScriptLanguage::Python)
            .unwrap()
            .into_iter()
            .filter(|meta| meta.rule_id == rule(OS_REMOVE))
            .collect();
        let matcher = super::super::AstMatcher::with_patterns(HashMap::from([(
            ScriptLanguage::Python,
            only_remove,
        )]));
        let matches = matcher
            .find_matches(
                "from os import remove as erase\nerase('/etc/hosts')\np.unlink()",
                ScriptLanguage::Python,
            )
            .unwrap();
        assert_eq!(matches.len(), 1, "omitted pathlib rule must remain omitted");
        assert_eq!(matches[0].rule_id, rule(OS_REMOVE));
        assert!(matches[0].severity.blocks_by_default());
    }
}

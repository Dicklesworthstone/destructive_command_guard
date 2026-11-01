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
const DELETE_KINDS: u16 = 31;
const MAY_OS: u16 = 1 << 5;
const MAY_GETATTR: u16 = 1 << 6;
const MAY_BUILTINS: u16 = 1 << 7;
const MAY_GET: u16 = 1 << 8;
const MAY_POP: u16 = 1 << 9;
const MAY_APPEND: u16 = 1 << 10;
const MAY_EXTEND: u16 = 1 << 11;
const MAY_UPDATE: u16 = 1 << 12;
const MAY_LIST: u16 = 1 << 13;
const MAY_DICT: u16 = 1 << 14;
const MAY_SELECT: u16 = MAY_GET | MAY_POP;
const MAY_MUTATE: u16 = MAY_POP | MAY_APPEND | MAY_EXTEND | MAY_UPDATE;
const MAY_CONTAINER: u16 = MAY_LIST | MAY_DICT;
const MAX_CONTAINER_ITEMS: usize = 32;
const MAX_CONTAINER_DEPTH: usize = 32;
const MAX_KEY_BYTES: usize = 1024;

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
    Getattr,
    Builtins,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Delete {
    kinds: u8,
    receiver: Option<Path>,
    bound: bool,
    trusted: bool,
}

// Direct and contained capabilities are separate: storing a deletion does not
// invoke it, and a container's own remove method is not os.remove. Joins only
// union these finite masks; none of them carries a safe path or trusted object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Capabilities {
    direct: u16,
    contained: u16,
    // Keep each selector invocation distinct from invocation of the selected
    // callback. This fixed ladder bounds nested selectors without recursively
    // expanding the shared container graph.
    returned: [u16; MAX_CONTAINER_DEPTH],
    returned_overflow: bool,
}

impl Capabilities {
    const fn union(mut self, other: Self) -> Self {
        self.direct |= other.direct;
        self.contained |= other.contained;
        self.returned_overflow |= other.returned_overflow;
        let mut index = 0;
        while index < MAX_CONTAINER_DEPTH {
            self.returned[index] |= other.returned[index];
            index += 1;
        }
        self
    }

    const fn any(self) -> bool {
        if self.direct != 0 || self.contained != 0 || self.returned_overflow {
            return true;
        }
        let mut index = 0;
        while index < MAX_CONTAINER_DEPTH {
            if self.returned[index] != 0 {
                return true;
            }
            index += 1;
        }
        false
    }

    const fn stored(self) -> Self {
        Self {
            direct: 0,
            contained: self.direct | self.contained,
            returned: self.returned,
            returned_overflow: self.returned_overflow,
        }
    }

    const fn selected(self) -> Self {
        Self {
            direct: self.contained,
            // Retain descendants after an unresolved selection so another
            // subscription cannot hide a nested deletion.
            contained: self.contained,
            returned: self.returned,
            returned_overflow: self.returned_overflow,
        }
    }

    fn selector(self, operation: ContainerOp) -> Self {
        let mut result = Self {
            direct: operation.capability(),
            ..Self::default()
        };
        if operation.selects() {
            result.returned[0] = self.contained;
            for index in 1..MAX_CONTAINER_DEPTH {
                result.returned[index] = self.returned[index - 1];
            }
            result.returned_overflow =
                self.returned_overflow || self.returned[MAX_CONTAINER_DEPTH - 1] != 0;
        }
        result
    }

    fn called(self) -> Self {
        let mut result = Self {
            direct: self.returned[0],
            contained: self.returned[0],
            returned_overflow: self.returned_overflow,
            ..Self::default()
        };
        for index in 0..MAX_CONTAINER_DEPTH - 1 {
            result.returned[index] = self.returned[index + 1];
        }
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContainerOp {
    Get,
    Pop,
    Append,
    Extend,
    Update,
}

impl ContainerOp {
    const fn capability(self) -> u16 {
        match self {
            Self::Get => MAY_GET,
            Self::Pop => MAY_POP,
            Self::Append => MAY_APPEND,
            Self::Extend => MAY_EXTEND,
            Self::Update => MAY_UPDATE,
        }
    }

    const fn selects(self) -> bool {
        matches!(self, Self::Get | Self::Pop)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ContainerKey {
    Integer(i64),
    Text(Arc<str>),
}

struct Container {
    entries: Vec<(ContainerKey, Value)>,
    source: usize,
    sequence: bool,
    mutable_sequence: bool,
    precise: bool,
    members: Capabilities,
    depth: usize,
    origins: Vec<usize>,
    unknown_origins: bool,
}

impl std::fmt::Debug for Container {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Container")
            .field("entries", &self.entries.len())
            .field("precise", &self.precise)
            .field("members", &self.members)
            .field("depth", &self.depth)
            .field("origins", &self.origins.len())
            .field("unknown_origins", &self.unknown_origins)
            .finish_non_exhaustive()
    }
}

// Snapshots are shared by Arc and compare only by identity. Recursive
// comparison of independently built shared graphs can amplify a short source
// exponentially outside the AST budget. Distinct snapshots instead join to
// their finite may-call summaries.
impl PartialEq for Container {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for Container {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Value {
    #[default]
    Unknown,
    Scalar,
    None,
    // A selected standard text/path value without its path identity.
    Inert,
    // A non-deletion selection whose conversion behavior is unproved.
    Other,
    Text(Path),
    Path(Path),
    Directory(Path),
    Symbol(Symbol),
    Possible(Capabilities),
    Container(Arc<Container>),
    ContainerMethod {
        receiver: Arc<Container>,
        operation: ContainerOp,
    },
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

    fn inert_conversion(&self) -> bool {
        matches!(
            self,
            Self::Scalar | Self::None | Self::Inert | Self::Text(_) | Self::Path(_)
        )
    }

    fn inert_binary_operand(&self) -> bool {
        // Builtin container + and / dispatch does not convert its elements.
        // In contrast, str(container) can invoke an unknown element's repr.
        self.inert_conversion() || matches!(self, Self::Container(_))
    }

    fn capabilities(&self) -> Capabilities {
        match self {
            Self::Delete(call) => Capabilities {
                direct: u16::from(call.kinds),
                ..Capabilities::default()
            },
            Self::Symbol(symbol) => Capabilities {
                direct: match symbol {
                    Symbol::Os => MAY_OS,
                    Symbol::Getattr => MAY_GETATTR,
                    Symbol::Builtins => MAY_BUILTINS,
                    _ => 0,
                },
                ..Capabilities::default()
            },
            Self::Possible(possible) => *possible,
            Self::Container(container) => Capabilities {
                direct: if !container.sequence {
                    MAY_DICT
                } else if container.mutable_sequence {
                    MAY_LIST
                } else {
                    0
                },
                ..container.members.stored()
            },
            Self::ContainerMethod {
                receiver,
                operation,
            } => Self::Container(receiver.clone())
                .capabilities()
                .selector(*operation),
            _ => Capabilities::default(),
        }
    }

    fn possible(possible: Capabilities) -> Self {
        if possible.any() {
            Self::Possible(possible)
        } else {
            Self::Unknown
        }
    }

    fn has_capability(&self) -> bool {
        self.capabilities().any()
    }

    fn lost(&self) -> Self {
        Self::possible(self.capabilities())
    }

    // Literal snapshots retain exact selections until an opaque effect or a
    // join loses their identity. Only captured deletion functions may carry
    // receiver proofs; paths and module objects do not gain one by storage.
    fn indirect(&self) -> Self {
        if matches!(self, Self::Container(_) | Self::ContainerMethod { .. }) {
            self.clone()
        } else {
            self.lost()
        }
    }

    fn captured(&self) -> Self {
        if matches!(
            self,
            Self::Scalar | Self::None | Self::Inert | Self::Delete(Delete { trusted: true, .. })
        ) {
            self.clone()
        } else if matches!(self, Self::Text(_) | Self::Path(_)) {
            // Preserve inert conversion without granting a path through an
            // otherwise unsupported container value.
            Self::Inert
        } else if *self != Self::Unknown && !self.has_capability() {
            // A precise non-deletion slot must not fall back to another slot's
            // possible deletion. That fact alone does not prove its coercions
            // are inert: a nested container can hold unknown repr hooks.
            Self::Other
        } else {
            self.indirect()
        }
    }

    fn merge(&self, other: &Self) -> Self {
        if self == other {
            self.clone()
        } else {
            Self::possible(self.capabilities().union(other.capabilities()))
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ContainerEffects {
    changed: HashMap<usize, Capabilities>,
    all_changed: bool,
    added: Capabilities,
    performed: bool,
}

impl ContainerEffects {
    fn mark(&mut self, source: Option<usize>, added: Capabilities) {
        self.performed = true;
        self.added = self.added.union(added);
        if self.all_changed {
            return;
        }
        if let Some(source) = source {
            if self.changed.len() < MAX_CONTAINER_ITEMS || self.changed.contains_key(&source) {
                self.changed
                    .entry(source)
                    .and_modify(|old| *old = old.union(added))
                    .or_insert(added);
                return;
            }
        }
        self.all_changed = true;
        self.changed.clear();
    }

    fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.all_changed |= other.all_changed;
        merged.added = merged.added.union(other.added);
        merged.performed |= other.performed;
        if !merged.all_changed {
            for (source, added) in &other.changed {
                if merged.changed.len() == MAX_CONTAINER_ITEMS
                    && !merged.changed.contains_key(source)
                {
                    merged.all_changed = true;
                    break;
                }
                merged
                    .changed
                    .entry(*source)
                    .and_modify(|old| *old = old.union(*added))
                    .or_insert(*added);
            }
        }
        if merged.all_changed {
            merged.changed.clear();
        }
        merged
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Env {
    values: HashMap<String, Value>,
    trusted: bool,
    containers: ContainerEffects,
}

impl Env {
    fn get(&self, name: &str) -> Value {
        self.values.get(name).cloned().unwrap_or_default()
    }

    fn merge(&self, other: &Self) -> Self {
        let mut merged = Self {
            values: HashMap::new(),
            trusted: self.trusted && other.trusted,
            containers: self.containers.merge(&other.containers),
        };
        for name in self.values.keys().chain(other.values.keys()) {
            merged
                .values
                .insert(name.clone(), self.get(name).merge(&other.get(name)));
        }
        merged
    }

    fn exact_container(&self, receiver: &Container) -> bool {
        receiver.precise
            && !self.containers.all_changed
            && !self.containers.changed.contains_key(&receiver.source)
    }

    fn container_capabilities(&self, value: &Value) -> Capabilities {
        let mut possible = value.capabilities();
        let source = match value {
            Value::Container(receiver) | Value::ContainerMethod { receiver, .. } => {
                Some(receiver.source)
            }
            _ => None,
        };
        let added = if !self.containers.all_changed
            && let Some(source) = source
        {
            self.containers
                .changed
                .get(&source)
                .copied()
                .unwrap_or_default()
        } else {
            self.containers.added
        }
        .stored();
        if (possible.direct | possible.contained) & MAY_CONTAINER != 0 {
            possible = possible.union(added);
        }
        if possible.direct & MAY_SELECT != 0 {
            let operation = if possible.direct & MAY_GET != 0 {
                ContainerOp::Get
            } else {
                ContainerOp::Pop
            };
            possible = possible.union(added.selector(operation));
        }
        possible
    }

    fn container_value(&self, value: Value) -> Value {
        if let Value::Container(receiver) = &value {
            if self.exact_container(receiver) {
                return value;
            }
        } else if !matches!(value, Value::Possible(_)) {
            return value;
        }
        Value::possible(self.container_capabilities(&value))
    }

    fn select(&self, object: Value, key: Option<ContainerKey>, slice: bool) -> Value {
        selected(self.container_value(object), key, slice)
    }

    fn forget(&mut self) {
        self.containers.all_changed = true;
        self.containers.changed.clear();
        let values = std::mem::take(&mut self.values);
        self.values = values
            .into_iter()
            .map(|(name, value)| (name, Value::possible(self.container_capabilities(&value))))
            .collect();
    }
}

// A completed statement can leave by only one of these routes. Keep their
// facts separate: a break cannot reach the next statement or the loop's else,
// and a return still has to run a surrounding finally suite.
#[derive(Clone, Copy)]
enum Exit {
    Normal,
    Break,
    Continue,
    Return,
    Raise,
}

const EXITS: [Exit; 5] = [
    Exit::Normal,
    Exit::Break,
    Exit::Continue,
    Exit::Return,
    Exit::Raise,
];

#[derive(Default)]
struct Flow {
    normal: Option<Env>,
    breaks: Option<Env>,
    continues: Option<Env>,
    returns: Option<Env>,
    raises: Option<Env>,
}

impl Flow {
    fn normal(env: Env) -> Self {
        Self {
            normal: Some(env),
            ..Self::default()
        }
    }

    fn slot(&mut self, exit: Exit) -> &mut Option<Env> {
        match exit {
            Exit::Normal => &mut self.normal,
            Exit::Break => &mut self.breaks,
            Exit::Continue => &mut self.continues,
            Exit::Return => &mut self.returns,
            Exit::Raise => &mut self.raises,
        }
    }

    fn add(&mut self, exit: Exit, env: Env) {
        let slot = self.slot(exit);
        *slot = Some(match slot.take() {
            Some(old) => old.merge(&env),
            None => env,
        });
    }

    fn merge(&mut self, mut other: Self) {
        for exit in EXITS {
            if let Some(env) = other.slot(exit).take() {
                self.add(exit, env);
            }
        }
    }

    fn environments(&self) -> impl Iterator<Item = &Env> {
        [
            &self.normal,
            &self.breaks,
            &self.continues,
            &self.returns,
            &self.raises,
        ]
        .into_iter()
        .flatten()
    }

    fn environments_mut(&mut self) -> impl Iterator<Item = &mut Env> {
        [
            &mut self.normal,
            &mut self.breaks,
            &mut self.continues,
            &mut self.returns,
            &mut self.raises,
        ]
        .into_iter()
        .flatten()
    }

    fn joined(&self) -> Option<Env> {
        self.environments()
            .cloned()
            .reduce(|left, right| left.merge(&right))
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
    container_writes: bool,
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
            container_writes: false,
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
        let mut calls = Vec::new();
        let mut trusted = true;
        self.possible_binding("getattr", Value::Symbol(Symbol::Getattr).lost());
        // Whole-body identity proof includes later loop mutations and helper
        // bodies. Reflection/NFKC and shared-object writes revoke grants.
        for node in root.dfs() {
            self.check(&node, 0)?;
            let kind = node.kind();
            if kind == "identifier"
                && (!node.text().is_ascii()
                    || node.text() != "getattr"
                        && super::python_reflective_name(node.text().as_ref())
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
            if kind == "call" {
                calls.push(node.clone());
            }
            if let Some(target) = binding_target(&node) {
                self.names(&target, &mut writes, 0)?;
                if target
                    .dfs()
                    .any(|part| matches!(part.kind().as_ref(), "attribute" | "subscript"))
                {
                    trusted = false;
                    self.container_writes = true;
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
                        self.container_writes = true;
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
                if target.kind() == "identifier"
                    && value.kind() == "identifier"
                    && let Some(alias) = previous.get(target.text().as_ref())
                {
                    // An item store through either name can change their
                    // shared container. Propagate only contained may-facts;
                    // this cannot establish a callable or a safe receiver.
                    let possible = alias.capabilities();
                    let stored = Capabilities {
                        direct: 0,
                        ..possible
                    };
                    if stored.any() {
                        self.possible_binding(value.text().as_ref(), Value::possible(stored));
                    }
                }
                let value = self.capability(value, &previous, 0)?;
                if value.has_capability() {
                    self.possible_target(target, value, 0)?;
                }
            }
            for call in &calls {
                self.mutation_capability(call, &aliases, &previous, 0)?;
            }
            if self.possible == previous {
                break;
            }
        }
        let imported_names: HashSet<_> = imported.keys().cloned().collect();
        imported.retain(|name, value| !writes.contains(name) && value.immutable_import());
        for (name, symbol) in [
            ("str", Symbol::Str),
            ("print", Symbol::Print),
            ("getattr", Symbol::Getattr),
        ] {
            if !writes.contains(name) && !imported_names.contains(name) {
                imported.insert(name.to_string(), Value::Symbol(symbol));
            }
        }
        self.immutable = imported;
        let mut env = Env {
            values: HashMap::new(),
            trusted,
            containers: ContainerEffects::default(),
        };
        env.values
            .insert("getattr".to_string(), Value::Symbol(Symbol::Getattr).lost());
        for name in ["str", "print", "getattr"] {
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
        for (name, value) in &mut env.values {
            if let Some(possible) = self.possible.get(name) {
                *value = value.merge(&possible.lost());
            }
        }
        if self.deferred_depth == 0 {
            self.outer_invalidated = true;
        }
    }

    fn possible_binding(&mut self, name: &str, value: Value) {
        if value.has_capability() {
            self.possible
                .entry(name.to_string())
                .and_modify(|old| *old = old.merge(&value))
                .or_insert(value);
        }
    }

    fn possible_target<D: Doc>(
        &mut self,
        target: &Node<'_, D>,
        value: Value,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(target, depth)?;
        if target.kind() == "identifier" {
            self.possible_binding(target.text().as_ref(), value);
        } else if matches!(
            target.kind().as_ref(),
            "as_pattern_target" | "parenthesized_expression"
        ) {
            for child in named(target) {
                self.possible_target(&child, value.clone(), depth + 1)?;
            }
        } else if destructuring(target.kind().as_ref()) {
            let children: Vec<_> = named(target).collect();
            let starred = children
                .iter()
                .any(|child| child.kind() == "list_splat_pattern");
            for (index, child) in children.iter().enumerate() {
                let value = if child.kind() == "list_splat_pattern" {
                    value.lost()
                } else {
                    selected(
                        value.clone(),
                        (!starred)
                            .then(|| i64::try_from(index).ok())
                            .flatten()
                            .map(ContainerKey::Integer),
                        false,
                    )
                };
                self.possible_target(child, value, depth + 1)?;
            }
        } else if target.kind() == "list_splat_pattern" {
            for child in named(target) {
                self.possible_target(&child, value.clone(), depth + 1)?;
            }
        } else if target.kind() == "subscript" {
            // An explicit item store can introduce a capability absent from
            // the original literal. Attribute/index effects are still visited
            // by the normal assignment evaluator.
            let mut base = target.field("value");
            while let Some(node) = base {
                self.check(&node, depth + 1)?;
                if node.kind() == "identifier" {
                    let possible = value.capabilities();
                    self.possible_binding(node.text().as_ref(), Value::possible(possible.stored()));
                    break;
                }
                base = node.field("value").or_else(|| node.field("object"));
            }
        }
        Ok(())
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
            "list" | "tuple" | "expression_list" | "dictionary" => {
                self.container(node, depth + 1, |scan, child, depth| {
                    scan.capability(child, known, depth)
                })?
            }
            "subscript" => {
                let (object, key, slice) =
                    self.subscription(node, depth + 1, |scan, child, depth| {
                        scan.capability(child, known, depth)
                    })?;
                selected(object, key, slice)
            }
            "call" => self.call_capability(node, known, depth + 1)?,
            "list_splat" | "dictionary_splat" => {
                let mut possible = Capabilities::default();
                for child in named(node) {
                    possible =
                        possible.union(self.capability(&child, known, depth + 1)?.capabilities());
                }
                Value::possible(possible.selected())
            }
            "parenthesized_expression" => {
                let mut value = Value::Unknown;
                for child in named(node) {
                    value = self.capability(&child, known, depth + 1)?;
                }
                value
            }
            "conditional_expression" | "boolean_operator" => {
                let mut value = Value::Unknown;
                for child in named(node) {
                    value = value.merge(&self.capability(&child, known, depth + 1)?);
                }
                value
            }
            _ => Value::Unknown,
        };
        Ok(value.indirect())
    }

    fn container<'tree, D: Doc>(
        &mut self,
        node: &Node<'tree, D>,
        depth: usize,
        mut evaluate: impl FnMut(&mut Self, &Node<'tree, D>, usize) -> Result<Value, MatchError>,
    ) -> Result<Value, MatchError> {
        self.check(node, depth)?;
        let sequence = node.kind() != "dictionary";
        let mut container = Container {
            entries: Vec::new(),
            source: node.range().start,
            sequence,
            mutable_sequence: node.kind() == "list",
            precise: !self.container_writes,
            members: Capabilities::default(),
            depth: 1,
            origins: Vec::new(),
            unknown_origins: false,
        };
        let mut index = 0_i64;
        for child in named(node) {
            self.check(&child, depth + 1)?;
            let (key, value) = if child.kind() == "pair" {
                let key = if let Some(key) = child.field("key") {
                    evaluate(self, &key, depth + 1)?;
                    container_key(&key)
                } else {
                    None
                };
                let value = if let Some(value) = child.field("value") {
                    evaluate(self, &value, depth + 1)?
                } else {
                    Value::Unknown
                };
                (key, value)
            } else if matches!(child.kind().as_ref(), "list_splat" | "dictionary_splat") {
                container.precise = false;
                let mut value = Value::Unknown;
                for operand in named(&child) {
                    value = value.merge(&evaluate(self, &operand, depth + 1)?);
                }
                (None, value)
            } else {
                let value = evaluate(self, &child, depth + 1)?;
                let key = sequence.then_some(ContainerKey::Integer(index));
                index += 1;
                (key, value)
            };
            let value = value.captured();
            note_origins(&mut container, &value);
            container.members = container.members.union(value.capabilities());
            if let Some(key) = key {
                if let Some((_, previous)) =
                    container.entries.iter_mut().find(|(old, _)| *old == key)
                {
                    *previous = value;
                } else if container.entries.len() < MAX_CONTAINER_ITEMS {
                    container.entries.push((key, value));
                } else {
                    container.precise = false;
                }
            } else {
                container.precise = false;
            }
        }
        if container.depth > MAX_CONTAINER_DEPTH {
            // A flat sequence of assignments can build a deep value graph
            // without deep syntax. Keep its finite capability summary, while
            // bounding snapshot destruction and retaining every element's effects.
            return Ok(Value::possible(Capabilities {
                direct: if !container.sequence {
                    MAY_DICT
                } else if container.mutable_sequence {
                    MAY_LIST
                } else {
                    0
                },
                ..container.members.stored()
            }));
        }
        Ok(Value::Container(Arc::new(container)))
    }

    fn subscription<'tree, D: Doc>(
        &mut self,
        node: &Node<'tree, D>,
        depth: usize,
        mut evaluate: impl FnMut(&mut Self, &Node<'tree, D>, usize) -> Result<Value, MatchError>,
    ) -> Result<(Value, Option<ContainerKey>, bool), MatchError> {
        self.check(node, depth)?;
        let object = if let Some(object) = node.field("value") {
            evaluate(self, &object, depth + 1)?
        } else {
            Value::Unknown
        };
        let mut key = None;
        let mut count = 0;
        let mut slice = false;
        for index in node.field_children("subscript") {
            evaluate(self, &index, depth + 1)?;
            count += 1;
            key = container_key(&index);
            slice = index.kind() == "slice";
        }
        Ok((
            object,
            if count == 1 { key } else { None },
            count == 1 && slice,
        ))
    }

    fn call_capability<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        known: &HashMap<String, Value>,
        depth: usize,
    ) -> Result<Value, MatchError> {
        self.check(node, depth)?;
        let Some(function) = node.field("function") else {
            return Ok(Value::Unknown);
        };
        let function = self.capability(&function, known, depth + 1)?.capabilities();
        let Some(arguments) = node.field("arguments") else {
            return Ok(Value::Unknown);
        };
        let arguments: Vec<_> = named(&arguments).collect();
        let mut result = Value::Unknown;
        if function.direct & MAY_SELECT != 0 {
            result = Value::possible(function.called());
            if let Some(default) = arguments.get(1) {
                result = result.merge(&self.capability(default, known, depth + 1)?);
            }
        }
        if function.direct & MAY_GETATTR != 0
            && (2..=3).contains(&arguments.len())
            && !arguments.iter().any(|argument| {
                matches!(
                    argument.kind().as_ref(),
                    "keyword_argument" | "list_splat" | "dictionary_splat"
                )
            })
        {
            let object = self.capability(&arguments[0], known, depth + 1)?;
            let member =
                super::super::static_interpreter_literal(&arguments[1], ScriptLanguage::Python, 0);
            let default = if let Some(default) = arguments.get(2) {
                self.capability(default, known, depth + 1)?
            } else {
                Value::Unknown
            };
            result = result.merge(&reflected(object, member.as_deref(), default));
        }
        Ok(result)
    }

    // Source-visible stores must reach aliases even when a helper executes
    // after its definition. These facts provide only may-identities.
    fn mutation_capability<'tree, D: Doc>(
        &mut self,
        call: &Node<'tree, D>,
        aliases: &[(Node<'tree, D>, Node<'tree, D>)],
        known: &HashMap<String, Value>,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(call, depth)?;
        let Some(function) = call.field("function") else {
            return Ok(());
        };
        let mut targets = Vec::new();
        let unresolved = self.mutation_targets(
            &function,
            aliases,
            &mut HashSet::new(),
            &mut targets,
            depth + 1,
        )?;
        let unknown_methods = if unresolved {
            self.capability(&function, known, depth + 1)?
                .capabilities()
                .direct
                & (MAY_APPEND | MAY_EXTEND | MAY_UPDATE)
        } else {
            0
        };
        if targets.is_empty() && unknown_methods == 0 {
            return Ok(());
        }
        let Some(arguments) = call.field("arguments") else {
            return Ok(());
        };
        let mut args = Args::default();
        for argument in named(&arguments) {
            self.check(&argument, depth + 1)?;
            if argument.kind() == "keyword_argument" {
                if let (Some(name), Some(value)) = (argument.field("name"), argument.field("value"))
                {
                    args.keywords.insert(
                        name.text().into_owned(),
                        self.capability(&value, known, depth + 1)?,
                    );
                }
            } else {
                args.positional
                    .push(self.capability(&argument, known, depth + 1)?);
            }
        }
        let mut unknown_added = mutation_arguments(unknown_methods, &args);
        for (target, operation) in targets {
            let added = mutation_arguments(operation.capability(), &args);
            let mut base = Some(target);
            let mut resolved = false;
            while let Some(node) = base {
                self.check(&node, depth + 1)?;
                if node.kind() == "identifier" {
                    self.possible_binding(
                        node.text().as_ref(),
                        Value::possible(Capabilities {
                            direct: if operation == ContainerOp::Update {
                                MAY_DICT
                            } else {
                                MAY_LIST
                            },
                            ..added.stored()
                        }),
                    );
                    resolved = true;
                    break;
                }
                base = node.field("value").or_else(|| node.field("object"));
            }
            if !resolved {
                unknown_added = unknown_added.union(added);
            }
        }
        if unknown_added.any() {
            // A source-visible captured mutator can be retrieved through a
            // container in a deferred helper. Its receiver may then be lost,
            // but the stored callback must still reach possible containers.
            // These finite may-facts never establish a callable or safe path.
            for (name, value) in known {
                self.check(call, depth + 1)?;
                let possible = value.capabilities();
                if (possible.direct | possible.contained) & MAY_CONTAINER != 0 {
                    self.possible_binding(
                        name,
                        Value::possible(possible.union(unknown_added.stored())),
                    );
                }
            }
        }
        Ok(())
    }

    fn mutation_targets<'tree, D: Doc>(
        &mut self,
        function: &Node<'tree, D>,
        aliases: &[(Node<'tree, D>, Node<'tree, D>)],
        seen: &mut HashSet<String>,
        targets: &mut Vec<(Node<'tree, D>, ContainerOp)>,
        depth: usize,
    ) -> Result<bool, MatchError> {
        self.check(function, depth)?;
        let mut unresolved = false;
        match function.kind().as_ref() {
            "attribute" => {
                let operation =
                    function
                        .field("attribute")
                        .and_then(|member| match member.text().as_ref() {
                            "append" => Some(ContainerOp::Append),
                            "extend" => Some(ContainerOp::Extend),
                            "update" => Some(ContainerOp::Update),
                            _ => None,
                        });
                if let Some(operation) = operation
                    && let Some(receiver) = function.field("object")
                {
                    targets.push((receiver, operation));
                }
            }
            "identifier" if seen.insert(function.text().into_owned()) => {
                for (target, value) in aliases {
                    self.check(target, depth + 1)?;
                    if target.kind() == "identifier" && target.text() == function.text() {
                        unresolved |=
                            self.mutation_targets(value, aliases, seen, targets, depth + 1)?;
                    } else if target.kind() != "identifier" {
                        let mut bound = HashSet::new();
                        self.names(target, &mut bound, depth + 1)?;
                        // Destructuring can capture a mutator whose receiver
                        // is absent from the simple assignment-alias graph.
                        // Keep the finite method identity even when another
                        // assignment to this name has a recoverable receiver.
                        unresolved |= bound.contains(function.text().as_ref());
                    }
                }
            }
            "parenthesized_expression" | "conditional_expression" | "boolean_operator" => {
                for child in named(function) {
                    unresolved |=
                        self.mutation_targets(&child, aliases, seen, targets, depth + 1)?;
                }
            }
            "subscript" | "call" => unresolved = true,
            _ => {}
        }
        Ok(unresolved)
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
        if destructuring(target.kind().as_ref()) {
            let children: Vec<_> = named(target).collect();
            let starred = children
                .iter()
                .any(|child| child.kind() == "list_splat_pattern");
            for (index, child) in children.iter().enumerate() {
                let value = if child.kind() == "list_splat_pattern" {
                    value.lost()
                } else {
                    env.select(
                        value.clone(),
                        (!starred)
                            .then(|| i64::try_from(index).ok())
                            .flatten()
                            .map(ContainerKey::Integer),
                        false,
                    )
                };
                self.bind(child, value, env, depth + 1)?;
            }
            return Ok(());
        }
        let mut names = HashSet::new();
        self.names(target, &mut names, depth)?;
        let scalar = matches!(target.kind().as_ref(), "identifier" | "list_splat_pattern");
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
            containers: ContainerEffects::default(),
        };
        for (name, value) in &env.values {
            if self.immutable.get(name) == Some(value) && value.immutable_import() {
                local.values.insert(name.clone(), value.clone());
            } else if value.has_capability() {
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
                    && value.has_capability()
                    && let Some(name) = parameter.field("name")
                {
                    defaults.insert(name.text().into_owned(), value.lost());
                }
            }
        }
        Ok(defaults)
    }

    fn sequence<'tree, D: Doc>(
        &mut self,
        nodes: impl Iterator<Item = Node<'tree, D>>,
        env: &Env,
        depth: usize,
    ) -> Result<Flow, MatchError> {
        let mut flow = Flow::normal(env.clone());
        for node in nodes {
            let Some(mut incoming) = flow.normal.take() else {
                break;
            };
            flow.merge(self.visit(node, &mut incoming, depth + 1)?);
        }
        Ok(flow)
    }

    fn loop_flow<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Flow, MatchError> {
        if let Some(iterable) = node.field("right") {
            self.eval(&iterable, env, depth + 1)?;
        }
        let mut header = env.clone();
        let mut exits = Flow::default();
        let mut exhausted = loop {
            self.check(node, depth)?;
            let mut iteration = header.clone();
            if let Some(condition) = node.field("condition") {
                self.eval(&condition, &mut iteration, depth + 1)?;
            }
            // The condition also runs on the false exit. For a for-loop this
            // is the exhausted-iterator path, including zero iterations.
            let exhausted = iteration.clone();
            if let Some(target) = node.field("left") {
                self.assign(&target, Value::Unknown, &mut iteration, depth + 1)?;
            }
            let mut body = if let Some(body) = node.field("body") {
                self.visit(body, &mut iteration, depth + 1)?
            } else {
                Flow::normal(iteration)
            };
            if let Some(env) = body.breaks.take() {
                exits.add(Exit::Normal, env);
            }
            if let Some(env) = body.returns.take() {
                exits.add(Exit::Return, env);
            }
            if let Some(env) = body.raises.take() {
                exits.add(Exit::Raise, env);
            }
            // Only normal completion and continue reach the next iteration.
            // A break must never be overwritten by a later body statement.
            let mut next = header.clone();
            for backedge in [body.normal.take(), body.continues.take()]
                .into_iter()
                .flatten()
            {
                next = next.merge(&backedge);
            }
            if next == header {
                break exhausted;
            }
            header = next;
        };
        if let Some(alternative) = node.field("alternative") {
            exits.merge(self.visit(alternative, &mut exhausted, depth + 1)?);
        } else {
            exits.add(Exit::Normal, exhausted);
        }
        Ok(exits)
    }

    fn exceptional_prefix(&self, entry: &Env, body: &Flow) -> Env {
        // Any evaluated expression can raise before a later assignment. A
        // finalizer/handler therefore cannot inherit the normal end-state's
        // path proofs. Keep only dominating immutable imports when no path
        // through the protected suite has invalidated their identities.
        let mut exceptional = body
            .joined()
            .map_or_else(|| entry.clone(), |body| entry.merge(&body));
        exceptional.forget();
        if exceptional.trusted {
            for (name, value) in &entry.values {
                if self.immutable.get(name) == Some(value) && value.immutable_import() {
                    exceptional.values.insert(name.clone(), value.clone());
                }
            }
        }
        exceptional
    }

    fn finally_flow<D: Doc>(
        &mut self,
        mut incoming: Flow,
        finalizer: Node<'_, D>,
        depth: usize,
    ) -> Result<Flow, MatchError> {
        let Some(mut combined) = incoming.joined() else {
            return Ok(incoming);
        };
        // Scan once from a conservative join instead of multiplying visits
        // for every nested exit reason. Normal finalizer completion preserves
        // the original reason; an abrupt finalizer replaces it.
        let mut completed = self.visit(finalizer, &mut combined, depth + 1)?;
        if let Some(normal) = completed.normal.take() {
            for exit in EXITS {
                if incoming.slot(exit).take().is_some() {
                    completed.add(exit, normal.clone());
                }
            }
        }
        Ok(completed)
    }

    fn try_flow<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Flow, MatchError> {
        let entry = env.clone();
        let mut exits = if let Some(body) = node.field("body") {
            self.visit(body, env, depth + 1)?
        } else {
            Flow::normal(entry.clone())
        };
        let exceptional = self.exceptional_prefix(&entry, &exits);
        exits.raises = None;
        if let Some(mut normal) = exits.normal.take() {
            if let Some(alternative) = named(node).find(|child| child.kind() == "else_clause") {
                exits.merge(self.visit(alternative, &mut normal, depth + 1)?);
            } else {
                exits.add(Exit::Normal, normal);
            }
        }
        // Handler selection and implicit exception sites are deliberately
        // unresolved. Every handler may run; an exception may also escape.
        // None of those paths receives the protected suite's last assignment.
        exits.add(Exit::Raise, exceptional.clone());
        let mut handler_entry = exceptional;
        for handler in named(node).filter(|child| child.kind() == "except_clause") {
            let mut handler_env = handler_entry.clone();
            let handled = self.visit(handler, &mut handler_env, depth + 1)?;
            // Except* handlers can run sequentially. Even ordinary handlers
            // may evaluate an earlier type expression before selecting a
            // later handler. Neither may restore an invalidated identity.
            handler_entry = self.exceptional_prefix(&handler_entry, &handled);
            exits.merge(handled);
        }
        if let Some(finalizer) = named(node).find(|child| child.kind() == "finally_clause") {
            exits = self.finally_flow(exits, finalizer, depth + 1)?;
        }
        Ok(exits)
    }

    fn match_flow<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Flow, MatchError> {
        for subject in named(node).filter(|child| child.kind() != "block") {
            self.eval(&subject, env, depth + 1)?;
        }
        // Pattern dispatch can invoke user hooks, and a failed guard can
        // mutate shared modules before a later case. Unsupported matching
        // cannot preserve positive identities across those paths.
        self.invalidate(env);
        let base = env.clone();
        let mut exits = Flow::normal(base.clone());
        for block in named(node).filter(|child| child.kind() == "block") {
            for case in named(&block) {
                let mut branch = base.clone();
                exits.merge(self.visit(case, &mut branch, depth + 1)?);
            }
        }
        Ok(exits)
    }

    fn visit<D: Doc>(
        &mut self,
        node: Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Flow, MatchError> {
        self.check(&node, depth)?;
        let flow = self.visit_statement(node, env, depth)?;
        if let Some(normal) = &flow.normal {
            *env = normal.clone();
        }
        Ok(flow)
    }

    fn visit_statement<D: Doc>(
        &mut self,
        node: Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<Flow, MatchError> {
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
                let preserves = if let Some(body) = body {
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
                    visited?
                        .environments()
                        .all(|exit| exit.trusted && !exit.containers.performed)
                } else {
                    local.trusted
                };
                if let Some(name) = node.field("name") {
                    env.values.insert(
                        name.text().into_owned(),
                        if is_function {
                            Value::LocalFunction { preserves }
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
                let mut exits = Flow::default();
                if let Some(body) = node.field("consequence") {
                    let mut branch = base.clone();
                    exits.merge(self.visit(body, &mut branch, depth + 1)?);
                }
                let mut exhaustive = false;
                let mut fallthrough = base;
                for alternative in node.field_children("alternative") {
                    exhaustive |= alternative.kind() == "else_clause";
                    self.check(&alternative, depth + 1)?;
                    if let Some(condition) = alternative.field("condition") {
                        self.eval(&condition, &mut fallthrough, depth + 1)?;
                    }
                    let branch = fallthrough.clone();
                    exits.merge(self.sequence(
                        named(&alternative).filter(|child| child.kind() == "block"),
                        &branch,
                        depth + 1,
                    )?);
                }
                if !exhaustive {
                    exits.add(Exit::Normal, fallthrough);
                }
                return Ok(exits);
            }
            "for_statement" | "while_statement" => {
                return self.loop_flow(&node, env, depth);
            }
            "try_statement" => {
                return self.try_flow(&node, env, depth);
            }
            "match_statement" => {
                return self.match_flow(&node, env, depth);
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
                let mut exits = if let Some(body) = node.field("body") {
                    self.visit(body, env, depth + 1)?
                } else {
                    Flow::normal(env.clone())
                };
                for exit in exits.environments_mut() {
                    for value in exit.values.values_mut() {
                        let path = match &*value {
                            Value::Directory(path) => Some(path),
                            Value::Delete(call) => call.receiver.as_ref(),
                            _ => value.path(),
                        };
                        let expired_container = matches!(
                            &*value,
                            Value::Container(container)
                                | Value::ContainerMethod {
                                    receiver: container, ..
                                }
                                if !managed.is_empty()
                                    && (container.unknown_origins
                                        || container.origins.iter().any(|origin| managed.contains(origin)))
                        );
                        if expired_container
                            || path
                                .and_then(Path::origin)
                                .is_some_and(|origin| managed.contains(&origin))
                        {
                            *value = value.lost();
                        }
                    }
                    if opaque {
                        // __exit__ runs for normal and abrupt completion.
                        self.invalidate(exit);
                    }
                }
                if opaque && let Some(suppressed) = exits.raises.clone() {
                    // Only exceptions can be suppressed by __exit__.
                    exits.add(Exit::Normal, suppressed);
                }
                return Ok(exits);
            }
            "decorated_definition" => {
                // Applying the decorator happens before a deferred body can
                // run. Do not grant that body a pre-decoration factory proof.
                self.invalidate(env);
                let mut exits = self.sequence(named(&node), env, depth + 1)?;
                // Applying a decorator invokes arbitrary code even when its
                // source is just a name. The following statement cannot rely
                // on the preceding path or factory bindings.
                for exit in exits.environments_mut() {
                    self.invalidate(exit);
                }
                return Ok(exits);
            }
            "break_statement" | "continue_statement" | "return_statement" | "raise_statement" => {
                for child in named(&node) {
                    let value = self.eval(&child, env, depth + 1)?;
                    if node.kind() == "raise_statement"
                        && child.kind() != "call"
                        && value == Value::Unknown
                    {
                        // Raising a class constructs it even without a call
                        // expression. An unknown exception can run code.
                        self.invalidate(env);
                    }
                }
                let exit = match node.kind().as_ref() {
                    "break_statement" => Exit::Break,
                    "continue_statement" => Exit::Continue,
                    "return_statement" => Exit::Return,
                    _ => Exit::Raise,
                };
                let mut exits = Flow::default();
                exits.add(exit, env.clone());
                return Ok(exits);
            }
            "delete_statement" => {
                for target in named(&node) {
                    self.assign(&target, Value::Unknown, env, depth + 1)?;
                }
            }
            "module" | "block" | "else_clause" | "elif_clause" | "finally_clause"
            | "except_clause" | "case_clause" => {
                if let Some(alias) = node.field("alias") {
                    self.assign(&alias, Value::Unknown, env, depth + 1)?;
                }
                return self.sequence(named(&node), env, depth + 1);
            }
            _ => {
                self.eval(&node, env, depth + 1)?;
            }
        }
        Ok(Flow::normal(env.clone()))
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
            "list" | "tuple" | "expression_list" | "dictionary" => {
                self.container(node, depth + 1, |scan, child, depth| {
                    scan.eval(child, env, depth)
                })?
            }
            "subscript" => {
                let (object, key, slice) =
                    self.subscription(node, depth + 1, |scan, child, depth| {
                        scan.eval(child, env, depth)
                    })?;
                env.select(object, key, slice)
            }
            "list_splat" | "dictionary_splat" => {
                let mut possible = Capabilities::default();
                for child in named(node) {
                    let value = self.eval(&child, env, depth + 1)?;
                    possible = possible.union(env.container_capabilities(&value));
                }
                // Expansion still has uncertain arity/keys. Preserve only
                // possible values so it cannot erase a stored callback.
                Value::possible(possible.selected())
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
                let path_operator = matches!(operator.as_str(), "+" | "/");
                let inert_result =
                    path_operator && left.inert_conversion() && right.inert_conversion();
                if path_operator && (!left.inert_binary_operand() || !right.inert_binary_operand())
                {
                    // Overloaded operators and pathlib's path conversion can
                    // run user code. An unresolved result cannot preserve
                    // trusted factory or receiver identities afterward.
                    self.invalidate(env);
                }
                let unresolved = if inert_result {
                    Value::Inert
                } else {
                    Value::Unknown
                };
                match (operator.as_str(), left, right) {
                    ("/", Value::Path(left), right) => right
                        .path()
                        .and_then(|right| left.join(right))
                        .map_or(unresolved, Value::Path),
                    ("+", Value::Text(Path::Literal(left)), Value::Text(Path::Literal(right)))
                        if left.len() + right.len() <= MAX_VALUE_BYTES =>
                    {
                        Value::Text(Path::Literal(format!("{left}{right}").into()))
                    }
                    _ => unresolved,
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
                self.comprehension(node, env, depth + 1)?;
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

    fn comprehension<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        env: &mut Env,
        depth: usize,
    ) -> Result<(), MatchError> {
        self.check(node, depth)?;
        let clauses: Vec<_> = named(node)
            .filter(|child| matches!(child.kind().as_ref(), "for_in_clause" | "if_clause"))
            .collect();
        let first = clauses
            .iter()
            .position(|clause| clause.kind() == "for_in_clause");
        let mut targets = HashSet::new();
        for clause in &clauses {
            if let Some(left) = clause.field("left") {
                self.names(&left, &mut targets, depth + 1)?;
            }
        }
        // Python evaluates the leftmost iterable immediately in the enclosing
        // scope, even for a generator. Later iterables execute in its body.
        if let Some(first) = first {
            for right in clauses[first].field_children("right") {
                self.eval(&right, env, depth + 1)?;
            }
        }
        let deferred = node.kind() == "generator_expression";
        let mut entry = if deferred {
            self.deferred(env)
        } else {
            env.clone()
        };
        if deferred {
            self.deferred_depth += 1;
        }
        let visited: Result<(), MatchError> = (|| {
            loop {
                self.check(node, depth)?;
                let mut iteration = entry.clone();
                let mut skipped = entry.clone();
                for (index, clause) in clauses.iter().enumerate() {
                    self.check(clause, depth + 1)?;
                    if clause.kind() == "for_in_clause" {
                        if Some(index) != first {
                            for right in clause.field_children("right") {
                                self.eval(&right, &mut iteration, depth + 1)?;
                            }
                        }
                        // An inner iterator can be empty. Effects before it
                        // still reach the next outer iteration.
                        skipped = skipped.merge(&iteration);
                        if let Some(left) = clause.field("left") {
                            self.assign(&left, Value::Unknown, &mut iteration, depth + 1)?;
                        }
                    } else {
                        self.eval(clause, &mut iteration, depth + 1)?;
                        // A false filter skips the body without undoing a
                        // walrus assignment or another condition side effect.
                        skipped = skipped.merge(&iteration);
                    }
                }
                if let Some(body) = node.field("body") {
                    self.eval(&body, &mut iteration, depth + 1)?;
                }
                let merged = entry.merge(&skipped).merge(&iteration);
                if merged == entry {
                    break;
                }
                entry = merged;
            }
            Ok(())
        })();
        if deferred {
            self.deferred_depth -= 1;
        }
        visited?;
        if deferred {
            // A generator may later change its enclosing walrus bindings.
            // Its iteration variables remain local, and its body has not run.
            self.walrus_locals(node, env, depth + 1)?;
        } else {
            // Eager comprehensions execute now. Preserve their effects while
            // keeping iteration targets out of the enclosing namespace.
            env.trusted &= entry.trusted;
            env.containers = env.containers.merge(&entry.containers);
            for (name, value) in entry.values {
                if !targets.contains(&name) {
                    env.values.insert(name, value);
                }
            }
        }
        Ok(())
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

    fn container_call<D: Doc>(
        &mut self,
        node: &Node<'_, D>,
        receiver: Arc<Container>,
        operation: ContainerOp,
        args: &Args,
        env: &mut Env,
        depth: usize,
    ) -> Result<Value, MatchError> {
        self.check(node, depth)?;
        let plain = !args.uncertain && args.keywords.is_empty();
        if operation.selects() {
            let valid = plain
                && if receiver.sequence {
                    args.positional.len() <= 1
                } else {
                    (1..=2).contains(&args.positional.len())
                };
            let mut key = args.positional.first().and_then(value_key);
            if key.is_none() {
                key = node
                    .field("arguments")
                    .and_then(|arguments| named(&arguments).next())
                    .and_then(|argument| container_key(&argument));
            }
            if receiver.sequence && args.positional.is_empty() {
                key = Some(ContainerKey::Integer(-1));
            }
            let passive_key = args.positional.first().is_none_or(passive_container_key);
            if !valid || !passive_key || !receiver.precise {
                // Unknown indexing/hash/equality hooks can mutate bindings or
                // the receiver before a lookup returns. Arguments have already
                // run, so a mutation in a default cannot reuse the old slot.
                self.invalidate(env);
            }
            let default = if receiver.sequence {
                Value::None
            } else {
                args.positional.get(1).cloned().unwrap_or(Value::None)
            };
            let result = if valid
                && passive_key
                && env.exact_container(&receiver)
                && let Some(key) = key
            {
                container_entry(&receiver, key).map_or_else(|| default.captured(), Value::captured)
            } else {
                let possible = env
                    .container_capabilities(&Value::Container(receiver.clone()))
                    .selected();
                Value::possible(possible).merge(&default.indirect())
            };
            if operation == ContainerOp::Pop {
                // Return the selected immutable callback first. Every later
                // selector, including captured methods, sees this mutation.
                env.containers
                    .mark(Some(receiver.source), Capabilities::default());
            }
            return Ok(result);
        }

        let valid = !args.uncertain
            && if operation == ContainerOp::Update {
                args.positional.len() <= 1
            } else {
                args.keywords.is_empty() && args.positional.len() == 1
            };
        let passive = match operation {
            ContainerOp::Append => valid,
            ContainerOp::Extend => {
                valid
                    && args.positional.first().is_some_and(|value| {
                        matches!(value, Value::Container(source) if env.exact_container(source))
                    })
            }
            ContainerOp::Update => {
                valid
                    && env.exact_container(&receiver)
                    && args.positional.first().is_none_or(|value| {
                        matches!(value, Value::Container(source)
                            if !source.sequence && env.exact_container(source))
                    })
            }
            ContainerOp::Get | ContainerOp::Pop => unreachable!("selectors returned above"),
        };
        let added = mutation_arguments(operation.capability(), args);
        env.containers.mark(Some(receiver.source), added);
        if !passive {
            self.invalidate(env);
        }
        Ok(Value::None)
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
        let conversion = matches!(
            &function,
            Value::Symbol(Symbol::PathClass | Symbol::Str | Symbol::Join) | Value::Join(_)
        );
        let inert_conversion = conversion && args.positional.iter().all(Value::inert_conversion);
        if conversion && !inert_conversion {
            // Familiar constructors can dispatch unknown __fspath__/__str__
            // hooks. Losing the result's path proof must also lose the
            // identities that such hooks may have changed. Pure operands
            // retain trust even when a literal join cannot be resolved.
            self.invalidate(env);
        }
        let unresolved_conversion = if inert_conversion {
            Value::Inert
        } else {
            Value::Unknown
        };
        let value = match function {
            Value::ContainerMethod {
                receiver,
                operation,
            } => self.container_call(node, receiver, operation, &args, env, depth + 1)?,
            Value::Possible(possible) => {
                if possible.direct & MAY_SELECT != 0 && possible.returned_overflow {
                    return Err(MatchError::Unavailable {
                        language: ScriptLanguage::Python,
                        detail:
                            "Python container selector analysis exhausted its return-depth limit"
                                .to_string(),
                    });
                }
                let kinds = u8::try_from(possible.direct & DELETE_KINDS).unwrap_or_default();
                if kinds != 0 {
                    self.record(node, kinds, false);
                }
                let mut result = if possible.direct & MAY_GETATTR != 0 {
                    reflected_arguments(&args)
                } else {
                    Value::Unknown
                };
                if possible.direct & MAY_SELECT != 0 {
                    let returned = env
                        .container_capabilities(&Value::Possible(possible))
                        .called();
                    result = result.merge(&Value::possible(returned));
                    if let Some(default) = args.positional.get(1) {
                        result = result.merge(&default.indirect());
                    }
                }
                if possible.direct & MAY_MUTATE != 0 {
                    let added = mutation_arguments(possible.direct, &args);
                    env.containers.mark(None, added);
                }
                self.invalidate(env);
                result
            }
            Value::Symbol(Symbol::Getattr) => {
                if env.trusted
                    && let Some(captured) = trusted_reflected_arguments(&args)
                {
                    captured
                } else {
                    let result = reflected_arguments(&args);
                    self.invalidate(env);
                    result
                }
            }
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
                fold_paths(&args.positional).map_or(unresolved_conversion, Value::Path)
            }
            Value::Symbol(Symbol::Str) if plain && args.positional.len() == 1 => args.positional[0]
                .path()
                .cloned()
                .map_or(unresolved_conversion, Value::Text),
            Value::Symbol(Symbol::Join) if plain && !args.positional.is_empty() => {
                fold_paths(&args.positional).map_or(unresolved_conversion, Value::Text)
            }
            Value::Join(base) if plain => {
                let mut values = vec![Value::Path(base)];
                values.extend(args.positional);
                fold_paths(&values).map_or(unresolved_conversion, Value::Path)
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
                (None, "builtins") => Value::Symbol(Symbol::Builtins),
                (Some("builtins"), "getattr") => Value::Symbol(Symbol::Getattr),
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

fn note_origins(container: &mut Container, value: &Value) {
    let (origins, unknown): (&[usize], bool) = match value {
        Value::Container(nested) => {
            container.depth = container.depth.max(nested.depth + 1);
            (&nested.origins, nested.unknown_origins)
        }
        Value::ContainerMethod {
            receiver: nested, ..
        } => {
            container.depth = container.depth.max(nested.depth + 2);
            (&nested.origins, nested.unknown_origins)
        }
        Value::Delete(call) => {
            if let Some(origin) = call.receiver.as_ref().and_then(Path::origin) {
                if !container.origins.contains(&origin) {
                    if container.origins.len() < MAX_CONTAINER_ITEMS {
                        container.origins.push(origin);
                    } else {
                        container.unknown_origins = true;
                    }
                }
            }
            return;
        }
        _ => return,
    };
    container.unknown_origins |= unknown;
    for origin in origins {
        if !container.origins.contains(origin) {
            if container.origins.len() < MAX_CONTAINER_ITEMS {
                container.origins.push(*origin);
            } else {
                container.unknown_origins = true;
            }
        }
    }
}

fn trusted_reflected_arguments(args: &Args) -> Option<Value> {
    if args.uncertain || !args.keywords.is_empty() || !(2..=3).contains(&args.positional.len()) {
        return None;
    }
    let Value::Text(Path::Literal(member)) = &args.positional[1] else {
        return None;
    };
    let object = &args.positional[0];
    if !matches!(
        (object, member.as_ref()),
        (Value::Path(_), "unlink" | "rmdir")
            | (Value::Symbol(Symbol::Os), "unlink" | "remove" | "rmdir")
    ) {
        return None;
    }
    Some(attribute(object.clone(), member))
}

fn destructuring(kind: &str) -> bool {
    matches!(
        kind,
        "tuple_pattern" | "list_pattern" | "pattern_list" | "tuple" | "list" | "expression_list"
    )
}

fn container_key<D: Doc>(node: &Node<'_, D>) -> Option<ContainerKey> {
    if node.text().len() > MAX_KEY_BYTES {
        return None;
    }
    match node.kind().as_ref() {
        "integer" | "unary_operator" => node
            .text()
            .replace('_', "")
            .parse::<i64>()
            .ok()
            .map(ContainerKey::Integer),
        "true" => Some(ContainerKey::Integer(1)),
        "false" => Some(ContainerKey::Integer(0)),
        "string" | "concatenated_string" => {
            super::super::static_interpreter_literal(node, ScriptLanguage::Python, 0)
                .map(|text| ContainerKey::Text(text.into()))
        }
        _ => None,
    }
}

fn container_entry(container: &Container, mut key: ContainerKey) -> Option<&Value> {
    if container.sequence
        && let ContainerKey::Integer(index) = key
        && index < 0
    {
        let length = i64::try_from(container.entries.len()).ok()?;
        key = ContainerKey::Integer(length.checked_add(index)?);
    }
    container
        .entries
        .iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, value)| value)
}

fn selected(object: Value, key: Option<ContainerKey>, slice: bool) -> Value {
    let possible = object.capabilities();
    if slice {
        return Value::possible(Capabilities {
            direct: possible.direct & MAY_CONTAINER,
            ..possible
        });
    }
    if let Value::Container(container) = &object
        && container.precise
        && let Some(key) = key
    {
        return container_entry(container, key).map_or(Value::Unknown, Value::captured);
    }
    Value::possible(possible.selected())
}

fn value_key(value: &Value) -> Option<ContainerKey> {
    match value {
        Value::Text(Path::Literal(text)) if text.len() <= MAX_KEY_BYTES => {
            Some(ContainerKey::Text(text.clone()))
        }
        _ => None,
    }
}

fn passive_container_key(value: &Value) -> bool {
    matches!(
        value,
        Value::Scalar | Value::None | Value::Text(Path::Literal(_))
    )
}

fn container_operation(value: &Value, member: &str) -> Option<ContainerOp> {
    let (list, dictionary) = match value {
        Value::Container(container) => (container.mutable_sequence, !container.sequence),
        Value::Possible(possible) => (
            possible.direct & MAY_LIST != 0 || possible.contained != 0,
            possible.direct & MAY_DICT != 0 || possible.contained != 0,
        ),
        _ => return None,
    };
    match member {
        "get" if dictionary => Some(ContainerOp::Get),
        "pop" if list || dictionary => Some(ContainerOp::Pop),
        "append" if list => Some(ContainerOp::Append),
        "extend" if list => Some(ContainerOp::Extend),
        "update" if dictionary => Some(ContainerOp::Update),
        _ => None,
    }
}

fn mutation_arguments(methods: u16, args: &Args) -> Capabilities {
    let mut added = Capabilities::default();
    for value in &args.positional {
        let possible = value.capabilities();
        if methods & MAY_APPEND != 0 {
            added = added.union(possible);
        }
        if methods & (MAY_EXTEND | MAY_UPDATE) != 0 {
            added = added.union(possible.selected());
        }
    }
    if methods & MAY_UPDATE != 0 {
        for value in args.keywords.values() {
            added = added.union(value.capabilities());
        }
    }
    added
}

fn reflected(object: Value, member: Option<&str>, default: Value) -> Value {
    let found = member.map_or(Value::Unknown, |member| attribute(object, member).lost());
    found.merge(&default.indirect())
}

fn reflected_arguments(args: &Args) -> Value {
    if args.uncertain || !args.keywords.is_empty() || !(2..=3).contains(&args.positional.len()) {
        return Value::Unknown;
    }
    let member = match &args.positional[1] {
        Value::Text(Path::Literal(member)) => Some(member.as_ref()),
        _ => None,
    };
    reflected(
        args.positional[0].clone(),
        member,
        args.positional.get(2).cloned().unwrap_or_default(),
    )
}

fn attribute(object: Value, member: &str) -> Value {
    if let Some(operation) = container_operation(&object, member) {
        return if let Value::Container(receiver) = object {
            Value::ContainerMethod {
                receiver,
                operation,
            }
        } else {
            Value::possible(object.capabilities().selector(operation))
        };
    }
    match (&object, member) {
        (Value::Symbol(Symbol::Os), "unlink" | "remove" | "rmdir") => {
            let kind = match member {
                "unlink" => OS_UNLINK,
                "remove" => OS_REMOVE,
                _ => OS_RMDIR,
            };
            deletion(kind, None, false, true)
        }
        (Value::Possible(possible), "unlink" | "remove" | "rmdir")
            if possible.direct & MAY_OS != 0 =>
        {
            let kind = match member {
                "unlink" => OS_UNLINK,
                "remove" => OS_REMOVE,
                _ => OS_RMDIR,
            };
            deletion(kind, None, false, false)
        }
        (Value::Symbol(Symbol::Builtins), "getattr") => Value::Symbol(Symbol::Getattr),
        (Value::Possible(possible), "getattr") if possible.direct & MAY_BUILTINS != 0 => {
            Value::Symbol(Symbol::Getattr).lost()
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

    fn assert_blocked(source: &str, expected: bool) {
        let matcher = super::super::AstMatcher::with_patterns(super::super::default_patterns());
        let matches = matcher
            .find_matches(source, ScriptLanguage::Python)
            .expect("valid Python must complete bounded analysis");
        assert_eq!(
            matches.iter().any(|hit| hit.severity.blocks_by_default()),
            expected,
            "source: {source}\nfindings: {matches:?}"
        );
    }

    #[test]
    fn unresolved_conversions_revoke_temporary_receiver_proofs() {
        for operation in [
            "Path(value)",
            "str(value)",
            "os.fspath(value)",
            "os.path.join('/tmp', value)",
            "p.joinpath(value)",
            "p / value",
            "value + 1",
            "1 / value",
        ] {
            let source = format!(
                "import os, tempfile\nfrom pathlib import Path\nfrom helpers import value\np = Path(tempfile.mkdtemp()) / 'child'\n{operation}\np.unlink()",
            );
            assert_blocked(&source, true);
        }
    }

    #[test]
    fn known_conversions_preserve_temporary_receiver_proofs() {
        assert_blocked(
            "import os, tempfile\nfrom pathlib import Path\np = Path(tempfile.mkdtemp()) / 'child'\nPath('/tmp')\nstr(p)\nos.fspath(p)\nos.path.join('/tmp', 'child')\np.joinpath('sibling')\nos.path.join('/tmp', '..')\np.joinpath('..')\nstr(42)\nPath(str(42))\nstr(1 + 2)\nstr(p.joinpath('..'))\nstr(None)\nstr([42][0])\nstr(['literal'][0])\nstr([Path('/tmp/other')][0])\n['a'] + ['b']\n'a' + 'b'\n1 + 2\n1 / 2\np.unlink()",
            false,
        );
    }

    #[test]
    fn non_deletion_slots_do_not_prove_conversion_is_inert() {
        assert_blocked(
            "import tempfile\nfrom pathlib import Path\nfrom helpers import value\np = Path(tempfile.mkdtemp()) / 'child'\nwrapped = [[value]]\nstr(wrapped[0])\np.unlink()",
            true,
        );
    }

    #[test]
    fn coercions_without_deletion_invocations_stay_nonblocking() {
        assert_blocked(
            "from pathlib import Path\nfrom helpers import value\nunused = Path('/etc/hosts').unlink\nPath(value)\nstr(value)",
            false,
        );
    }

    #[test]
    fn unknown_conversion_revokes_deferred_receiver_proofs() {
        assert_blocked(
            "import tempfile\nfrom pathlib import Path\nfrom helpers import value\ndef cleanup():\n    p = Path(tempfile.mkdtemp()) / 'child'\n    p.unlink()\nPath(value)\ncleanup()",
            true,
        );
    }

    #[test]
    fn container_selectors_require_the_selected_callback_to_be_invoked() {
        let prefix = "from pathlib import Path\np = Path('/etc/hosts')\n";
        for suffix in [
            "actions = {'erase': p.unlink}\nactions.get('erase')",
            "actions = [p.unlink]\nactions.pop()",
            "actions = {'erase': p.unlink}\nouter = {'step': actions.get}\nouter.get('step')('erase')",
        ] {
            assert_blocked(&format!("{prefix}{suffix}"), false);
            assert_blocked(&format!("{prefix}{suffix}()"), true);
        }
        assert_blocked(
            &format!("{prefix}actions = {{'show': print}}\nactions.get('show', p.unlink)('ok')"),
            false,
        );
    }

    #[test]
    fn container_stores_retain_callbacks_through_aliases_and_helpers() {
        let prefix = "from pathlib import Path\np = Path('/etc/hosts')\n";
        for suffix in [
            "actions = []\nactions.append(p.unlink)\nactions[0]()",
            "actions = []\nactions.extend([p.unlink])\nactions[0]()",
            "actions = {}\nactions.update({'erase': p.unlink})\nactions['erase']()",
            "actions = {}\ninsert = actions.update\ninsert(erase=p.unlink)\nactions.get('erase')()",
            "actions = []\ninsert = actions.append\nrelay = insert\nrelay(p.unlink)\nactions.pop()()",
            "inner = []\nouter = [inner]\nalias = inner\nalias.append(p.unlink)\nouter[0][0]()",
            "actions = []\ninsert = actions.append\ndef populate():\n    insert(p.unlink)\npopulate()\nactions.pop()()",
            "actions = []\nqueue = {'put': actions.append}\ndef populate():\n    queue.get('put')(p.unlink)\npopulate()\nactions[0]()",
            "actions = []\n(put,) = [actions.append]\ndef populate():\n    put(p.unlink)\npopulate()\nactions[0]()",
            "actions = []\nother = []\nput = other.append\n(put,) = [actions.append]\ndef populate():\n    put(p.unlink)\npopulate()\nactions[0]()",
            "actions = []\nactions.append(*[p.unlink])\nactions[0]()",
            "actions = {}\nactions.update(**{'erase': p.unlink})\nactions.get('erase')()",
        ] {
            assert_blocked(&format!("{prefix}{suffix}"), true);
        }
        for suffix in [
            "actions = []\nactions.append(p.unlink)",
            "actions = {}\nactions.update(erase=p.unlink)",
            "actions = []\nactions.append(*[p.unlink])",
            "actions = {}\nactions.update(**{'erase': p.unlink})",
            "pending = p.unlink\nitems = [1, 2]\nitems.remove(1)\nitems.append(3)\nitems.extend([4, 5])\nitems.pop()",
        ] {
            assert_blocked(&format!("{prefix}{suffix}"), false);
        }
    }

    #[test]
    fn container_mutations_revoke_all_aliases_of_the_old_snapshot() {
        let prefix =
            "from pathlib import Path\nsafe = Path('/tmp/child')\np = Path('/etc/hosts')\n";
        for suffix in [
            "actions = [safe.unlink, p.unlink]\nactions.pop(0)()\nactions.pop(0)()",
            "actions = [safe.unlink, p.unlink]\nextract = actions.pop\nextract(0)()\nactions[0]()",
            "actions = [print, p.unlink]\nactions.pop(0)\n(erase,) = actions\nerase()",
            "actions = [print]\n[actions.append(p.unlink) for _ in [0]]\nactions[-1]()",
            "actions = [print]\nif choice:\n    actions.append(p.unlink)\nactions[-1]()",
            "actions = {'erase': print}\nlookup = actions.get\nlookup('erase', actions.update({'erase': p.unlink}))()",
        ] {
            assert_blocked(&format!("{prefix}{suffix}"), true);
        }
        assert_blocked(
            &format!("{prefix}actions = [safe.unlink, p.unlink]\nfirst = actions.pop(0)\nfirst()"),
            false,
        );
    }

    #[test]
    fn temporary_container_callbacks_keep_only_live_scoped_proofs() {
        let prefix =
            "import tempfile\nfrom pathlib import Path\np = Path(tempfile.mkdtemp()) / 'child'\n";
        for suffix in [
            "actions = {'erase': p.unlink}\nactions.get('erase')()",
            "actions = [p.unlink]\nactions.pop()()",
            "actions = [p.unlink]\ndef unused():\n    actions.append(Path('/etc/hosts').unlink)\nactions.pop()()",
            "actions = []\ngenerator = (actions.append(Path('/etc/hosts').unlink) for _ in [0])\np.unlink()",
        ] {
            assert_blocked(&format!("{prefix}{suffix}"), false);
        }
        assert_blocked(
            "import tempfile\nfrom pathlib import Path\nwith tempfile.TemporaryDirectory() as temp:\n    actions = {'erase': (Path(temp) / 'child').unlink}\n    lookup = actions.get\n    lookup('erase')()",
            false,
        );
        assert_blocked(
            "import tempfile\nfrom pathlib import Path\nwith tempfile.TemporaryDirectory() as temp:\n    actions = [(Path(temp) / 'child').unlink]\n    extract = actions.pop\nextract()()",
            true,
        );
        assert_blocked(
            &format!(
                "{prefix}from helpers import key\nactions = {{}}\nactions.get(key)\np.unlink()"
            ),
            true,
        );
        assert_blocked(
            "from helpers import value\nimport tempfile\nfrom pathlib import Path\nactions = {value: print}\np = Path(tempfile.mkdtemp()) / 'child'\nactions.update({'known': print})\np.unlink()",
            true,
        );
    }

    #[test]
    fn excessive_selector_depth_is_incomplete_only_when_invoked() {
        let mut source = String::from(
            "from pathlib import Path\np = Path('/etc/hosts')\nactions = {'step': p.unlink}\n",
        );
        for _ in 0..=MAX_CONTAINER_DEPTH {
            source.push_str("actions = {'step': actions.get}\n");
        }
        source.push_str("lookup = actions.get\n");
        assert_blocked(&source, false);
        source.push_str("lookup('step')\n");
        let matcher = super::super::AstMatcher::with_patterns(super::super::default_patterns());
        assert!(matches!(
            matcher.find_matches(&source, ScriptLanguage::Python),
            Err(MatchError::Unavailable { detail, .. })
                if detail.contains("selector") && detail.contains("return-depth")
        ));
    }

    #[test]
    fn shared_container_graphs_keep_bounded_deletion_summaries() {
        let mut source = String::from(
            "from pathlib import Path\np = Path('/etc/hosts')\na = [p.unlink]\nb = [p.unlink]\n",
        );
        // The source remains linear although a recursive comparison of the
        // two independently shared value graphs would expand exponentially.
        for _ in 0..32 {
            source.push_str("a = [a, a]\nb = [b, b]\n");
        }
        source.push_str("if choice:\n    selected = a\nelse:\n    selected = b\nselected");
        for _ in 0..33 {
            source.push_str("[0]");
        }
        source.push_str("()\n");
        assert_blocked(&source, true);
    }

    #[test]
    fn break_exits_ignore_unreachable_assignments_and_loop_else() {
        assert_blocked(
            "from pathlib import Path\np = Path('/tmp/first')\nfor i in (0,):\n    p = Path('/etc/hosts')\n    break\n    p = Path('/tmp/first')\nelse:\n    p = Path('/tmp/first')\np.unlink()",
            true,
        );
    }

    #[test]
    fn continue_carries_unsafe_paths_to_the_next_iteration() {
        assert_blocked(
            "from pathlib import Path\np = Path('/tmp/first')\nfor i in (0, 1):\n    p.unlink(missing_ok=True)\n    p = Path('/etc/hosts')\n    continue\n    p = Path('/tmp/first')",
            true,
        );
    }

    #[test]
    fn finally_runs_on_implicit_exceptions_and_returns() {
        assert_blocked(
            "from pathlib import Path\np = Path('/etc/hosts')\ntry:\n    Path('/tmp/missing').read_text()\n    p = Path('/tmp/safe')\nfinally:\n    p.unlink()",
            true,
        );
        assert_blocked(
            "def cleanup():\n    from pathlib import Path\n    p = Path('/etc/hosts')\n    try:\n        return\n    finally:\n        p.unlink()\ncleanup()",
            true,
        );
    }

    #[test]
    fn finally_can_repair_paths_or_replace_pending_breaks() {
        assert_blocked(
            "from pathlib import Path\np = Path('/tmp/first')\nfor i in (0,):\n    try:\n        p = Path('/etc/hosts')\n        break\n    finally:\n        p = Path('/tmp/first')\np.unlink(missing_ok=True)",
            false,
        );
        assert_blocked(
            "def cleanup():\n    from pathlib import Path\n    p = Path('/tmp/first')\n    for i in (0,):\n        try:\n            p = Path('/etc/hosts')\n            break\n        finally:\n            return\n    p.unlink(missing_ok=True)\ncleanup()",
            false,
        );
    }

    #[test]
    fn temporary_context_ownership_is_revoked_on_break() {
        assert_blocked(
            "import tempfile\nfrom pathlib import Path\nfor i in (0,):\n    with tempfile.TemporaryDirectory() as directory:\n        p = Path(directory) / 'child'\n        break\np.unlink()",
            true,
        );
    }

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

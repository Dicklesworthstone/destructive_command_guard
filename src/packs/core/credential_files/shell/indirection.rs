//! Positive destination evidence from same-command scalars and Git queries.
//!
//! This view only adds findings to the native path policy. It never grants a
//! safe-path exemption, executes shell source, reads Git configuration, or
//! reparses expanded data as shell syntax. Unknown values lose their proof.

use super::super::word_splitting;
use super::{CredentialFileWrite, Token, Word, classify_simple_command, git_redirect_write};
use crate::normalize::ShellDialect;
use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::collections::HashMap;
use std::ops::Range;

mod git_paths;

const MAX_BYTES: usize = 64 * 1024;
const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_BINDINGS: usize = 64;
const MAX_NODES: usize = 4096;
const MAX_DEPTH: usize = 32;
const MAX_TOKENS: usize = 128;
const MAX_MATERIALIZED_BYTES: usize = 64 * 1024;

/// Provenance is separate from bytes. In particular, the literal value
/// `'$(git rev-parse --git-dir)'` can never acquire a Git origin on expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Literal(String),
    Home {
        prefix: String,
        root: String,
        tail: String,
    },
    Git {
        prefix: String,
        path: git_paths::GitPath,
    },
}

impl Value {
    fn append(self, next: Self) -> Option<Self> {
        match (self, next) {
            (Self::Literal(mut before), Self::Literal(after)) => {
                before.push_str(&after);
                (before.len() <= MAX_VALUE_BYTES).then_some(Self::Literal(before))
            }
            (
                Self::Home {
                    prefix,
                    root,
                    mut tail,
                },
                Self::Literal(after),
            ) => {
                if tail.is_empty() && !after.is_empty() && !after.starts_with('/') {
                    return None;
                }
                tail.push_str(&after);
                (prefix.len() + root.len() + tail.len() <= MAX_VALUE_BYTES).then_some(Self::Home {
                    prefix,
                    root,
                    tail,
                })
            }
            (Self::Git { prefix, path }, Self::Literal(after)) => Some(Self::Git {
                prefix,
                path: path.append_literal(&after)?,
            }),
            (Self::Literal(before), Self::Home { prefix, root, tail }) => Some(Self::Home {
                prefix: before + &prefix,
                root,
                tail,
            }),
            (Self::Literal(before), Self::Git { prefix, path }) => Some(Self::Git {
                prefix: before + &prefix,
                path,
            }),
            // Two independently expanded roots do not prove a path.
            _ => None,
        }
    }

    fn word(&self, range: Range<usize>) -> Option<Word> {
        let (text, literal) = match self {
            Self::Literal(value) => {
                let text: Vec<char> = value.chars().collect();
                let literal = vec![true; text.len()];
                (text, literal)
            }
            Self::Home { prefix, root, tail } => {
                if !path_prefix(prefix) {
                    return None;
                }
                let (home, end) = super::read_word(root, 0);
                if end != root.len() {
                    return None;
                }
                let mut text: Vec<char> = prefix.chars().collect();
                let mut literal = vec![true; text.len()];
                text.extend(home.text);
                literal.extend(home.literal);
                text.extend(tail.chars());
                literal.resize(text.len(), true);
                (text, literal)
            }
            Self::Git { prefix, path } => {
                if !path_prefix(prefix) {
                    return None;
                }
                let text: Vec<char> = (prefix.clone() + &path.policy_path()).chars().collect();
                let literal = vec![true; text.len()];
                (text, literal)
            }
        };
        (text.len() <= MAX_VALUE_BYTES).then_some(Word {
            text,
            literal,
            range,
            glued_paren: false,
        })
    }

    fn literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Home { .. } | Self::Git { .. } => None,
        }
    }

    fn one_unquoted_field(&self, state: &State) -> bool {
        let Some(ifs) = state.ifs.as_deref() else {
            return false;
        };
        let Some(word) = self.word(0..0) else {
            return false;
        };
        // Default splitting is a possible reading of a fresh shell. This is
        // positive denial evidence only, never a claim that an unknown caller
        // environment makes an operand safe. Observed IFS changes are honored.
        !word.text.is_empty()
            && !word
                .text
                .iter()
                .any(|ch| ifs.contains(*ch) || matches!(ch, '*' | '?' | '[' | '('))
    }
}

/// The native writer parser removes these option/operand prefixes before
/// judging a path. An arbitrary prefix before a symbolic root is not a proof:
/// `backup/$(git rev-parse --git-dir)` need not address Git's directory.
fn path_prefix(prefix: &str) -> bool {
    matches!(
        prefix,
        "" | "of=" | "-t" | "--target-directory=" | "-C" | "--directory=" | "-o"
    )
}

#[derive(Clone)]
struct State {
    values: HashMap<String, Value>,
    ifs: Option<String>,
    attributes_unknown: bool,
    commands_unknown: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            values: HashMap::new(),
            ifs: Some(" \t\n".to_owned()),
            attributes_unknown: false,
            commands_unknown: false,
        }
    }
}

impl State {
    fn forget(&mut self) {
        self.values.clear();
        self.ifs = None;
    }

    fn intersect(&mut self, other: &Self) {
        self.values
            .retain(|name, value| other.values.get(name) == Some(value));
        if self.ifs != other.ifs {
            self.ifs = None;
        }
        self.attributes_unknown |= other.attributes_unknown;
        self.commands_unknown |= other.commands_unknown;
    }

    fn assign(&mut self, raw: &str, incoming: &Self) {
        let Some((name, append, rhs)) = word_splitting::assignment(raw) else {
            self.forget();
            self.attributes_unknown = true;
            return;
        };
        let value = if self.attributes_unknown || word_splitting::maintained_variable(name) {
            None
        } else {
            decode(rhs, incoming, true).and_then(|decoded| {
                if append {
                    incoming.values.get(name)?.clone().append(decoded.value)
                } else {
                    Some(decoded.value)
                }
            })
        };
        if name == "IFS" {
            self.ifs = value.as_ref().and_then(Value::literal).map(str::to_owned);
        }
        if let Some(value) = value {
            if self.values.len() >= MAX_BINDINGS && !self.values.contains_key(name) {
                self.values.clear();
            }
            self.values.insert(name.to_owned(), value);
        } else {
            self.values.remove(name);
        }
    }
}

struct Decoded {
    value: Value,
    expanded: bool,
}

/// Decode a single scalar, retaining quoted data and expansion-time origins.
/// Only simple parameter reads and recognized one-result Git queries qualify.
/// Arithmetic, parameter operators, arrays, globs and unknown substitutions
/// never establish a new value. Assignment RHSs do not undergo field splitting.
fn decode(raw: &str, state: &State, assignment: bool) -> Option<Decoded> {
    if raw.len() > MAX_VALUE_BYTES || raw.contains('\0') {
        return None;
    }
    let mut value = Value::Literal(String::new());
    let mut chunk = String::new();
    let mut quote = None;
    let mut index = 0;
    let mut expanded = false;
    while index < raw.len() {
        let ch = raw[index..].chars().next()?;
        let here = index;
        index += ch.len_utf8();
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => chunk.push(ch),
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') => {
                let next = raw[index..].chars().next()?;
                index += next.len_utf8();
                if next == '\n' {
                    continue;
                }
                if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\') {
                    chunk.push('\\');
                }
                chunk.push(next);
            }
            (_, '$' | '`') => {
                value = value.append(Value::Literal(std::mem::take(&mut chunk)))?;
                let next = if ch == '`' || raw[index..].starts_with('(') {
                    if state.commands_unknown {
                        return None;
                    }
                    let (body, end) = substitution(raw, here)?;
                    index = end;
                    Value::Git {
                        prefix: String::new(),
                        path: git_paths::resolve_query(body)?,
                    }
                } else if quote.is_none() && raw[index..].starts_with('\'') {
                    // Reuse the native decoder for ANSI-C literal data only.
                    let end = quoted_end(raw, index, '\'')?;
                    let (word, read) = super::read_word(&raw[here..end], 0);
                    if read != end - here || !word.is_all_literal() {
                        return None;
                    }
                    index = end;
                    Value::Literal(word.as_string())
                } else {
                    if state.attributes_unknown {
                        return None;
                    }
                    let braced = raw[index..].starts_with('{');
                    if braced {
                        index += 1;
                    }
                    let start = index;
                    while raw
                        .as_bytes()
                        .get(index)
                        .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == b'_')
                    {
                        index += 1;
                    }
                    let name = &raw[start..index];
                    if !word_splitting::identifier(name) {
                        return None;
                    }
                    if braced {
                        if raw.as_bytes().get(index) != Some(&b'}') {
                            return None;
                        }
                        index += 1;
                    }
                    state.values.get(name).cloned().or_else(|| {
                        (name == "HOME").then(|| Value::Home {
                            prefix: String::new(),
                            root: "$HOME".to_owned(),
                            tail: String::new(),
                        })
                    })?
                };
                if !assignment && quote.is_none() && !next.one_unquoted_field(state) {
                    return None;
                }
                value = value.append(next)?;
                expanded = true;
            }
            (None, '~') if here == 0 => {
                let end = raw[index..]
                    .find('/')
                    .map_or(raw.len(), |offset| index + offset);
                let user = &raw[index..end];
                if !user
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
                {
                    return None;
                }
                value = Value::Home {
                    prefix: String::new(),
                    root: raw[..end].to_owned(),
                    tail: String::new(),
                };
                index = end;
                expanded = true;
            }
            (None, '(' | ')' | ';' | '&' | '|' | '<' | '>') => return None,
            (None, '*' | '?' | '[' | '{' | '}') if !assignment => return None,
            (None, ch) if ch.is_whitespace() => return None,
            _ => chunk.push(ch),
        }
    }
    if quote.is_some() {
        return None;
    }
    Some(Decoded {
        value: value.append(Value::Literal(chunk))?,
        expanded,
    })
}

fn quoted_end(raw: &str, start: usize, delimiter: char) -> Option<usize> {
    let mut escaped = false;
    for (offset, ch) in raw[start + 1..].char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == delimiter {
            return Some(start + 1 + offset + ch.len_utf8());
        }
    }
    None
}

/// The query recognizer rejects nested expressions, but boundaries still have
/// to respect quoted parentheses so they cannot truncate the query's argv.
fn substitution(raw: &str, start: usize) -> Option<(&str, usize)> {
    if raw.as_bytes().get(start) == Some(&b'`') {
        let end = quoted_end(raw, start, '`')?;
        return Some((&raw[start + 1..end - 1], end));
    }
    if !raw[start..].starts_with("$(") {
        return None;
    }
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 1usize;
    for (offset, ch) in raw[start + 2..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (_, '\\') => escaped = true,
            (None, '\'' | '"') => quote = Some(ch),
            (None, '(') => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return None;
                }
            }
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return Some((&raw[start + 2..start + 2 + offset], start + 3 + offset));
                }
            }
            _ => {}
        }
    }
    None
}

pub(in super::super) fn candidate(command: &str) -> bool {
    command.contains('`') || command.contains('$') && command.contains(['=', '('])
}

pub(in super::super) fn scan(command: &str, dialect: ShellDialect) -> Vec<CredentialFileWrite> {
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
        || !candidate(command)
        || command.len() > MAX_BYTES
    {
        return Vec::new();
    }
    // The existing outer-source joiner does not model nested quote scopes.
    // Leave substitution source intact; its own literal-query lexer handles
    // continuations without changing single-quoted query arguments.
    let joined = if command.contains("$(") || command.contains('`') {
        None
    } else {
        word_splitting::join_line_continuations(command)
    };
    let source = joined
        .as_ref()
        .map_or(command, |(source, _)| source.as_str());
    let parse_source = crate::context::shell_parse_source(source);
    let Ok(ast) = AstGrep::try_new(parse_source.as_ref(), SupportLang::Bash) else {
        return Vec::new();
    };
    if ast.root().get_inner_node().has_error() {
        return Vec::new();
    }
    let mut scanner = Scanner {
        source,
        visited: 0,
        hits: Vec::new(),
    };
    scanner.walk(ast.root(), &mut State::default(), 0);
    if let Some((_, offsets)) = &joined {
        for hit in &mut scanner.hits {
            hit.span = offsets[hit.span.start]..offsets[hit.span.end];
        }
    }
    scanner.hits
}

struct Scanner<'a> {
    source: &'a str,
    visited: usize,
    hits: Vec<CredentialFileWrite>,
}

impl Scanner<'_> {
    fn walk(&mut self, node: Node<'_, StrDoc<SupportLang>>, state: &mut State, depth: usize) {
        self.visited += 1;
        if self.visited > MAX_NODES || depth > MAX_DEPTH {
            state.forget();
            return;
        }
        match node.kind().as_ref() {
            "program" | "variable_assignments" | "do_group" | "negated_command" => {
                self.children(node, state, depth)
            }
            "variable_assignment" => {
                if has_expansion_effect(node.clone()) {
                    state.forget();
                }
                self.nested(node.clone(), state, depth + 1);
                state.assign(node.text().as_ref(), &state.clone());
            }
            "command" => self.command(node, state, depth),
            "redirected_statement" => {
                if node
                    .field("body")
                    .is_some_and(|body| body.kind() == "command")
                {
                    let incoming = state.clone();
                    self.command(node.clone(), state, depth);
                    self.heredoc_tail(node, &incoming, state, depth);
                } else {
                    // Redirections open before an assignment/group runs.
                    for child in node
                        .children()
                        .filter(|child| child.kind() == "file_redirect")
                    {
                        if has_expansion_effect(child.clone()) {
                            state.forget();
                        }
                        self.nested(child.clone(), state, depth + 1);
                        self.targets(child, state);
                    }
                    if let Some(body) = node.field("body") {
                        let before = state.clone();
                        self.walk(body, state, depth + 1);
                        // An open failure may prevent the body's assignments.
                        state.intersect(&before);
                    }
                }
            }
            "subshell" => self.children(node, &mut state.clone(), depth),
            "compound_statement" if node.text().trim_start().starts_with('{') => {
                self.children(node, state, depth)
            }
            "pipeline" => {
                let incoming = state.clone();
                let mut last = incoming.clone();
                for child in node.children().filter(ast_grep_core::Node::is_named) {
                    let mut stage = incoming.clone();
                    self.walk(child, &mut stage, depth + 1);
                    last = stage;
                }
                // Bash lastpipe may retain effects of its final stage.
                state.intersect(&last);
            }
            "list" => {
                let (mut success, failure) = self.outcomes(node, state, depth);
                success.intersect(&failure);
                *state = success;
            }
            "if_statement" | "elif_clause" => self.conditional(node, state, depth),
            "else_clause" => self.children(node, state, depth),
            "for_statement" | "while_statement" | "c_style_for_statement" => {
                let mut iteration = state.clone();
                let body = node.field("body");
                for header in node.children().filter(|child| {
                    child.is_named()
                        && body
                            .as_ref()
                            .is_none_or(|body| body.range() != child.range())
                }) {
                    self.nested(header, &iteration, depth + 1);
                }
                if node.kind() == "for_statement" {
                    if let Some(variable) = node.field("variable") {
                        iteration.values.remove(variable.text().as_ref());
                    }
                    if has_expansion_effect(node.clone()) {
                        iteration.forget();
                    }
                } else {
                    // Later iterations and arithmetic loop headers can change
                    // any binding. Body-local assignments can still prove it.
                    iteration.forget();
                }
                if let Some(body) = body {
                    self.walk(body, &mut iteration, depth + 1);
                }
                state.forget();
                state.attributes_unknown |= iteration.attributes_unknown;
                state.commands_unknown |= iteration.commands_unknown;
            }
            "case_statement" => {
                if let Some(value) = node.field("value") {
                    self.nested(value, state, depth + 1);
                }
                for branch in node.children().filter(|child| child.kind() == "case_item") {
                    let mut local = state.clone();
                    local.forget();
                    self.children(branch, &mut local, depth + 1);
                    state.attributes_unknown |= local.attributes_unknown;
                    state.commands_unknown |= local.commands_unknown;
                }
                state.forget();
            }
            "test_command" => {
                if has_expansion_effect(node.clone()) {
                    state.forget();
                }
                self.nested(node, state, depth + 1);
            }
            "declaration_command" => {
                if has_expansion_effect(node.clone()) {
                    state.forget();
                }
                self.nested(node.clone(), state, depth + 1);
                self.declaration(node, state);
            }
            "function_definition" => {
                state.forget();
                state.attributes_unknown = true;
                state.commands_unknown = true;
            }
            "comment" | "heredoc_body" => {}
            _ => {
                self.nested(node, state, depth + 1);
                state.forget();
            }
        }
    }

    /// Keep success and failure paths separate until the whole boolean list
    /// ends. A binding on the left of `&&` dominates its right-hand command,
    /// even when the parser nests a longer chain into several list nodes.
    fn outcomes(
        &mut self,
        node: Node<'_, StrDoc<SupportLang>>,
        incoming: &State,
        depth: usize,
    ) -> (State, State) {
        if node.kind() != "list" || depth > MAX_DEPTH || self.visited >= MAX_NODES {
            let mut state = incoming.clone();
            self.walk(node, &mut state, depth + 1);
            return (state.clone(), state);
        }
        self.visited += 1;
        let mut children = node.children().filter(ast_grep_core::Node::is_named);
        let (Some(left), Some(right)) = (children.next(), children.next()) else {
            let mut unknown = incoming.clone();
            unknown.forget();
            return (unknown.clone(), unknown);
        };
        let and = node.children().any(|child| child.kind() == "&&");
        let (mut success, mut failure) = self.outcomes(left, incoming, depth + 1);
        if and {
            let (right_success, right_failure) = self.outcomes(right, &success, depth + 1);
            failure.intersect(&right_failure);
            (right_success, failure)
        } else {
            let (right_success, right_failure) = self.outcomes(right, &failure, depth + 1);
            success.intersect(&right_success);
            (success, right_failure)
        }
    }

    fn conditional(
        &mut self,
        node: Node<'_, StrDoc<SupportLang>>,
        state: &mut State,
        depth: usize,
    ) {
        let mut alternative = None;
        let mut merged: Option<State> = None;
        for child in node.children() {
            if child.kind() == "then" {
                alternative = Some(state.clone());
            } else if child.is_named() {
                if matches!(child.kind().as_ref(), "elif_clause" | "else_clause") {
                    let mut branch = alternative.clone().unwrap_or_else(|| state.clone());
                    self.walk(child, &mut branch, depth + 1);
                    merged
                        .get_or_insert_with(|| state.clone())
                        .intersect(&branch);
                    if let Some(alternative) = &mut alternative {
                        alternative.intersect(&branch);
                    }
                } else if word_splitting::has_async_terminator(&child) {
                    self.walk(child, &mut state.clone(), depth + 1);
                } else {
                    self.walk(child, state, depth + 1);
                }
            }
        }
        if let Some(other) = merged {
            state.intersect(&other);
        }
        if let Some(skipped) = alternative {
            state.intersect(&skipped);
        }
    }

    fn children(&mut self, node: Node<'_, StrDoc<SupportLang>>, state: &mut State, depth: usize) {
        for child in node.children().filter(ast_grep_core::Node::is_named) {
            if word_splitting::has_async_terminator(&child) {
                self.walk(child, &mut state.clone(), depth + 1);
            } else {
                self.walk(child, state, depth + 1);
            }
        }
    }

    fn declaration(&mut self, node: Node<'_, StrDoc<SupportLang>>, state: &mut State) {
        let raw = node.text();
        let tokens = super::tokenize(raw.as_ref());
        let words: Vec<_> = tokens
            .iter()
            .filter_map(|token| match token {
                Token::Word(word) => Some(word),
                _ => None,
            })
            .collect();
        if words
            .first()
            .is_none_or(|word| word.as_string() != "export")
            || word_splitting::declaration_may_expand_braces(raw.as_ref())
            || has_expansion_effect(node)
        {
            state.forget();
            state.attributes_unknown = true;
            return;
        }
        let incoming = state.clone();
        for word in words.into_iter().skip(1) {
            let source = &raw[word.range.clone()];
            if word_splitting::assignment(source).is_some() {
                state.assign(source, &incoming);
            } else if !word_splitting::identifier(&word.as_string()) {
                state.forget();
                state.attributes_unknown = true;
                return;
            }
        }
    }

    fn command(&mut self, node: Node<'_, StrDoc<SupportLang>>, state: &mut State, depth: usize) {
        if has_expansion_effect(node.clone()) {
            state.forget();
        }
        self.nested(node.clone(), state, depth + 1);
        let tokens = self.targets(node.clone(), state);
        if tokens.is_empty() {
            state.forget();
            return;
        }
        let words: Vec<_> = tokens
            .iter()
            .filter_map(|token| match token {
                Token::Word(word) => Some(word),
                _ => None,
            })
            .collect();
        let Some(command_index) = words
            .iter()
            .position(|word| !crate::normalize::is_env_assignment(&word.as_string()))
        else {
            return;
        };
        let name = super::executable_name(words[command_index]);
        let mutation = name.as_deref().is_none_or(word_splitting::mutates_shell);
        let mut format_index = command_index + 1;
        if words
            .get(format_index)
            .is_some_and(|word| word.is_all_literal() && word.as_string() == "--")
        {
            format_index += 1;
        }
        let printf_mutation = name.as_deref() == Some("printf")
            && words.get(format_index).is_none_or(|format| {
                !format.is_all_literal()
                    || format.as_string().starts_with("-v")
                    || word_splitting::printf_format_may_assign(&format.as_string())
            });
        if mutation || printf_mutation {
            state.forget();
            // Reads lose values but cannot change an independent Git query's
            // producer. Declarations can introduce namerefs/integer attributes;
            // executable code and command-table changes also lose identity.
            state.commands_unknown |= name.as_deref().is_none_or(|name| {
                matches!(
                    name,
                    "eval"
                        | "."
                        | "source"
                        | "trap"
                        | "alias"
                        | "unalias"
                        | "enable"
                        | "builtin"
                        | "command"
                )
            });
            state.attributes_unknown |= state.commands_unknown
                || name.as_deref().is_some_and(|name| {
                    matches!(
                        name,
                        "declare" | "typeset" | "local" | "readonly" | "export"
                    )
                });
        } else if name.as_deref().is_some_and(word_splitting::special_builtin) {
            for word in &words[..command_index] {
                if let Some((name, _, _)) = word_splitting::assignment(&word.as_string()) {
                    state.values.remove(name);
                    if name == "IFS" {
                        state.ifs = None;
                    }
                }
            }
        }
    }

    fn nested(&mut self, node: Node<'_, StrDoc<SupportLang>>, state: &State, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        for child in node.children() {
            self.visited += 1;
            if self.visited > MAX_NODES {
                return;
            }
            if attached_heredoc_statement(&child) {
                continue;
            }
            match child.kind().as_ref() {
                "command_substitution" | "process_substitution" => {
                    self.children(child, &mut state.clone(), depth)
                }
                // Quoted heredoc bodies have no expansion children. In an
                // unquoted body only its typed expansions are executable.
                "raw_string" | "ansi_c_string" | "comment" => {}
                _ => self.nested(child, state, depth + 1),
            }
        }
    }

    fn heredoc_tail(
        &mut self,
        node: Node<'_, StrDoc<SupportLang>>,
        incoming: &State,
        state: &mut State,
        depth: usize,
    ) {
        let mut pending = vec![node];
        while let Some(part) = pending.pop() {
            self.visited += 1;
            if self.visited > MAX_NODES {
                state.forget();
                return;
            }
            if attached_heredoc_statement(&part) {
                if part.kind() == "pipeline" {
                    let mut last = incoming.clone();
                    self.walk(part, &mut last, depth + 1);
                    *state = incoming.clone();
                    state.intersect(&last);
                } else {
                    let mut branch = state.clone();
                    self.walk(part, &mut branch, depth + 1);
                    state.intersect(&branch);
                }
            } else if !matches!(
                part.kind().as_ref(),
                "command_substitution" | "process_substitution" | "heredoc_body"
            ) {
                pending.extend(part.children());
            }
        }
    }

    fn targets(&mut self, node: Node<'_, StrDoc<SupportLang>>, state: &State) -> Vec<Token> {
        if self.visited >= MAX_NODES {
            return Vec::new();
        }
        let span = node.range();
        let Some(source) = self.source.get(span.clone()) else {
            return Vec::new();
        };
        // A redirected statement's AST range includes its heredoc body. It
        // supplies stdin data, never outer argv or redirections. Keep offsets
        // and real redirect syntax while removing only those data ranges.
        let mut masked = None;
        let mut pending = vec![node];
        while let Some(part) = pending.pop() {
            self.visited += 1;
            if self.visited > MAX_NODES {
                return Vec::new();
            }
            let process = part.kind() == "process_substitution";
            if process
                || attached_heredoc_statement(&part)
                || matches!(part.kind().as_ref(), "heredoc_body" | "heredoc_end")
            {
                let bytes = masked.get_or_insert_with(|| source.as_bytes().to_vec());
                let range = part.range();
                for byte in &mut bytes[range.start - span.start..range.end - span.start] {
                    if process {
                        *byte = b'x';
                    } else if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
            } else if part.kind() != "command_substitution" {
                pending.extend(part.children());
            }
        }
        let masked = masked.and_then(|bytes| String::from_utf8(bytes).ok());
        let raw = masked.as_deref().unwrap_or(source);
        let mut tokens = super::tokenize(raw);
        if tokens.len() > MAX_TOKENS {
            return Vec::new();
        }
        let mut expanded = false;
        let mut argv_proven = true;
        let mut materialized = 0usize;
        for token in &mut tokens {
            let argument = matches!(token, Token::Word(_));
            let word = match token {
                Token::Word(word) | Token::Write { target: word, .. } => word,
                Token::Separator => continue,
            };
            let local = word.range.clone();
            let range = span.start + local.start..span.start + local.end;
            if let Some(decoded) = decode(&raw[local], state, false)
                && let Some(mut proven) = decoded.value.word(range.clone())
            {
                expanded |= decoded.expanded;
                proven.glued_paren = word.glued_paren;
                *word = proven;
            } else {
                word.range = range;
                argv_proven &= !argument;
            }
            materialized += word.text.len();
            if materialized > MAX_MATERIALIZED_BYTES {
                return Vec::new();
            }
        }
        if !expanded {
            return tokens;
        }
        for token in &tokens {
            if let Token::Write { mode, target } = token {
                if let Some(hit) = git_redirect_write(target, *mode) {
                    self.hits.push(hit);
                }
                if let Some(hit) = classify_simple_command(std::slice::from_ref(token)) {
                    self.hits.push(hit);
                }
            }
        }
        // An unresolved field can introduce options or several operands.
        // Do not mistake a protected source for the destination of `cp $opts
        // "$source"`. Independently proved redirections above remain writes.
        if !argv_proven {
            return tokens;
        }
        // Keep all rule families. An allowlist for one target must not grant
        // a second target. Work with decoded words, never rendered shell code.
        let mut remaining: Vec<_> = tokens
            .iter()
            .filter(|token| matches!(token, Token::Word(_)))
            .cloned()
            .collect();
        for _ in 0..remaining.len() {
            let Some(mut hit) = classify_simple_command(&remaining) else {
                break;
            };
            let Some(word) = remaining.iter_mut().find_map(|token| {
                let word = match token {
                    Token::Word(word) | Token::Write { target: word, .. } => word,
                    Token::Separator => return None,
                };
                (word.range.start <= hit.span.start && word.range.end >= hit.span.end)
                    .then_some(word)
            }) else {
                break;
            };
            // Expanded option prefixes may be longer than their source
            // (`$out` can carry `of=/etc/sudoers`). Native suffix offsets are
            // decoded offsets, so report the original enclosing word instead.
            hit.span = word.range.clone();
            word.text = vec!['x'];
            word.literal = vec![true];
            word.glued_paren = false;
            self.hits.push(hit);
        }
        tokens
    }
}

fn attached_heredoc_statement(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "heredoc_redirect"
            && (node.kind() == "pipeline"
                || parent
                    .field("right")
                    .is_some_and(|right| right.range() == node.range()))
    })
}

fn has_expansion_effect(node: Node<'_, StrDoc<SupportLang>>) -> bool {
    let mut pending = vec![node];
    let mut count = 0;
    while let Some(part) = pending.pop() {
        count += 1;
        if count > MAX_NODES {
            return true;
        }
        if attached_heredoc_statement(&part) {
            continue;
        }
        match part.kind().as_ref() {
            "command_substitution"
            | "process_substitution"
            | "raw_string"
            | "ansi_c_string"
            | "comment" => {}
            "arithmetic_expansion" => return true,
            "expansion" => {
                let raw = part.text();
                if raw
                    .strip_prefix("${")
                    .and_then(|s| s.strip_suffix('}'))
                    .is_none_or(|name| !word_splitting::identifier(name))
                {
                    return true;
                }
            }
            _ => pending.extend(part.children()),
        }
    }
    false
}

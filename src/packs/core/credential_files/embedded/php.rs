//! PHP global filesystem APIs and bounded, source-local value propagation.
//!
//! PHP uses its real grammar, including argument wrappers and `.` rather than
//! arithmetic `+`. Literal tildes never acquire runtime HOME provenance.

use super::{
    Access, AstGrep, CredentialFileWrite, MAX_BYTES, MAX_DEPTH, MAX_NODES, MAX_STATIC_PATH_BYTES,
    ResolvedPath, SupportLang, Syntax, record_write,
};
use std::collections::HashMap;

const APPEND: u8 = 1;
const UNKNOWN: u8 = 2;

#[derive(Clone, Debug)]
enum Datum {
    Text(ResolvedPath),
    Flags(u8),
    Handle(ResolvedPath, Access),
    Environment,
}

#[derive(Clone)]
struct State {
    values: HashMap<String, Datum>,
    namespaced: bool,
    getenv_home: bool,
}

impl State {
    fn new(namespaced: bool) -> Self {
        Self {
            values: HashMap::from([
                ("$_SERVER".into(), Datum::Environment),
                ("$_ENV".into(), Datum::Environment),
            ]),
            namespaced,
            getenv_home: true,
        }
    }
}

pub(super) fn has_sink_name(code: &str) -> bool {
    [
        "file_put_contents",
        "fopen",
        "fwrite",
        "fputs",
        "ftruncate",
        "copy",
        "rename",
        // Creating a name is creating the file the name resolves to (#484).
        "symlink",
        "link",
        "move_uploaded_file",
    ]
    .iter()
    .any(|word| {
        code.as_bytes()
            .windows(word.len())
            .any(|part| part.eq_ignore_ascii_case(word.as_bytes()))
    })
}

pub(super) fn scan(code: &str) -> Result<Vec<CredentialFileWrite>, &'static str> {
    if code.len() > MAX_BYTES {
        return Err("protected-write PHP source exceeds the byte limit");
    }
    // -r has no opening tag; stdin programs normally do. Keep findings in
    // original-source coordinates rather than exposing the synthetic prefix.
    let prefix = if code.trim_start().starts_with("<?") {
        ""
    } else {
        "<?php\n"
    };
    let source = format!("{prefix}{code}");
    let ast = AstGrep::new(&source, SupportLang::Php);
    let mut hits = Vec::new();
    let mut remaining = MAX_NODES;
    visit(
        ast.root(),
        &mut State::new(false),
        0,
        &mut remaining,
        &mut hits,
    )?;
    for hit in &mut hits {
        hit.span =
            hit.span.start.saturating_sub(prefix.len())..hit.span.end.saturating_sub(prefix.len());
    }
    Ok(hits)
}

fn visit(
    node: Syntax<'_>,
    state: &mut State,
    depth: usize,
    remaining: &mut usize,
    hits: &mut Vec<CredentialFileWrite>,
) -> Result<(), &'static str> {
    if depth > MAX_DEPTH || *remaining == 0 || state.values.len() > 1024 {
        return Err("protected-write PHP source exceeds the traversal limit");
    }
    *remaining -= 1;
    let kind = node.kind();
    if kind == "ERROR" {
        return Err("protected-write PHP source contains a syntax error");
    }
    if kind == "namespace_definition" {
        if let Some(body) = node.field("body") {
            let mut local = state.clone();
            local.namespaced = node.field("name").is_some();
            return visit(body, &mut local, depth + 1, remaining, hits);
        }
        state.namespaced = node.field("name").is_some();
        return Ok(());
    }
    if matches!(
        kind.as_ref(),
        "function_definition" | "method_declaration" | "anonymous_function" | "arrow_function"
    ) {
        // Named PHP functions do not inherit caller-local variables. Arrow
        // functions capture by value; ordinary closures require an explicit
        // use-list, which is deliberately left unresolved in this bounded pass.
        let mut local = if kind == "arrow_function" {
            state.clone()
        } else {
            State::new(state.namespaced)
        };
        local.getenv_home = state.getenv_home;
        for global in ["$_SERVER", "$_ENV"] {
            if !state.values.contains_key(global) {
                local.values.remove(global);
            }
        }
        if let Some(parameters) = node.field("parameters") {
            for parameter in parameters
                .dfs()
                .filter(|child| child.kind() == "variable_name")
            {
                local.values.remove(parameter.text().as_ref());
            }
        }
        if let Some(body) = node.field("body") {
            visit(body, &mut local, depth + 1, remaining, hits)?;
        }
        return Ok(());
    }
    if matches!(
        kind.as_ref(),
        "assignment_expression"
            | "augmented_assignment_expression"
            | "reference_assignment_expression"
    ) {
        if let (Some(left), Some(right)) = (node.field("left"), node.field("right")) {
            // Capture compound LHS before evaluating RHS, but inspect effects
            // before installing the assignment (including fopen in the RHS).
            let before = value(&left, state, 0);
            visit(right.clone(), state, depth + 1, remaining, hits)?;
            let after = value(&right, state, 0);
            let assigned = match kind.as_ref() {
                "assignment_expression" => after,
                "augmented_assignment_expression" => match node
                    .field("operator")
                    .as_ref()
                    .map(ast_grep_core::Node::text)
                {
                    Some(op) if op == ".=" => concatenate(before, after),
                    Some(op) if op == "|=" => combine_flags(before, after),
                    _ => None,
                },
                // Aliases can change later without a direct assignment here.
                _ => None,
            };
            invalidate(&left, state);
            if left.kind() == "variable_name" {
                if let Some(assigned) = assigned {
                    state.values.insert(left.text().into_owned(), assigned);
                }
            }
            return Ok(());
        }
    }
    if matches!(
        kind.as_ref(),
        "update_expression" | "unset_statement" | "global_declaration"
    ) {
        invalidate(&node, state);
    }
    if kind == "function_call_expression" {
        inspect_call(&node, state, hits);
        if builtin(&node, state).as_deref() == Some("putenv") {
            state.getenv_home = false;
        }
    }
    for child in node.children() {
        visit(child, state, depth + 1, remaining, hits)?;
    }
    Ok(())
}

fn invalidate(node: &Syntax<'_>, state: &mut State) {
    for variable in node.dfs().filter(|child| child.kind() == "variable_name") {
        state.values.remove(variable.text().as_ref());
    }
}

fn builtin(node: &Syntax<'_>, state: &State) -> Option<String> {
    let function = node.field("function")?;
    let text = function.text();
    let name = match function.kind().as_ref() {
        "name" if !state.namespaced => text.as_ref(),
        "qualified_name" => text.strip_prefix('\\')?,
        _ => return None,
    };
    (!name.contains('\\')).then(|| name.to_ascii_lowercase())
}

fn argument<'a>(node: &Syntax<'a>, position: usize, name: &str) -> Option<Syntax<'a>> {
    let args = super::arguments(node);
    let selected = args
        .iter()
        .find(|arg| arg.field("name").is_some_and(|key| key.text() == name))
        .or_else(|| {
            args.iter()
                .filter(|arg| arg.field("name").is_none())
                .nth(position)
        })?;
    if selected.kind() != "argument" {
        return Some(selected.clone());
    }
    // PHP's argument value is an unnamed field. The optional argument name
    // is its first named child, while the expression is the last one.
    selected
        .children()
        .filter(|child| child.is_named() && child.kind() != "comment")
        .last()
}

fn path(node: &Syntax<'_>, state: &State) -> Option<ResolvedPath> {
    match value(node, state, 0)? {
        Datum::Text(path) => Some(path),
        _ => None,
    }
}

fn plain(node: &Syntax<'_>, state: &State, depth: usize) -> Option<String> {
    match value(node, state, depth)? {
        Datum::Text((text, false)) => Some(text),
        _ => None,
    }
}

fn concatenate(left: Option<Datum>, right: Option<Datum>) -> Option<Datum> {
    let (Datum::Text(left), Datum::Text(right)) = (left?, right?) else {
        return None;
    };
    let joined = super::concatenate_text(super::path_as_text(left), super::path_as_text(right))?;
    Some(Datum::Text(super::resolved_path(joined)?))
}

fn combine_flags(left: Option<Datum>, right: Option<Datum>) -> Option<Datum> {
    match (left, right) {
        (Some(Datum::Flags(left)), Some(Datum::Flags(right))) => Some(Datum::Flags(left | right)),
        (Some(Datum::Flags(bits)), _) | (_, Some(Datum::Flags(bits))) => {
            Some(Datum::Flags(bits | UNKNOWN))
        }
        _ => None,
    }
}

fn value(node: &Syntax<'_>, state: &State, depth: usize) -> Option<Datum> {
    if depth > 24 {
        return None;
    }
    match node.kind().as_ref() {
        "variable_name" => state.values.get(node.text().as_ref()).cloned(),
        "string" => {
            let raw = node.text();
            let raw = raw.strip_prefix(['b', 'B']).unwrap_or(&raw);
            let body = raw.strip_prefix('\'')?.strip_suffix('\'')?;
            Some(Datum::Text((decode(body, false)?, false)))
        }
        "encapsed_string" => {
            let mut result = Some(Datum::Text((String::new(), false)));
            for child in node.children().filter(ast_grep_core::Node::is_named) {
                let part = match child.kind().as_ref() {
                    "string_content" | "escape_sequence" => {
                        Some(Datum::Text((decode(child.text().as_ref(), true)?, false)))
                    }
                    _ => value(&child, state, depth + 1),
                };
                result = concatenate(result, part);
            }
            result
        }
        "parenthesized_expression" | "argument" => {
            let child = node
                .children()
                .filter(|child| child.is_named() && child.kind() != "comment")
                .last()?;
            value(&child, state, depth + 1)
        }
        "assignment_expression" => value(&node.field("right")?, state, depth + 1),
        "binary_expression" => {
            let left = value(&node.field("left")?, state, depth + 1);
            let right = value(&node.field("right")?, state, depth + 1);
            match node.field("operator")?.text().as_ref() {
                "." => concatenate(left, right),
                "|" => combine_flags(left, right),
                _ => None,
            }
        }
        "subscript_expression" => {
            let mut children = node
                .children()
                .filter(|child| child.is_named() && child.kind() != "comment");
            let base = children.next()?;
            let key = children.next()?;
            if children.next().is_none()
                && matches!(value(&base, state, depth + 1), Some(Datum::Environment))
                && plain(&key, state, depth + 1).as_deref() == Some("HOME")
            {
                Some(Datum::Text(("~".into(), true)))
            } else {
                None
            }
        }
        "name" | "qualified_name" => {
            let text = node.text();
            let name = if let Some(name) = text.strip_prefix('\\') {
                name
            } else if state.namespaced {
                return None;
            } else {
                &text
            };
            match name {
                "FILE_APPEND" => Some(Datum::Flags(APPEND)),
                "LOCK_EX" | "FILE_USE_INCLUDE_PATH" | "FILE_NO_DEFAULT_CONTEXT" => {
                    Some(Datum::Flags(0))
                }
                _ => None,
            }
        }
        "integer" if node.text() == "0" => Some(Datum::Flags(0)),
        "function_call_expression" => match builtin(node, state)?.as_str() {
            "getenv" if state.getenv_home => {
                let key = argument(node, 0, "name")?;
                (plain(&key, state, depth + 1).as_deref() == Some("HOME"))
                    .then(|| Datum::Text(("~".into(), true)))
            }
            "fopen" => {
                let target = argument(node, 0, "filename")?;
                let mode = argument(node, 1, "mode")?;
                let Datum::Text(path) = value(&target, state, depth + 1)? else {
                    return None;
                };
                Some(Datum::Handle(
                    path,
                    mode_access(&plain(&mode, state, depth + 1)?)?,
                ))
            }
            _ => None,
        },
        _ => None,
    }
}

fn mode_access(mode: &str) -> Option<Access> {
    let first = *mode.as_bytes().first()?;
    if !mode.bytes().skip(1).all(|b| b"+bten".contains(&b)) {
        return None;
    }
    match first {
        b'r' => Some(if mode.contains('+') {
            Access::Write
        } else {
            Access::Read
        }),
        b'a' => Some(Access::Append),
        b'w' | b'x' | b'c' => Some(Access::Write),
        _ => None,
    }
}

fn inspect_call(node: &Syntax<'_>, state: &State, hits: &mut Vec<CredentialFileWrite>) {
    let Some(api) = builtin(node, state) else {
        return;
    };
    let target = |position, name| argument(node, position, name).and_then(|arg| path(&arg, state));
    let mut record =
        |path, access| record_write(hits, node.range(), &format!("PHP {api}"), path, access);
    match api.as_str() {
        "file_put_contents" => {
            let access = match argument(node, 2, "flags").and_then(|arg| value(&arg, state, 0)) {
                Some(Datum::Flags(APPEND)) => Access::Append,
                _ => Access::Write,
            };
            if let Some(path) = target(0, "filename") {
                record(path, access);
            }
        }
        "fopen" => {
            if let Some(Datum::Handle(path, access)) = value(node, state, 0) {
                record(path, access);
            }
        }
        "copy" | "rename" => {
            if let Some(path) = target(1, "to") {
                record(path, Access::Write);
            }
            if api == "rename" {
                if let Some(path) = target(0, "from") {
                    record(path, Access::Write);
                }
            }
        }
        // The destination is argument 1 in all three (#484). `symlink`/`link`
        // take (target, link) and create `link`; `move_uploaded_file` takes
        // (from, to). Only the created name is a write -- a link never alters
        // what it points at, and the upload source is a request temp file.
        "symlink" | "link" => {
            if let Some(path) = target(1, "link") {
                record(path, Access::Write);
            }
        }
        "move_uploaded_file" => {
            if let Some(path) = target(1, "to") {
                record(path, Access::Write);
            }
        }
        "fwrite" | "fputs" | "ftruncate" => {
            if let Some(Datum::Handle(path, access)) =
                argument(node, 0, "stream").and_then(|arg| value(&arg, state, 0))
            {
                if access != Access::Read {
                    record(
                        path,
                        if api == "ftruncate" {
                            Access::Write
                        } else {
                            access
                        },
                    );
                }
            }
        }
        _ => {}
    }
}

/// PHP single quotes only unescape quote/backslash. Double quotes support
/// octal, hex and braced Unicode; unknown escapes retain their backslash.
fn decode(body: &str, double: bool) -> Option<String> {
    if body.len() > MAX_STATIC_PATH_BYTES {
        return None;
    }
    let mut output = String::new();
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        let escaped = chars.next()?;
        if !double {
            if !matches!(escaped, '\\' | '\'') {
                output.push('\\');
            }
            output.push(escaped);
            continue;
        }
        match escaped {
            '\\' | '"' | '$' => output.push(escaped),
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            'v' => output.push('\u{000b}'),
            'e' => output.push('\u{001b}'),
            'f' => output.push('\u{000c}'),
            '0'..='7' | 'x' => {
                let radix = if escaped == 'x' { 16 } else { 8 };
                let mut digits = if escaped == 'x' {
                    String::new()
                } else {
                    escaped.to_string()
                };
                let limit = if radix == 16 { 2 } else { 3 };
                while digits.len() < limit && chars.peek().is_some_and(|c| c.is_digit(radix)) {
                    digits.push(chars.next()?);
                }
                if digits.is_empty() {
                    output.push_str("\\x");
                } else {
                    let byte = u32::from_str_radix(&digits, radix).ok()? & 255;
                    // PHP byte strings need not be UTF-8. Do not invent a
                    // Unicode pathname for a non-ASCII escaped byte.
                    if byte > 127 {
                        return None;
                    }
                    output.push(char::from_u32(byte)?);
                }
            }
            'u' if chars.peek() == Some(&'{') => {
                chars.next();
                let mut digits = String::new();
                while chars.peek().is_some_and(char::is_ascii_hexdigit) {
                    digits.push(chars.next()?);
                }
                if chars.next()? != '}' {
                    return None;
                }
                output.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            _ => {
                output.push('\\');
                output.push(escaped);
            }
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn denied(code: &str) {
        let hits = scan(code).expect(code);
        assert!(!hits.is_empty(), "{code}");
        for hit in hits {
            assert!(code.get(hit.span).is_some(), "{code}");
        }
    }

    fn allowed(code: &str) {
        assert!(scan(code).expect(code).is_empty(), "{code}");
    }

    #[test]
    fn php_global_sinks_modes_and_case() {
        for mode in ["w", "w+", "a", "a+", "r+", "x", "c", "c+b", "wbe"] {
            denied(&format!("fopen('/etc/shadow', '{mode}');"));
        }
        for code in [
            "file_put_contents('/etc/shadow', 'x');",
            "<?php FILE_PUT_CONTENTS('/etc/shadow', 'x', FILE_APPEND);",
            "\\fopen('/home/u/.bashrc', 'r+');",
            "copy('/tmp/input', '/etc/shadow');",
            "rename('/etc/shadow', '/tmp/output');",
            "rename($unknown, '/etc/shadow');",
            "file_put_contents(flags: FILE_APPEND, data: 'x', filename: '/etc/shadow');",
            "$f = fopen('/home/u/.ssh/known_hosts', 'a'); ftruncate($f, 0);",
            "file_put_contents('/home/u/.ssh/known_hosts', 'x', FILE_APPEND | $unknown);",
        ] {
            denied(code);
        }
        for code in [
            "fopen('/etc/shadow', 'r');",
            "fopen('/etc/shadow', 'rb');",
            "file_put_contents('/tmp/out', 'x');",
            "copy('/etc/shadow', '/tmp/out');",
            "file_put_contents('/home/u/.ssh/known_hosts', 'x', FILE_APPEND | LOCK_EX);",
            "$f = fopen('/home/u/.ssh/known_hosts', 'a+'); fwrite($f, 'host');",
            "file_put_contents('/home/u/.ssh/id_rsa.pub', 'x');",
            "$o->file_put_contents('/etc/shadow', 'x');",
            "Other\\file_put_contents('/etc/shadow', 'x');",
            "echo \"file_put_contents('/etc/shadow', 'x')\";",
            "// file_put_contents('/etc/shadow', 'x');",
        ] {
            allowed(code);
        }
    }

    #[test]
    fn php_paths_keep_home_provenance_and_assignment_order() {
        for code in [
            "$p = '/etc/' . 'shadow'; file_put_contents($p, 'x');",
            "$p = getenv('HOME'); $p .= '/.bashrc'; fopen($p, 'c');",
            "fopen($_SERVER['HOME'] . '/.ssh/authorized_keys', 'a');",
            "file_put_contents(\"{$_ENV['HOME']}/.bashrc\", 'x');",
            "file_put_contents(\"/etc/\\x73hadow\", 'x');",
            "$p = '/etc/shadow'; $p = fopen($p, 'w');",
            "$flags = FILE_APPEND; $flags |= $unknown; file_put_contents('/home/u/.ssh/known_hosts', 'x', $flags);",
        ] {
            denied(code);
        }
        for code in [
            "file_put_contents('~/.bashrc', 'x');",
            "file_put_contents('$HOME/.bashrc', 'x');",
            "$p = '/etc/shadow'; $p = '/tmp/out'; fopen($p, 'w');",
            "$p = '/etc/shadow'; $p = unknown(); fopen($p, 'w');",
            "$_SERVER['HOME'] = '/tmp'; fopen($_SERVER['HOME'] . '/.bashrc', 'w');",
            "putenv('HOME=/tmp'); fopen(getenv('HOME') . '/.bashrc', 'w');",
            "$p = '/etc/shadow'; function f($p) { fopen($p, 'w'); }",
            "file_put_contents(getenv('HOME') . 'other/.bashrc', 'x');",
            "file_put_contents('fixture/' . getenv('HOME') . '/.bashrc', 'x');",
        ] {
            allowed(code);
        }
    }

    #[test]
    fn php_independent_rules_and_bounds() {
        let hits = scan("rename('.git/config', '/home/u/.bashrc');").unwrap();
        assert_eq!(hits.len(), 2);
        assert_ne!(hits[0].rule, hits[1].rule);
        assert_eq!(hits[0].span, hits[1].span);
        assert!(scan(&" ".repeat(MAX_BYTES + 1)).is_err());
        assert!(scan("fopen(").is_err());
        let code = format!(
            "{}file_put_contents('/etc/shadow', 'x');{}",
            "if (true) {".repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert!(scan(&code).is_err());
    }
}

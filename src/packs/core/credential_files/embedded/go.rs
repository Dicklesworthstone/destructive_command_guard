//! Go standard-library filesystem writes and bounded, source-local value
//! propagation.
//!
//! Go's write vocabulary is small and regular, which is why this pass is much
//! shorter than the PHP and Perl ones. The mode is the part that differs from
//! every other language here: it is a flag constant (`os.O_APPEND`) rather than
//! a mode string, so append-versus-truncate is decided by bit test rather than
//! by reading a `'a'`.
//!
//! What this pass deliberately does not do: resolve a path that depends on
//! anything outside the source it was handed. A parameter, a struct field, a
//! function result other than the two home lookups below — each of those ends
//! resolution and the call is left alone, exactly as the other language passes
//! leave a dynamic destination alone. The recursive-delete and exec-sink rules
//! still judge the same program under their own predicates.

use super::{
    Access, AstGrep, CredentialFileWrite, MAX_BYTES, MAX_DEPTH, MAX_NODES, MAX_STATIC_PATH_BYTES,
    ResolvedPath, SupportLang, Syntax, record_write,
};
use std::collections::HashMap;

/// `os.O_APPEND` was proven present.
const FLAG_APPEND: u8 = 1;
/// A flag that opens the file for writing was proven present.
const FLAG_WRITE: u8 = 2;
/// Part of the flag expression could not be read, so the absence of
/// `O_APPEND` is not proof of truncation and the absence of a write flag is
/// not proof of a read.
const FLAG_UNKNOWN: u8 = 4;

/// The standard packages this pass recognises, under whatever local name the
/// file imports them as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pkg {
    Os,
    Filepath,
    Ioutil,
}

#[derive(Clone, Debug)]
enum Datum {
    Text(ResolvedPath),
    Flags(u8),
}

#[derive(Clone)]
struct State {
    values: HashMap<String, Datum>,
    packages: HashMap<String, Pkg>,
}

impl State {
    fn new() -> Self {
        // Seeded with the conventional names rather than requiring an import
        // to have survived extraction: a truncated body can lose its import
        // block and keep the call. An `import alias "…"` below overwrites the
        // entry, so a file that really does rebind `os` is still read
        // correctly.
        Self {
            values: HashMap::new(),
            packages: HashMap::from([
                ("os".into(), Pkg::Os),
                ("filepath".into(), Pkg::Filepath),
                ("ioutil".into(), Pkg::Ioutil),
            ]),
        }
    }
}

/// The lexical gate. Go's sink names are capitalised, so none of them survive
/// the shared lowercase vocabulary in `source_has_sink_name` — `Create`,
/// `Truncate` and `Rename` contain none of its words at all.
pub(super) fn has_sink_name(code: &str) -> bool {
    ["WriteFile", "Create", "OpenFile", "Truncate", "Rename"]
        .iter()
        .any(|word| code.contains(word))
}

pub(super) fn scan(code: &str) -> Result<Vec<CredentialFileWrite>, &'static str> {
    if code.len() > MAX_BYTES {
        return Err("protected-write Go source exceeds the byte limit");
    }
    let ast = AstGrep::new(code, SupportLang::Go);
    let mut hits = Vec::new();
    let mut remaining = MAX_NODES;
    visit(ast.root(), &mut State::new(), 0, &mut remaining, &mut hits)?;
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
        return Err("protected-write Go source exceeds the traversal limit");
    }
    *remaining -= 1;
    let kind = node.kind();
    if kind == "ERROR" {
        return Err("protected-write Go source contains a syntax error");
    }

    if kind == "import_spec" {
        bind_import(&node, state);
        return Ok(());
    }

    // A function body does not inherit the caller's locals. Package-level
    // declarations do reach it, and those are bound before any body is walked
    // because the source file is visited in order.
    if matches!(kind.as_ref(), "function_declaration" | "method_declaration") {
        let mut local = state.clone();
        local.values.clear();
        if let Some(body) = node.field("body") {
            visit(body, &mut local, depth + 1, remaining, hits)?;
        }
        return Ok(());
    }
    // A literal closure DOES capture, so it keeps the enclosing bindings, but
    // its own assignments must not leak back out.
    if kind == "func_literal" {
        let mut local = state.clone();
        if let Some(body) = node.field("body") {
            visit(body, &mut local, depth + 1, remaining, hits)?;
        }
        return Ok(());
    }

    if matches!(
        kind.as_ref(),
        "short_var_declaration" | "assignment_statement" | "var_spec" | "const_spec"
    ) {
        assign(&node, state, depth, remaining, hits)?;
        return Ok(());
    }

    if kind == "call_expression" {
        inspect_call(&node, state, hits);
    }

    for child in node.children() {
        visit(child, state, depth + 1, remaining, hits)?;
    }
    Ok(())
}

/// `import alias "path"` / `import "path"`.
fn bind_import(node: &Syntax<'_>, state: &mut State) {
    let Some(path) = node.field("path") else {
        return;
    };
    let literal = string_literal(&path).unwrap_or_default();
    let package = match literal.as_str() {
        "os" => Some(Pkg::Os),
        "path/filepath" | "path" => Some(Pkg::Filepath),
        "io/ioutil" => Some(Pkg::Ioutil),
        _ => None,
    };
    // The default local name is the last path element, which is what the file
    // writes when there is no alias.
    let default_name = literal.rsplit('/').next().unwrap_or(&literal).to_string();
    let name = node
        .field("name")
        .map_or(default_name, |n| n.text().into_owned());
    if name == "_" || name == "." {
        return;
    }
    match package {
        Some(package) => {
            state.packages.insert(name, package);
        }
        // An import that rebinds a name this pass seeded — `import os "fmt"` —
        // must remove the seeded meaning rather than leave it standing.
        None => {
            state.packages.remove(&name);
        }
    }
}

fn assign(
    node: &Syntax<'_>,
    state: &mut State,
    depth: usize,
    remaining: &mut usize,
    hits: &mut Vec<CredentialFileWrite>,
) -> Result<(), &'static str> {
    let names: Vec<String> = node
        .field("left")
        .or_else(|| node.field("name"))
        .map(|left| {
            if left.kind() == "expression_list" || left.kind() == "identifier_list" {
                left.children()
                    .filter(Syntax::is_named)
                    .map(|child| child.text().into_owned())
                    .collect()
            } else {
                vec![left.text().into_owned()]
            }
        })
        .unwrap_or_default();

    let rights: Vec<Syntax<'_>> = node
        .field("right")
        .or_else(|| node.field("value"))
        .map(|right| {
            if right.kind() == "expression_list" {
                right.children().filter(Syntax::is_named).collect()
            } else {
                vec![right]
            }
        })
        .unwrap_or_default();

    // The right-hand side runs first, and a sink call there is a write even
    // when its handle is never used: `f, _ := os.OpenFile(key, os.O_WRONLY, 0)`
    // has already opened the file for writing by the time `f` exists.
    for right in &rights {
        visit(right.clone(), state, depth + 1, remaining, hits)?;
    }

    // One right-hand side per name is the straightforward case.
    //
    // The other case that matters is Go's universal `value, err := call()`
    // idiom: one expression, several names, the value first. `home, _ :=
    // os.UserHomeDir()` is the ordinary way to write the shape this pass most
    // needs to follow, so the first name takes the call's value and the rest
    // are cleared. Nothing is guessed by it — a call this pass cannot value
    // binds nothing, which is why `f, _ := os.OpenFile(…)` leaves `f` unbound
    // rather than pretending the handle is a path.
    let single_multi_bind = rights.len() == 1 && names.len() > 1;
    if names.len() == rights.len() || single_multi_bind {
        for (index, name) in names.iter().enumerate() {
            let assigned = rights
                .get(if single_multi_bind { 0 } else { index })
                .filter(|_| !single_multi_bind || index == 0)
                .and_then(|right| value(right, state, 0));
            match assigned {
                Some(datum) => {
                    state.values.insert(name.clone(), datum);
                }
                None => {
                    state.values.remove(name);
                }
            }
        }
    } else {
        for name in &names {
            state.values.remove(name);
        }
    }
    Ok(())
}

/// The package and function a call names, when it is one this pass owns.
fn sink(node: &Syntax<'_>, state: &State) -> Option<(Pkg, String)> {
    let function = node.field("function")?;
    if function.kind() != "selector_expression" {
        return None;
    }
    let operand = function.field("operand")?;
    if operand.kind() != "identifier" {
        return None;
    }
    let package = *state.packages.get(operand.text().as_ref())?;
    Some((package, function.field("field")?.text().into_owned()))
}

fn arg<'a>(node: &Syntax<'a>, index: usize) -> Option<Syntax<'a>> {
    super::arguments(node).into_iter().nth(index)
}

fn inspect_call(node: &Syntax<'_>, state: &State, hits: &mut Vec<CredentialFileWrite>) {
    let Some((package, name)) = sink(node, state) else {
        return;
    };
    let target = |index: usize| arg(node, index).and_then(|a| path(&a, state));
    let mut record = |path, access| {
        record_write(hits, node.range(), &format!("Go {name}"), path, access);
    };

    match (package, name.as_str()) {
        // Unambiguous truncating writes: no flags to read.
        (Pkg::Os | Pkg::Ioutil, "WriteFile") | (Pkg::Os, "Create" | "Truncate") => {
            if let Some(path) = target(0) {
                record(path, Access::Write);
            }
        }
        (Pkg::Os, "OpenFile") => {
            let flags = arg(node, 1).and_then(|a| value(&a, state, 0));
            let Some(access) = flag_access(flags) else {
                return;
            };
            if let Some(path) = target(0) {
                record(path, access);
            }
        }
        // A rename replaces the destination and removes the source, so both
        // ends are judged — the same treatment the other passes give a rename.
        (Pkg::Os, "Rename") => {
            for index in 0..=1 {
                if let Some(path) = target(index) {
                    record(path, Access::Write);
                }
            }
        }
        _ => {}
    }
}

/// What an `os.OpenFile` flag expression proves about the access.
///
/// `None` means "not proven to write", which is also what an unreadable flag
/// expression returns. That is the fail-open direction the rest of this module
/// takes on a destination it cannot resolve, and the reason it is right here
/// too: `os.OpenFile` is the one Go sink that is routinely a *read*, so
/// treating an unknown flag word as a write would deny reading a protected
/// file — which this policy explicitly allows.
fn flag_access(flags: Option<Datum>) -> Option<Access> {
    let Some(Datum::Flags(bits)) = flags else {
        return None;
    };
    if bits & FLAG_APPEND != 0 {
        return Some(Access::Append);
    }
    if bits & FLAG_WRITE != 0 {
        // A proven write flag alongside an unreadable operand still opens the
        // file for writing; the unknown part can only add access, never
        // remove it.
        return Some(Access::Write);
    }
    None
}

fn path(node: &Syntax<'_>, state: &State) -> Option<ResolvedPath> {
    match value(node, state, 0)? {
        Datum::Text(path) => Some(path),
        Datum::Flags(_) => None,
    }
}

fn value(node: &Syntax<'_>, state: &State, depth: usize) -> Option<Datum> {
    if depth > 24 {
        return None;
    }
    match node.kind().as_ref() {
        "identifier" => state.values.get(node.text().as_ref()).cloned(),
        "interpreted_string_literal" | "raw_string_literal" => {
            let text = string_literal(node)?;
            (text.len() <= MAX_STATIC_PATH_BYTES).then_some(Datum::Text((text, false)))
        }
        "parenthesized_expression" => node
            .children()
            .find(Syntax::is_named)
            .and_then(|inner| value(&inner, state, depth + 1)),
        "selector_expression" => open_flag(node, state),
        "binary_expression" => binary(node, state, depth),
        "call_expression" => call_value(node, state, depth),
        _ => None,
    }
}

fn binary(node: &Syntax<'_>, state: &State, depth: usize) -> Option<Datum> {
    let left = node.field("left")?;
    let right = node.field("right")?;
    let operator = node.field("operator").map(|op| op.text().into_owned());
    let left_value = value(&left, state, depth + 1);
    let right_value = value(&right, state, depth + 1);
    match operator.as_deref() {
        // Go's string concatenation.
        Some("+") => {
            let (Datum::Text(left), Datum::Text(right)) = (left_value?, right_value?) else {
                return None;
            };
            let joined =
                super::concatenate_text(super::path_as_text(left), super::path_as_text(right))?;
            Some(Datum::Text(super::resolved_path(joined)?))
        }
        // The flag union. An unreadable side contributes UNKNOWN rather than
        // ending the expression, so `os.O_APPEND|extra` still proves append.
        Some("|") => match (left_value, right_value) {
            (Some(Datum::Flags(left)), Some(Datum::Flags(right))) => {
                Some(Datum::Flags(left | right))
            }
            (Some(Datum::Flags(bits)), _) | (_, Some(Datum::Flags(bits))) => {
                Some(Datum::Flags(bits | FLAG_UNKNOWN))
            }
            _ => None,
        },
        _ => None,
    }
}

/// `os.O_*` read as its semantic effect, never as a numeric value: the native
/// constants differ between platforms and this pass never sees a target OS.
fn open_flag(node: &Syntax<'_>, state: &State) -> Option<Datum> {
    let operand = node.field("operand")?;
    if operand.kind() != "identifier"
        || state.packages.get(operand.text().as_ref()) != Some(&Pkg::Os)
    {
        return None;
    }
    match node.field("field")?.text().as_ref() {
        "O_APPEND" => Some(Datum::Flags(FLAG_APPEND)),
        "O_WRONLY" | "O_RDWR" | "O_CREATE" | "O_TRUNC" | "O_EXCL" => Some(Datum::Flags(FLAG_WRITE)),
        "O_RDONLY" | "O_SYNC" | "O_NOFOLLOW" => Some(Datum::Flags(0)),
        _ => None,
    }
}

fn call_value(node: &Syntax<'_>, state: &State, depth: usize) -> Option<Datum> {
    let (package, name) = sink(node, state)?;
    match (package, name.as_str()) {
        // The two ways a Go program asks for the home directory. Both produce
        // the symbolic `~` the shared policy expands, never this host's HOME.
        (Pkg::Os, "UserHomeDir") => Some(Datum::Text(("~".into(), true))),
        (Pkg::Os, "Getenv") => {
            let key = arg(node, 0).and_then(|a| string_literal(&a))?;
            (key == "HOME").then(|| Datum::Text(("~".into(), true)))
        }
        // `filepath.Join` is not `os.path.join`: an absolute element does NOT
        // reset the result, it is appended like any other. `Join("/a", "/b")`
        // is `/a/b`.
        (Pkg::Filepath, "Join") => {
            let mut joined: Option<ResolvedPath> = None;
            for argument in super::arguments(node) {
                let Some(Datum::Text(next)) = value(&argument, state, depth + 1) else {
                    return None;
                };
                joined = Some(match joined {
                    None => next,
                    Some(base) => join(base, next)?,
                });
            }
            joined.map(Datum::Text)
        }
        _ => None,
    }
}

/// `filepath.Join` semantics, minus the `Clean` pass: a `..` element is left
/// in place rather than resolved here, because the shared path table already
/// refuses a spelling that climbs out of its root.
fn join((mut base, home): ResolvedPath, (next, next_home): ResolvedPath) -> Option<ResolvedPath> {
    if base.is_empty() {
        return Some((next, next_home));
    }
    if next.is_empty() {
        return Some((base, home));
    }
    // A runtime home token is only a path root once a separator has
    // established its boundary; `~` joined to `other` is not `~other`.
    if home && base == "~" {
        base.push('/');
        base.push_str(&next);
        return (base.len() <= MAX_STATIC_PATH_BYTES).then_some((base, true));
    }
    if next_home {
        return None;
    }
    if !base.ends_with('/') {
        base.push('/');
    }
    base.push_str(next.trim_start_matches('/'));
    (base.len() <= MAX_STATIC_PATH_BYTES).then_some((base, home))
}

/// The text of a Go string literal, with the escapes that can change a path.
fn string_literal(node: &Syntax<'_>) -> Option<String> {
    let raw = node.text();
    let raw = raw.as_ref();
    if let Some(inner) = raw.strip_prefix('`').and_then(|r| r.strip_suffix('`')) {
        // A raw literal has no escapes at all.
        return Some(inner.to_string());
    }
    let inner = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"'))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '/' => out.push('/'),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            '0' => out.push('\0'),
            // A numeric or unicode escape can spell a separator, so a path
            // carrying one is not resolved rather than resolved wrongly.
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
#[path = "go/tests.rs"]
mod tests;

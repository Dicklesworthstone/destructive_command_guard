//! Bounded Perl protected-write fallback. Perl has no ast-grep grammar.
//!
//! A linear token regex separates executable words from comments and quoted
//! data. Only open/sysopen/truncate, scalar constants, concatenation and proven Fcntl
//! flags are interpreted. This is not a Perl parser or a runtime evaluator.

use super::{
    Access, Bindings, CredentialFileWrite, MAX_BYTES, MAX_DEPTH, MAX_NODES, MAX_STATIC_PATH_BYTES,
    OpenFlags, ResolvedPath, Value, combine_open_flags, concatenate_text, record_write,
    resolved_path,
};
use regex::Regex;
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::LazyLock;

static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
    r#"(?xs)\A(?:\s+|\#[^\n]*|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|\$[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*|[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*|\.=|\|=|=>|->|\|\||&&|=~|!~|[^\s])"#
).expect("Perl token regex is valid")
});

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Word,
    Variable,
    Quoted(bool),
    Words,
    Opaque,
    Punctuation,
}

#[derive(Clone, Debug)]
struct Token<'a> {
    text: &'a str,
    kind: Kind,
    span: Range<usize>,
}

struct State {
    values: Bindings,
    handles: HashMap<String, (ResolvedPath, Access)>,
    imports: HashSet<String>,
    fcntl: bool,
    home: bool,
    shadowed: HashSet<String>,
    work: Cell<usize>,
}

/// Bound total token visits as well as source size and nesting. Otherwise
/// overlapping argument scans could keep a quadratic worker alive after the
/// caller's wall-clock deadline has expired.
fn charge(work: &Cell<usize>) -> Result<(), &'static str> {
    let left = work
        .get()
        .checked_sub(1)
        .ok_or("protected-write Perl exceeds the work limit")?;
    work.set(left);
    Ok(())
}

pub(super) fn scan(code: &str) -> Result<Vec<CredentialFileWrite>, &'static str> {
    if code.len() > MAX_BYTES {
        return Err("protected-write Perl source exceeds the byte limit");
    }
    let tokens = lex(code)?;
    let mut state = State {
        values: Bindings::new(),
        handles: HashMap::new(),
        imports: HashSet::new(),
        fcntl: false,
        home: true,
        shadowed: HashSet::new(),
        work: Cell::new(MAX_NODES * 8),
    };
    // Bare calls can be overridden by a declared sub, even when its body is
    // later in the source. CORE::open/sysopen remain unambiguous.
    for pair in tokens.windows(2) {
        if pair[0].text == "sub" {
            state.shadowed.insert(pair[1].text.to_string());
        }
    }
    let mut hits = Vec::new();
    let mut pending: Vec<(usize, String, Option<Value>)> = Vec::new();
    for index in 0..tokens.len() {
        while pending.last().is_some_and(|(end, _, _)| *end <= index) {
            if let Some((_, name, value)) = pending.pop() {
                state.values.remove(&name);
                state.handles.remove(&name);
                if let Some(value) = value {
                    state.values.insert(name, value);
                }
            }
        }
        if state.values.len() + state.handles.len() > 1024 || pending.len() > MAX_DEPTH {
            return Err("protected-write Perl source exceeds the binding limit");
        }
        let token = &tokens[index];
        if matches!(token.text, "use" | "require")
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.text == "Fcntl")
        {
            state.fcntl = true;
            if token.text == "use" {
                let end = statement_end(&tokens, index + 2, &state.work)?;
                let options = &tokens[index + 2..end];
                if options.is_empty() {
                    state.imports.insert(":DEFAULT".into());
                }
                for option in options {
                    if matches!(option.kind, Kind::Words | Kind::Quoted(_)) {
                        state
                            .imports
                            .extend(option.text.split_whitespace().map(str::to_string));
                    }
                }
            }
        }
        if token.kind == Kind::Variable {
            if token.text == "$ENV" && tokens.get(index + 1).is_some_and(|next| next.text == "{") {
                let end = matching_end(&tokens, index + 1, &state.work)?;
                if tokens
                    .get(end + 1)
                    .is_some_and(|next| matches!(next.text, "=" | ".=" | "|="))
                {
                    state.home = false;
                }
            }
            if let Some(operator) = tokens
                .get(index + 1)
                .filter(|next| matches!(next.text, "=" | ".=" | "|=" | "+=" | "-="))
            {
                let end = statement_end(&tokens, index + 2, &state.work)?;
                let right = value(&tokens[index + 2..end], &state, 0);
                let before = state.values.get(token.text).cloned();
                let assigned = match operator.text {
                    "=" => right,
                    ".=" => before
                        .and_then(|left| right.and_then(|right| concatenate_text(left, right))),
                    "|=" => combine_open_flags(before, right),
                    _ => None,
                };
                // RHS calls see the old binding; a deferred update cannot hide
                // an open in `$p = open(..., $p)`.
                pending.push((end, token.text.to_string(), assigned));
            }
        }
        let api = token.text.strip_prefix("CORE::").unwrap_or(token.text);
        if token.kind != Kind::Word
            || !matches!(
                api,
                "open"
                    | "sysopen"
                    | "truncate"
                    | "close"
                    // Transfers (#484). `rename`, `symlink` and `link` are
                    // builtins; `copy`/`move`/`cp`/`mv` come from File::Copy,
                    // which exports them into the caller's namespace, so they
                    // are read unqualified the way the module is actually used.
                    | "rename"
                    | "symlink"
                    | "link"
                    | "copy"
                    | "move"
                    | "cp"
                    | "mv"
            )
        {
            continue;
        }
        if token.text == api && state.shadowed.contains(api) {
            continue;
        }
        if index > 0 && matches!(tokens[index - 1].text, "->" | "sub" | "&") {
            continue;
        }
        let (args, end) = call_arguments(&tokens, index + 1, &state.work)?;
        let handle = args.first().copied().and_then(handle_name);
        if api == "close" {
            if let Some(name) = handle {
                state.handles.remove(name);
            }
            continue;
        }
        let finding = if api == "open" {
            match args.as_slice() {
                [_, specification] => two_argument_open(specification, &state),
                [_, mode, path] => {
                    let access = value(mode, &state, 0).and_then(|value| match value {
                        Value::Text(mode) => mode_access(&mode),
                        _ => None,
                    });
                    access.and_then(|access| {
                        value(path, &state, 0)
                            .and_then(resolved_path)
                            .map(|path| (path, access))
                    })
                }
                _ => None,
            }
        } else if api == "truncate" && args.len() == 2 {
            if let Some((path, access)) = handle.and_then(|name| state.handles.get(name)) {
                (*access != Access::Read).then(|| (path.clone(), Access::Write))
            } else {
                value(args[0], &state, 0)
                    .and_then(resolved_path)
                    .map(|path| (path, Access::Write))
            }
        } else if api == "sysopen" && matches!(args.len(), 3 | 4) {
            let flags = value(args[2], &state, 0).and_then(|value| match value {
                Value::Flags(flags) => flags.access(),
                _ => None,
            });
            flags.and_then(|access| {
                value(args[1], &state, 0)
                    .and_then(resolved_path)
                    .map(|path| (path, access))
            })
        } else if is_transfer(api) && args.len() == 2 {
            // The destination is argument 1 in every one of them: `rename(from,
            // to)`, `symlink(target, link)`, `link(old, new)`, `copy(from, to)`
            // and `move(from, to)` (#484). The source end is judged separately
            // below, because a rename or move destroys a protected file by
            // taking its NAME away, not by writing over it.
            value(args[1], &state, 0)
                .and_then(resolved_path)
                .map(|path| (path, Access::Write))
        } else {
            None
        };
        // `symlink`, `link` and `copy` read their source and leave it in place,
        // so only a move removes one.
        let removed_source = if matches!(api, "rename" | "move" | "mv") && args.len() == 2 {
            value(args[0], &state, 0)
                .and_then(resolved_path)
                .map(|path| (path, Access::Write))
        } else {
            None
        };
        if matches!(api, "open" | "sysopen") {
            if let Some(name) = handle {
                // A filehandle target is an output, not a path-valued scalar.
                // Reopening it with an unresolved target also kills old proof.
                state.values.remove(name);
                state.handles.remove(name);
                if let Some(finding) = &finding {
                    state.handles.insert(name.to_string(), finding.clone());
                }
            }
        }
        for (path, access) in finding.into_iter().chain(removed_source) {
            let end = tokens
                .get(end.saturating_sub(1))
                .map_or(token.span.end, |last| last.span.end);
            record_write(
                &mut hits,
                token.span.start..end,
                &format!("Perl {api}"),
                path,
                access,
            );
        }
    }
    charge(&state.work)?;
    Ok(hits)
}

/// The two-argument transfer verbs, builtin or File::Copy (#484).
fn is_transfer(api: &str) -> bool {
    matches!(
        api,
        "rename" | "symlink" | "link" | "copy" | "move" | "cp" | "mv"
    )
}

fn handle_name<'a>(tokens: &[Token<'a>]) -> Option<&'a str> {
    let token = match tokens {
        [token] => token,
        [declaration, token] if matches!(declaration.text, "my" | "our" | "local") => token,
        _ => return None,
    };
    matches!(token.kind, Kind::Variable | Kind::Word).then_some(token.text)
}

fn lex(code: &str) -> Result<Vec<Token<'_>>, &'static str> {
    let mut tokens: Vec<Token<'_>> = Vec::new();
    let mut heredocs = Vec::new();
    let mut offset = 0;
    while offset < code.len() {
        if tokens.len() >= MAX_NODES {
            return Err("protected-write Perl source exceeds the token limit");
        }
        let rest = &code[offset..];
        let line_start = offset == 0 || code.as_bytes()[offset - 1] == b'\n';
        if line_start
            && matches!(
                rest.lines().next().unwrap_or("").trim_end(),
                "__DATA__" | "__END__"
            )
        {
            break;
        }
        if line_start
            && rest.starts_with('=')
            && rest.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
        {
            if let Some(end) = rest.find("\n=cut") {
                offset += end + 5;
                offset += code[offset..].find('\n').unwrap_or(code.len() - offset);
                continue;
            }
            break;
        }
        if let Some((label, indented, end)) = heredoc_header(code, offset)?
            && crate::heredoc::is_literal_perl_print_heredoc(code, offset..end)
        {
            if heredocs.len() == MAX_DEPTH {
                return Err("protected-write Perl exceeds the heredoc limit");
            }
            heredocs.push((label, indented));
            tokens.push(Token {
                text: &code[offset..end],
                kind: Kind::Opaque,
                span: offset..end,
            });
            offset = end;
            continue;
        }
        let found = TOKEN
            .find(rest)
            .ok_or("protected-write Perl tokenization failed")?;
        let raw = found.as_str();
        let start = offset;
        offset += raw.len();
        if !heredocs.is_empty() && raw.chars().all(char::is_whitespace) {
            if let Some(newline) = raw.find('\n') {
                offset = start + newline + 1;
                for (label, indented) in std::mem::take(&mut heredocs) {
                    offset = heredoc_end(code, offset, label, indented)?;
                }
                continue;
            }
        }
        if raw.starts_with('#') || raw.chars().all(char::is_whitespace) {
            continue;
        }
        let mut kind = if raw.starts_with('$') {
            Kind::Variable
        } else if raw.starts_with(['\'', '"']) {
            Kind::Quoted(raw.starts_with('"'))
        } else if raw.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            || raw.starts_with('_')
        {
            Kind::Word
        } else {
            Kind::Punctuation
        };
        let mut text = raw;
        if matches!(kind, Kind::Quoted(_)) {
            if raw.len() < 2 {
                return Err("protected-write Perl has an unterminated quote");
            }
            text = &raw[1..raw.len() - 1];
        } else if matches!(
            raw,
            "q" | "qq" | "qw" | "qx" | "qr" | "m" | "s" | "tr" | "y"
        ) {
            let delimiter = offset + code[offset..].len() - code[offset..].trim_start().len();
            if code[delimiter..]
                .chars()
                .next()
                .is_some_and(|ch| !ch.is_alphanumeric() && !ch.is_whitespace() && ch != '_')
            {
                let (body, end) = quoted_span(code, delimiter)?;
                text = &code[body];
                offset = end;
                kind = match raw {
                    "q" => Kind::Quoted(false),
                    "qq" => Kind::Quoted(true),
                    "qw" => Kind::Words,
                    _ => Kind::Opaque,
                };
                if matches!(raw, "s" | "tr" | "y") {
                    let paired = matches!(code.as_bytes()[delimiter], b'(' | b'[' | b'{' | b'<');
                    let second = if paired { offset } else { offset - 1 };
                    let (_, end) = quoted_span(code, second)?;
                    offset = end;
                }
            }
        } else if raw == "`"
            || (raw == "/"
                && tokens.last().is_none_or(|last| {
                    matches!(
                        last.text,
                        "=" | "=~" | "!~" | "(" | "," | "print" | "say" | "return"
                    )
                }))
        {
            let (_, end) = quoted_span(code, start)?;
            offset = end;
            kind = Kind::Opaque;
        }
        if matches!(raw, "'" | "\"") {
            return Err("protected-write Perl has an unterminated quote");
        }
        tokens.push(Token {
            text,
            kind,
            span: start..offset,
        });
    }
    if !heredocs.is_empty() {
        return Err("protected-write Perl has an unterminated heredoc");
    }
    Ok(tokens)
}

/// Locate a Perl heredoc header. The caller skips its body ONLY for a proven
/// literal print statement; eval-fed and interpolating bodies remain visible
/// to the conservative fallback just as they were before data skipping.
fn heredoc_header(code: &str, start: usize) -> Result<Option<(&str, bool, usize)>, &'static str> {
    let Some(rest) = code[start..].strip_prefix("<<") else {
        return Ok(None);
    };
    let indented = rest.starts_with('~');
    let start = start + 2 + usize::from(indented);
    let rest = &code[start..];
    let trimmed = rest.trim_start_matches([' ', '\t']);
    let spaced = rest.len() != trimmed.len();
    let position = start + rest.len() - trimmed.len();
    let Some(first) = trimmed.chars().next() else {
        return Ok(None);
    };
    if matches!(first, '\'' | '"' | '`') {
        let (body, end) = quoted_span(code, position)?;
        let label = &code[body];
        if label.contains(['\n', '\r', '\\']) {
            return Err("protected-write Perl has an unsupported heredoc delimiter");
        }
        return Ok(Some((label, indented, end)));
    }
    if spaced {
        return Ok(None);
    }
    let position = position + usize::from(first == '\\');
    let rest = &code[position..];
    if !rest
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return Ok(None);
    }
    let length = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    Ok(Some((&rest[..length], indented, position + length)))
}

fn heredoc_end(
    code: &str,
    mut offset: usize,
    label: &str,
    indented: bool,
) -> Result<usize, &'static str> {
    while offset < code.len() {
        let rest = &code[offset..];
        let length = rest.find('\n').unwrap_or(rest.len());
        let line = rest[..length].trim_end_matches('\r');
        let line = if indented {
            line.trim_start_matches([' ', '\t'])
        } else {
            line
        };
        offset += length + usize::from(length < rest.len());
        if line == label {
            return Ok(offset);
        }
    }
    Err("protected-write Perl has an unterminated heredoc")
}

fn quoted_span(code: &str, start: usize) -> Result<(Range<usize>, usize), &'static str> {
    let open = code[start..]
        .chars()
        .next()
        .ok_or("missing Perl quote delimiter")?;
    let close = match open {
        '(' => ')',
        '[' => ']',
        '{' => '}',
        '<' => '>',
        _ => open,
    };
    let body = start + open.len_utf8();
    let mut depth = 1;
    let mut escaped = false;
    for (offset, ch) in code[body..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == close {
            depth -= 1;
            if depth == 0 {
                return Ok((body..body + offset, body + offset + ch.len_utf8()));
            }
        } else if open != close && ch == open {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err("protected-write Perl quote exceeds the nesting limit");
            }
        }
    }
    Err("protected-write Perl has an unterminated quote")
}

fn matching_end(
    tokens: &[Token<'_>],
    start: usize,
    work: &Cell<usize>,
) -> Result<usize, &'static str> {
    let mut stack = Vec::new();
    for (index, token) in tokens.iter().enumerate().skip(start) {
        charge(work)?;
        if token.kind != Kind::Punctuation {
            continue;
        }
        match token.text {
            "(" => stack.push(")"),
            "[" => stack.push("]"),
            "{" => stack.push("}"),
            ")" | "]" | "}" => {
                if stack.pop() != Some(token.text) {
                    return Err("protected-write Perl has mismatched delimiters");
                }
                if stack.is_empty() {
                    return Ok(index);
                }
            }
            _ => {}
        }
        if stack.len() > MAX_DEPTH {
            return Err("protected-write Perl exceeds the nesting limit");
        }
    }
    Err("protected-write Perl has an unterminated argument list")
}

fn statement_end(
    tokens: &[Token<'_>],
    start: usize,
    work: &Cell<usize>,
) -> Result<usize, &'static str> {
    let mut index = start;
    while let Some(token) = tokens.get(index) {
        charge(work)?;
        if token.kind == Kind::Punctuation && matches!(token.text, "(" | "[" | "{") {
            index = matching_end(tokens, index, work)? + 1;
        } else if (token.kind == Kind::Punctuation && matches!(token.text, ";" | "}" | "||" | "&&"))
            || (token.kind == Kind::Word && matches!(token.text, "or" | "and"))
        {
            return Ok(index);
        } else {
            index += 1;
        }
    }
    Ok(index)
}

fn call_arguments<'a, 's>(
    tokens: &'a [Token<'s>],
    start: usize,
    work: &Cell<usize>,
) -> Result<(Vec<&'a [Token<'s>]>, usize), &'static str> {
    let parenthesized = tokens
        .get(start)
        .is_some_and(|token| token.text == "(" && token.kind == Kind::Punctuation);
    let end = if parenthesized {
        matching_end(tokens, start, work)?
    } else {
        statement_end(tokens, start, work)?
    };
    let mut begin = start + usize::from(parenthesized);
    let mut index = begin;
    let mut args = Vec::new();
    while index < end {
        charge(work)?;
        let token = &tokens[index];
        if token.kind == Kind::Punctuation && matches!(token.text, "(" | "[" | "{") {
            index = matching_end(tokens, index, work)? + 1;
        } else {
            if token.kind == Kind::Punctuation && token.text == "," {
                args.push(&tokens[begin..index]);
                begin = index + 1;
            }
            index += 1;
        }
    }
    if begin < end {
        args.push(&tokens[begin..end]);
    }
    Ok((args, end + usize::from(parenthesized)))
}

fn value(tokens: &[Token<'_>], state: &State, depth: usize) -> Option<Value> {
    charge(&state.work).ok()?;
    if depth > 24 || tokens.len() > 1024 {
        return None;
    }
    if tokens
        .first()
        .is_some_and(|token| token.text == "(" && token.kind == Kind::Punctuation)
        && matching_end(tokens, 0, &state.work).ok()? == tokens.len() - 1
    {
        return value(&tokens[1..tokens.len() - 1], state, depth + 1);
    }
    for operator in ["|", "."] {
        let mut index = 0;
        let mut split = None;
        while index < tokens.len() {
            charge(&state.work).ok()?;
            let token = &tokens[index];
            if token.kind == Kind::Punctuation && matches!(token.text, "(" | "[" | "{") {
                index = matching_end(tokens, index, &state.work).ok()? + 1;
            } else {
                if token.kind == Kind::Punctuation && token.text == operator {
                    split = Some(index);
                }
                index += 1;
            }
        }
        if let Some(index) = split {
            let left = value(&tokens[..index], state, depth + 1);
            let right = value(&tokens[index + 1..], state, depth + 1);
            return if operator == "|" {
                combine_open_flags(left, right)
            } else {
                concatenate_text(left?, right?)
            };
        }
    }
    if let [variable, open, key, close] = tokens {
        if state.home
            && variable.text == "$ENV"
            && open.text == "{"
            && close.text == "}"
            && (key.text == "HOME"
                || matches!(value(std::slice::from_ref(key), state, depth + 1), Some(Value::Text(ref key)) if key == "HOME"))
        {
            return Some(Value::HomePath("~".into()));
        }
    }
    let token = match tokens {
        [token] => token,
        [token, open, close] if open.text == "(" && close.text == ")" => token,
        _ => return None,
    };
    match token.kind {
        Kind::Quoted(double) => string_value(token.text, double, state),
        Kind::Variable => state.values.get(token.text).cloned(),
        Kind::Word => {
            let name = if let Some(name) = token.text.strip_prefix("Fcntl::") {
                if !state.fcntl {
                    return None;
                }
                name
            } else {
                if state.shadowed.contains(token.text)
                    || !(state.imports.contains(":DEFAULT") || state.imports.contains(token.text))
                {
                    return None;
                }
                token.text
            };
            OpenFlags::prefixed(name).map(Value::Flags)
        }
        _ => None,
    }
}

fn string_value(body: &str, double: bool, state: &State) -> Option<Value> {
    if body.len() > MAX_STATIC_PATH_BYTES {
        return None;
    }
    let mut result = Value::Text(String::new());
    let mut literal = String::new();
    let mut chars = body.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch == '\\' {
            let (_, escaped) = chars.next()?;
            if !double {
                if !matches!(escaped, '\\' | '\'') {
                    literal.push('\\');
                }
                literal.push(escaped);
                continue;
            }
            match escaped {
                '\\' | '"' | '$' | '@' | '/' => literal.push(escaped),
                'n' => literal.push('\n'),
                'r' => literal.push('\r'),
                't' => literal.push('\t'),
                '0'..='7' | 'x' => {
                    let radix = if escaped == 'x' { 16 } else { 8 };
                    let mut digits = if escaped == 'x' {
                        String::new()
                    } else {
                        escaped.to_string()
                    };
                    let limit = if radix == 16 { 2 } else { 3 };
                    while digits.len() < limit
                        && chars.peek().is_some_and(|(_, c)| c.is_digit(radix))
                    {
                        digits.push(chars.next()?.1);
                    }
                    let number = u32::from_str_radix(&digits, radix).ok()?;
                    if number > 127 {
                        return None;
                    }
                    literal.push(char::from_u32(number)?);
                }
                _ => return None,
            }
        } else if double && ch == '$' {
            result = concatenate_text(result, Value::Text(std::mem::take(&mut literal)))?;
            let mut name = String::from("$");
            while chars
                .peek()
                .is_some_and(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
            {
                name.push(chars.next()?.1);
            }
            let variable = if name == "$ENV" && chars.peek().is_some_and(|(_, c)| *c == '{') {
                chars.next();
                let mut key = String::new();
                while chars.peek().is_some_and(|(_, c)| *c != '}') {
                    key.push(chars.next()?.1);
                }
                if chars.next()?.1 != '}'
                    || !state.home
                    || key.trim_matches(['\'', '"', ' ']) != "HOME"
                {
                    return None;
                }
                Value::HomePath("~".into())
            } else {
                state.values.get(&name)?.clone()
            };
            result = concatenate_text(result, variable)?;
        } else if double && ch == '@' {
            return None;
        } else {
            literal.push(ch);
        }
    }
    concatenate_text(result, Value::Text(literal))
}

fn mode_access(mode: &str) -> Option<Access> {
    match mode.split(':').next()?.trim() {
        "<" => Some(Access::Read),
        ">>" | "+>>" => Some(Access::Append),
        ">" | "+>" | "+<" => Some(Access::Write),
        // Pipes and descriptor duplication are not pathname opens.
        _ => None,
    }
}

fn fused_mode(specification: &str) -> Option<(&str, Access)> {
    let specification = specification.trim();
    if specification.ends_with('|') {
        return None;
    }
    for (mode, access) in [
        ("+>>", Access::Append),
        (">>", Access::Append),
        ("+<", Access::Write),
        ("+>", Access::Write),
        (">", Access::Write),
        ("<", Access::Read),
    ] {
        if let Some(path) = specification.strip_prefix(mode) {
            let path = path.trim_start();
            if path.starts_with(['&', '|', ':']) {
                return None;
            }
            return Some((path, access));
        }
    }
    None
}

fn two_argument_open(tokens: &[Token<'_>], state: &State) -> Option<(ResolvedPath, Access)> {
    if let Some(first) = tokens
        .first()
        .filter(|token| matches!(token.kind, Kind::Quoted(_)))
    {
        // Remove the open-mode syntax BEFORE folding interpolation: the `>>`
        // prefix is not a literal path prefix that could discard HOME proof.
        let (body, access) = fused_mode(first.text)?;
        let mut path_tokens = tokens.to_vec();
        path_tokens[0].text = body;
        return value(&path_tokens, state, 0)
            .and_then(resolved_path)
            .map(|path| (path, access));
    }
    let Value::Text(specification) = value(tokens, state, 0)? else {
        return None;
    };
    let (path, access) = fused_mode(&specification)?;
    Some(((path.to_string(), false), access))
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
    fn perl_open_modes_and_delivery_syntax() {
        for mode in [">", ">>", "+<", "+>", "+>>", ">>:encoding(UTF-8)"] {
            denied(&format!("open(my $fh, '{mode}', '/etc/shadow');"));
        }
        for code in [
            "open FH, '>', '/etc/shadow';",
            "CORE::open(my $fh, '+<', '/etc/shadow');",
            "open(FH, '>/etc/shadow');",
            "open FH, '>>/home/u/.bashrc';",
            "open(FH, q(>/etc/shadow));",
            "$p = '/etc/' . 'shadow'; open(my $fh, '>', $p);",
            "$p = $ENV{HOME}; $p .= '/.bashrc'; open FH, '>>', $p;",
            "open(FH, \"+<$ENV{HOME}/.bashrc\");",
            "open(FH, '>>' . $ENV{'HOME'} . '/.ssh/authorized_keys');",
            "open(FH, '>', \"/etc/\\x73hadow\");",
        ] {
            denied(code);
        }
        for code in [
            "open(my $fh, '<', '/etc/shadow');",
            "open(my $fh, '>', '/tmp/out');",
            "open(my $fh, '>>', '/home/u/.ssh/known_hosts');",
            "open(my $fh, '+>>', '/home/u/.ssh/known_hosts');",
            "open(my $fh, '>', '/home/u/.ssh/id_rsa.pub');",
            "open(FH, '>', '~/.bashrc');",
            "open(FH, '|-', '/etc/shadow');",
            "open(FH, '>&', '/etc/shadow');",
            "$p = '/etc/shadow'; $p = '/tmp/out'; open FH, '>', $p;",
            "$p = '/etc/shadow'; $p = unknown(); open FH, '>', $p;",
            "$ENV{HOME} = '/tmp'; open FH, '>', $ENV{HOME} . '/.bashrc';",
        ] {
            allowed(code);
        }
    }

    #[test]
    fn perl_sysopen_flags_need_fcntl_provenance() {
        for code in [
            "use Fcntl; sysopen(my $fh, '/etc/shadow', O_WRONLY | O_CREAT);",
            "use Fcntl qw(:DEFAULT); sysopen FH, '/etc/shadow', O_RDWR;",
            "use Fcntl qw(O_WRONLY O_APPEND); sysopen FH, '/home/u/.bashrc', O_WRONLY | O_APPEND;",
            "use Fcntl (); sysopen(FH, '/etc/shadow', Fcntl::O_WRONLY());",
            "use Fcntl; sysopen(FH, '/home/u/.ssh/known_hosts', O_WRONLY | O_APPEND | O_TRUNC);",
            "use Fcntl; $flags = O_WRONLY | O_APPEND; $flags |= $unknown; sysopen FH, '/home/u/.ssh/known_hosts', $flags;",
        ] {
            denied(code);
        }
        for code in [
            "use Fcntl; sysopen FH, '/etc/shadow', O_RDONLY;",
            "use Fcntl; sysopen FH, '/home/u/.ssh/known_hosts', O_WRONLY | O_APPEND;",
            "use Fcntl; sysopen FH, '/tmp/out', O_WRONLY | O_CREAT;",
            "sysopen FH, '/etc/shadow', O_WRONLY;",
            "use Fcntl (); sysopen FH, '/etc/shadow', O_WRONLY;",
            "use Fcntl qw(O_RDONLY); sysopen FH, '/etc/shadow', O_WRONLY;",
            "use Fcntl; sysopen FH, '/etc/shadow', O_WRONLY & $unknown;",
        ] {
            allowed(code);
        }
    }

    #[test]
    fn perl_data_comments_and_unrelated_methods_are_not_sinks() {
        for code in [
            "# open(FH, '>', '/etc/shadow');",
            "print q{open(FH, '>', '/etc/shadow')};",
            "print qq{open(FH, '>', '/etc/shadow')};",
            "my $regex = qr{open(FH, '>', '/etc/shadow')};",
            r"my $regex = /open(FH, '>', '\/etc\/shadow')/;",
            "$object->open(FH, '>', '/etc/shadow');",
            "Other::open(FH, '>', '/etc/shadow');",
            "sub open { 1 }; open(FH, '>', '/etc/shadow');",
            "=pod\nopen(FH, '>', '/etc/shadow');\n=cut\nprint 'ok';",
            "print 'ok';\n__DATA__\nopen(FH, '>', '/etc/shadow');",
        ] {
            allowed(code);
        }
        denied("print q{ignored}; open(FH, '>', '/etc/shadow');");
    }

    #[test]
    fn perl_heredoc_data_and_shell_strings_are_not_perl_calls() {
        for code in [
            "print <<'DATA';\nopen(FH, '>', '/etc/shadow');\nDATA\n",
            "print <<~'DATA';\n  open(FH, '>', '/etc/shadow');\n  DATA\n",
            "print <<'FIRST';\nopen(FH, '>', '/etc/shadow');\nFIRST\nprint <<'SECOND';\nopen(FH, '>', '/etc/shadow');\nSECOND\n",
            "print qx{printf \"open(FH, '>', '/etc/shadow')\"};",
            "print `printf \"open(FH, '>', '/etc/shadow')\"`;",
        ] {
            allowed(code);
        }
        denied("print <<'DATA';\nopen(FH, '>', '/tmp/out');\nDATA\nopen(FH, '>', '/etc/shadow');");
        denied("__DATA__suffix(); open(FH, '>', '/etc/shadow');");
        assert!(scan("print <<'DATA';\nunterminated\n").is_err());
    }

    #[test]
    fn perl_truncation_does_not_inherit_the_append_exception() {
        for code in [
            "truncate('/etc/shadow', 0);",
            "truncate '/home/u/.ssh/known_hosts', 0;",
            "open(my $fh, '>>', '/home/u/.ssh/known_hosts'); truncate($fh, 0);",
            "open(FH, '>>', '/home/u/.ssh/known_hosts'); CORE::truncate FH, 0;",
            "use Fcntl; sysopen(FH, '/home/u/.ssh/known_hosts', O_WRONLY | O_APPEND); truncate(FH, 0);",
        ] {
            denied(code);
        }
        for code in [
            "truncate('/tmp/out', 0);",
            "open(FH, '<', '/etc/shadow'); truncate(FH, 0);",
            "open(FH, '>>', '/home/u/.ssh/known_hosts'); open(FH, '<', '/etc/shadow'); truncate(FH, 0);",
            "open(FH, '>>', '/home/u/.ssh/known_hosts'); open(FH, '>', $unknown); truncate(FH, 0);",
            "open(my $fh, '>>', '/home/u/.ssh/known_hosts'); $fh = unknown(); truncate($fh, 0);",
            "open(FH, '>>', '/home/u/.ssh/known_hosts'); close(FH); truncate(FH, 0);",
            "$p = '/etc/shadow'; open($p, '>', '/tmp/out'); truncate($p, 0);",
        ] {
            allowed(code);
        }
    }

    #[test]
    fn perl_overlapping_scans_have_an_aggregate_work_budget() {
        let code = format!("{}FH, '>', '/etc/shadow';", "open ".repeat(1000));
        assert_eq!(
            scan(&code).unwrap_err(),
            "protected-write Perl exceeds the work limit"
        );
    }

    #[test]
    fn perl_eval_and_interpolating_heredocs_remain_executable() {
        for code in [
            "eval <<'CODE';\nopen(FH, '>', '/etc/shadow');\nCODE",
            "print eval <<'CODE';\nopen(FH, '>', '/etc/shadow');\nCODE",
            "$program = <<'CODE';\nopen(FH, '>', '/etc/shadow');\nCODE\neval $program;",
            "print <<\"CODE\";\n${\\ do { open(FH, '>', '/etc/shadow'); '' }}\nCODE",
        ] {
            denied(code);
        }
    }

    #[test]
    fn perl_retains_rule_families_and_reports_bounds() {
        let hits =
            scan("open(FH, '>', '/home/u/.bashrc'); open(GIT, '>', '.git/config');").unwrap();
        assert_eq!(hits.len(), 2);
        assert_ne!(hits[0].rule, hits[1].rule);
        assert!(scan(&" ".repeat(MAX_BYTES + 1)).is_err());
        assert!(scan("open(FH, '>', '/etc/shadow'").is_err());
        assert!(scan("print 'unterminated").is_err());
        let code = format!(
            "open(FH, '>', {}'/etc/shadow'{});",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert!(scan(&code).is_err());
    }
}

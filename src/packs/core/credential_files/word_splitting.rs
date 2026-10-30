//! IFS-sensitive writer arguments must reach the native destination policy.
//!
//! This is an additional, bounded view of argv, not executable shell source.
//! It never executes a command, opens a path, or exempts the original source.

use super::{CredentialFileWrite, shell};
use crate::normalize::{NormalizeTokenKind, ShellDialect, strip_wrapper_prefixes};
use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;

#[cfg(test)]
const DEFAULT_IFS: &str = " \t\n";
const MAX_BYTES: usize = 64 * 1024;
const MAX_VALUE_BYTES: usize = 16 * 1024;
const MAX_FIELDS: usize = 128;
const MAX_EVENTS: usize = 256;
const MAX_BINDINGS: usize = 64;
const UNCERTAIN: &str = "Cannot verify writer destinations after an IFS change: an expansion, shell mutation, or analysis limit prevents bounded literal arguments. Quote scalar destinations or provide explicit arguments for review.";

#[derive(Default)]
struct State {
    values: HashMap<String, String>,
    ifs: Option<String>,
    changed: bool,
    attributes_unknown: bool,
}

impl State {
    fn forget(&mut self) {
        self.values.clear();
        self.ifs = None;
        self.changed = true;
    }

    fn value(&self, name: &str) -> Option<&str> {
        if name == "IFS" {
            self.ifs.as_deref()
        } else {
            self.values.get(name).map(String::as_str)
        }
    }

    fn assign(&mut self, raw: &str, certain: bool) {
        let continued = source_word_without_continuations(raw);
        let raw = continued.as_ref();
        let Some((name, append, rhs)) = assignment(raw) else {
            self.forget();
            return;
        };
        let mut value = literal(rhs).or_else(|| {
            scalar(rhs).and_then(|(dependency, _)| self.value(dependency).map(str::to_owned))
        });
        if value.is_none() && scalar(rhs).is_none() {
            // Complex expansions can assign other variables while evaluating
            // an otherwise ordinary assignment, e.g. A=${IFS:=@}.
            self.forget();
        }
        if append {
            value = self
                .value(name)
                .zip(value.as_deref())
                .and_then(|(before, after)| {
                    (before.len().saturating_add(after.len()) <= MAX_VALUE_BYTES)
                        .then(|| format!("{before}{after}"))
                });
        }
        if !certain
            || self.attributes_unknown
            || maintained_variable(name)
            || value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_VALUE_BYTES || value.contains('\0'))
        {
            value = None;
        }
        if name == "IFS" {
            self.ifs = value;
            self.changed = true;
        } else if let Some(value) = value {
            if self.values.len() >= MAX_BINDINGS && !self.values.contains_key(name) {
                self.values.clear();
            }
            self.values.insert(name.to_owned(), value);
        } else {
            self.values.remove(name);
        }
    }
}

pub(super) fn maintained_variable(name: &str) -> bool {
    name.starts_with("BASH_")
        || matches!(
            name,
            "RANDOM"
                | "SRANDOM"
                | "SECONDS"
                | "LINENO"
                | "EPOCHSECONDS"
                | "EPOCHREALTIME"
                | "PIPESTATUS"
                | "FUNCNAME"
                | "DIRSTACK"
                | "GROUPS"
                | "PWD"
                | "OLDPWD"
                | "_"
        )
}

pub(super) fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || index > 0 && byte.is_ascii_digit()
        })
}

pub(super) fn assignment(raw: &str) -> Option<(&str, bool, &str)> {
    let (left, rhs) = raw.split_once('=')?;
    let name = left.strip_suffix('+').unwrap_or(left);
    identifier(name).then_some((name, left != name, rhs))
}

/// Shell line continuation happens before variable names are recognized:
/// `$TA\` + newline + `RGET` reads TARGET, not TA followed by literal RGET.
/// Only normalize source words, never values obtained from the environment
/// model. Keep single-quoted data and escaped backslashes intact, and retain
/// quotes/other escapes for the ordinary decoder. Unsupported substitutions
/// remain unsupported; this is not a command or expanded-data reparsing step.
fn source_word_without_continuations(raw: &str) -> Cow<'_, str> {
    if !raw.contains("\\\n") {
        return Cow::Borrowed(raw);
    }
    let mut result = String::with_capacity(raw.len());
    let mut quote = None;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                result.push(ch);
            }
            (Some('\''), _) => result.push(ch),
            (None, '\'' | '"') => {
                quote = Some(ch);
                result.push(ch);
            }
            (_, '\\') => {
                let next = chars.next();
                if next == Some('\n') {
                    continue;
                }
                result.push(ch);
                if let Some(next) = next {
                    result.push(next);
                }
            }
            _ => result.push(ch),
        }
    }
    if result.len() == raw.len() {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(result)
    }
}

/// A complete scalar expansion only; mixed words, arrays, parameter operators
/// and substitutions need an expansion/provenance model, not text replacement.
fn scalar(raw: &str) -> Option<(&str, bool)> {
    let (raw, quoted) = match raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(inner) => (inner, true),
        None => (raw, false),
    };
    let name = raw
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .or_else(|| raw.strip_prefix('$'))?;
    identifier(name).then_some((name, quoted))
}

/// Quote removal for static scalar assignments. Runtime expansions, tilde
/// expansion, locale/ANSI-C quotes and array initializers forfeit the proof.
/// This deliberately does not ask the host environment what a value means.
fn literal(raw: &str) -> Option<String> {
    let mut result = String::new();
    let mut quote = None;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => result.push(ch),
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') => {
                let next = chars.next()?;
                if next == '\n' {
                    continue;
                }
                if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\') {
                    result.push('\\');
                }
                result.push(next);
            }
            (_, '$' | '`') | (None, '~' | '(' | ')') => return None,
            _ => result.push(ch),
        }
    }
    quote.is_none().then_some(result)
}

/// Double quotes suppress scalar field splitting, but not list-valued `@`
/// expansions and their parameter operators. Indirection can name `@` or an
/// array list, so it is not a scalar proof either. The AST supplies exactly
/// one live expansion here, not quoted argument data or a substring match.
fn parameter_can_produce_multiple_fields(raw: &str) -> bool {
    let Some(parameter) = raw.strip_prefix("${").and_then(|s| s.strip_suffix('}')) else {
        return raw == "$@";
    };
    if parameter.starts_with('#') {
        return false;
    }
    if parameter.starts_with('@') {
        return true;
    }
    let indirect = parameter.starts_with('!');
    let parameter = parameter.strip_prefix('!').unwrap_or(parameter);
    let name_end = parameter
        .bytes()
        .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .count();
    if name_end == 0 {
        return false;
    }
    let operator = &parameter[name_end..];
    operator.starts_with("[@]") || indirect && !matches!(operator, "[*]" | "*")
}

/// Bash expands the word of a double-quoted `"${S:+word}"` (likewise
/// `"${S:-word}"`) in that quoted context: `$@` there still yields one field
/// per positional parameter, and single quotes are literal characters, not
/// quoting. After `set -- /tmp/a /etc/passwd`, `tee "${S:+$@}"` hands tee
/// `/etc/passwd` as its own argument; after `set -- /tmp/a /etc/passwd x`,
/// so does `tee "${S:+'$@'}"` (fields `'/tmp/a`, `/etc/passwd`, `x'`). The
/// parser's expansion-word token swallows such a `$@` as plain text, and it
/// reads `'…'` there as a raw string, so the AST children cannot show either
/// one. Read the expansion's own text instead: only a backslash makes a `$`
/// literal here. Any list-capable read counts, even under an operator whose
/// result is one field (`${S#$@}`, `${S=$@}`) and inside a nested
/// substitution: this only selects the bounded analysis, which fails closed.
fn expansion_text_may_read_a_list(raw: &str) -> bool {
    let Some(inner) = raw.strip_prefix("${") else {
        return false;
    };
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                chars.next();
            }
            '$' => match chars.peek() {
                Some('@') => return true,
                Some('{') => {
                    chars.next();
                    if chars.next_if(|next| matches!(next, '@' | '!')).is_some() {
                        return true;
                    }
                    while chars
                        .next_if(|next| next.is_ascii_alphanumeric() || *next == '_')
                        .is_some()
                    {}
                    if chars.next_if_eq(&'[').is_some()
                        && chars.next_if_eq(&'@').is_some()
                        && chars.next_if_eq(&']').is_some()
                    {
                        return true;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    false
}

/// Preserve the parser's quoting and execution boundaries. A `$@` inside
/// `"$(printf '%s' "$@")"` belongs to the nested command, not the outer argv;
/// its quoted output is one scalar. Nested commands are scanned separately.
/// Assignment and redirect words likewise do not supply this command's argv.
fn argv_needs_field_analysis(node: Node<'_, StrDoc<SupportLang>>) -> bool {
    let mut pending = vec![(node, false)];
    while let Some((part, quoted)) = pending.pop() {
        match part.kind().as_ref() {
            "variable_assignment"
            | "file_redirect"
            | "heredoc_redirect"
            | "herestring_redirect"
            | "process_substitution"
            | "raw_string"
            | "ansi_c_string"
            | "comment" => {}
            "string" => pending.extend(part.children().map(|child| (child, true))),
            "command_substitution" | "arithmetic_expansion" => {
                if !quoted {
                    return true;
                }
            }
            "simple_expansion" | "expansion" => {
                let raw = part.text();
                if !quoted
                    || parameter_can_produce_multiple_fields(raw.as_ref())
                    || expansion_text_may_read_a_list(raw.as_ref())
                {
                    return true;
                }
                // An operator's replacement can itself contain a live list,
                // e.g. "${S:+"$@"}". Do not stop at the scalar parameter name.
                pending.extend(part.children().map(|child| (child, quoted)));
            }
            _ => pending.extend(part.children().map(|child| (child, quoted))),
        }
    }
    false
}

/// POSIX distinguishes IFS whitespace from other separators. Empty fields
/// before/interior to non-whitespace separators survive; a final separator
/// terminates the preceding field rather than inventing a final argument.
pub(super) fn fields<'a>(value: &'a str, ifs: &str) -> Result<Vec<&'a str>, ()> {
    if value.len() > MAX_VALUE_BYTES
        || ifs.len() > MAX_VALUE_BYTES
        || !ifs.is_ascii()
        || value.contains('\0')
        || ifs.contains('\0')
    {
        return Err(());
    }
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let separator = |byte: u8| ifs.as_bytes().contains(&byte);
    let whitespace = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n') && separator(byte);
    let bytes = value.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && whitespace(bytes[start]) {
        start += 1;
    }
    while end > start && whitespace(bytes[end - 1]) {
        end -= 1;
    }
    let mut result = Vec::new();
    while start < end {
        let mut cursor = start;
        while cursor < end && !separator(bytes[cursor]) {
            cursor += 1;
        }
        let field = &value[start..cursor];
        // Pathname expansion happens after splitting, so a glob character
        // consumed as an IFS separator is not a glob in any resulting field.
        if field.contains(['*', '?', '[', '(']) || result.len() >= MAX_FIELDS {
            return Err(());
        }
        result.push(field);
        if cursor == end {
            break;
        }
        if whitespace(bytes[cursor]) {
            while cursor < end && whitespace(bytes[cursor]) {
                cursor += 1;
            }
            if cursor < end && separator(bytes[cursor]) {
                cursor += 1;
            }
        } else {
            cursor += 1;
        }
        while cursor < end && whitespace(bytes[cursor]) {
            cursor += 1;
        }
        start = cursor;
    }
    Ok(result)
}

fn expand(raw: &str, state: &State) -> Result<Vec<String>, ()> {
    let continued = source_word_without_continuations(raw);
    let raw = continued.as_ref();
    if let Some((name, quoted)) = scalar(raw) {
        let value = state.value(name).ok_or(())?;
        if quoted {
            return Ok(vec![value.to_owned()]);
        }
        return fields(value, state.ifs.as_deref().ok_or(())?)
            .map(|fields| fields.into_iter().map(str::to_owned).collect());
    }
    if let Some(value) = literal(raw) {
        // A bare glob is not a literal argument, even without expansion.
        if live_pattern(raw) {
            return Err(());
        }
        return Ok(vec![value]);
    }
    // #566: $ROOT/file and "${ROOT}"/file are scalar words, not mutations.
    // Only reconstruct a concatenation when every expansion stays in one
    // field. Literal prefix/suffix bytes are never subject to IFS splitting.
    // The general standalone-scalar splitter above remains unchanged.
    let (value, present) = scalar_word(raw, |name, quoted| {
        let value = state.value(name)?;
        if !quoted {
            let ifs = state.ifs.as_deref()?;
            if !ifs.is_ascii()
                || ifs.contains('\0')
                || value.chars().any(|ch| ifs.contains(ch))
                || value.contains(['*', '?', '[', '('])
            {
                return None;
            }
        }
        Some(value.to_owned())
    })
    .ok_or(())?;
    Ok(if present { vec![value] } else { Vec::new() })
}

/// Decode only literal pieces and simple scalar parameter reads. The resolver
/// owns value/splitting checks; a syntax-only caller may provide empty values
/// to prove that a word cannot assign IFS or other bindings while expanding.
/// This is not an argv safety grant. Unknown values still fail in `expand`.
/// Parameter operators, arrays, indirection, arithmetic, substitutions and
/// unquoted patterns are deliberately unsupported. No host lookup or eval.
fn scalar_word(
    raw: &str,
    mut resolve: impl FnMut(&str, bool) -> Option<String>,
) -> Option<(String, bool)> {
    if raw.len() > MAX_VALUE_BYTES || raw.contains('\0') {
        return None;
    }
    let continued = source_word_without_continuations(raw);
    let raw = continued.as_ref();
    let mut result = String::new();
    let mut present = false;
    let mut quote = None;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {
                result.push(ch);
                present = true;
            }
            (None, '\'' | '"') => {
                quote = Some(ch);
                present = true; // explicit null arguments survive
            }
            (_, '\\') => {
                let next = chars.next()?;
                if next == '\n' {
                    continue;
                }
                if quote == Some('"') && !matches!(next, '$' | '`' | '"' | '\\') {
                    result.push('\\');
                }
                result.push(next);
                present = true;
            }
            (_, '$') => {
                let braced = chars.next_if_eq(&'{').is_some();
                let mut name = String::new();
                while chars
                    .peek()
                    .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                {
                    name.push(chars.next()?);
                }
                if !identifier(&name) || braced && chars.next() != Some('}') {
                    return None;
                }
                let value = resolve(&name, quote == Some('"'))?;
                if result.len().saturating_add(value.len()) > MAX_VALUE_BYTES
                    || value.contains('\0')
                {
                    return None;
                }
                present |= !value.is_empty();
                result.push_str(&value);
            }
            (_, '`')
            | (None, '~' | '{' | '}' | '*' | '?' | '[' | '(' | ')' | ';' | '&' | '|' | '<' | '>') =>
            {
                return None;
            }
            (None, ch) if ch.is_whitespace() => return None,
            _ => {
                result.push(ch);
                present = true;
            }
        }
        if result.len() > MAX_VALUE_BYTES {
            return None;
        }
    }
    quote.is_none().then_some((result, present))
}

/// Mixed quoting does not neutralize a pattern in the unquoted portion:
/// `"/tmp/"*` is still a glob. Check provenance, not equality after decoding.
fn live_pattern(raw: &str) -> bool {
    let mut quote = None;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') => {
                chars.next();
            }
            (None, '*' | '?' | '[' | '{' | '(') => return true,
            _ => {}
        }
    }
    false
}

fn uncertain(span: Range<usize>) -> Vec<CredentialFileWrite> {
    // Unknown destinations may name either protected family. A grant for
    // credentials must not silently grant an unverified .git destination.
    [
        shell::CREDENTIAL_FILE_WRITE_NAME,
        shell::GIT_INTERNALS_WRITE_NAME,
    ]
    .into_iter()
    .map(|rule| CredentialFileWrite {
        span: span.clone(),
        reason: UNCERTAIN.to_owned(),
        rule,
    })
    .collect()
}

fn render(argv: &[String]) -> String {
    argv.iter()
        .map(|word| quote_field(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote an expanded field for the native policy so that it reads as the
/// literal it is. The shell expands braces before parameters, so a brace a
/// field holds (`/etc/shadow}` from `S=/tmp/a{,@/etc/shadow}` split on `@`)
/// expands to nothing; `shell_words` leaves braces unquoted, and the policy
/// read one as a brace that may still name a protected path.
fn quote_field(word: &str) -> Cow<'_, str> {
    if word.contains(['{', '}']) {
        Cow::Owned(format!("'{}'", word.replace('\'', "'\\''")))
    } else {
        shell_words::quote(word)
    }
}

/// Match the executable spelling understood by the shared native path policy.
/// That classifier removes a terminal .exe/.EXE and folds ASCII case even for
/// POSIX source (including Git Bash). Its IFS selector must not silently drop
/// those writers, and tee variants must still check EVERY split destination.
/// Decode shell syntax before calling this; do not reinterpret backslashes as
/// Windows separators or change the actual argv passed to the native policy.
fn policy_executable_basename(name: &str) -> Cow<'_, str> {
    let basename = name.rsplit('/').next().unwrap_or(name);
    let basename = basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".EXE"))
        .unwrap_or(basename);
    if basename.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(basename.to_ascii_lowercase())
    } else {
        Cow::Borrowed(basename)
    }
}

/// An execution frontend left in argv0 is not evidence of a non-writer.
/// Normalization can stop on a dynamic option even in a single wrapper, or
/// an expansion can supply the wrapper name after normalization has run.
fn execution_frontend(name: &str) -> bool {
    matches!(name, "sudo" | "env" | "command" | "builtin")
        || crate::normalize::is_posix_execution_frontend_basename(name)
}

/// Find the first argv field, not just the first source word. Unquoted
/// empty expansions vanish: after stripping `command` from `command $E -p
/// tee $S`, an empty E exposes `-p`, which still belongs to the wrapper.
/// Unknown expansions stop the proof; quoted empties are real argv fields
/// and must not be skipped. The complete argv pass retains its own bounds.
fn first_expanded_word(arguments: &[&str], state: &State) -> Result<Option<String>, ()> {
    for (index, raw) in arguments.iter().enumerate() {
        if index >= MAX_FIELDS {
            return Err(());
        }
        let fields = expand(raw, state)?;
        if let Some(word) = fields.into_iter().next() {
            return Ok(Some(word));
        }
    }
    Ok(None)
}

/// A dynamically supplied word at the normalizer's command boundary can
/// still be an option of the removed execution wrapper. This applies to
/// nice/stdbuf/exec and the other frontends, not only command and env.
/// Assignment and backslash normalization are shell syntax, not option
/// parsers. Environment assignments retain the existing command/env handling.
/// This is a conservative ownership check, not another utility option parser.
fn wrapper_may_own_generated_control(wrapper_type: &str, word: &str) -> bool {
    match wrapper_type {
        "assignment" | "backslash" => false,
        "command" | "env" => word.starts_with('-') || word.contains('='),
        _ => word.starts_with('-'),
    }
}

/// A literal command -v/-V is a query, not an execution frontend. Only read
/// options before its first operand/--, and stop at dynamic words: they can
/// supply an operand or terminate option parsing before a later literal -v.
/// This exempts this argv pass only, never the original command's checks.
fn command_queries_only(arguments: &[&str]) -> bool {
    if arguments.first().and_then(|word| literal(word)).as_deref() != Some("command") {
        return false;
    }
    for raw in arguments.iter().skip(1) {
        let Some(word) = literal(raw) else {
            return false;
        };
        let Some(flags) = word.strip_prefix('-') else {
            return false;
        };
        if flags.is_empty() || !flags.chars().all(|ch| matches!(ch, 'p' | 'v' | 'V')) {
            return false;
        }
        if flags.contains(['v', 'V']) {
            return true;
        }
    }
    false
}

/// Removing a wrapper prefix assumes each source word occupies one argv slot.
/// An unquoted option value can split into extra words (or disappear), making
/// one of those words the real executable. Check the discarded words against
/// the caller's state before trusting the normalizer's command boundary.
fn wrapper_prefix_preserves_fields(prefix: &str, state: &State) -> bool {
    let tokens = crate::normalize::tokenize_for_shell_dialect(prefix, ShellDialect::Posix);
    tokens.len() <= MAX_FIELDS
        && tokens.iter().all(|token| {
            if token.kind != NormalizeTokenKind::Word {
                return false;
            }
            let Some(raw) = token.text(prefix) else {
                return false;
            };
            // Quoted scalar pieces stay in one argument even if their
            // values are unknown. Lists, operators and substitutions do not
            // qualify, and an implicit empty word must not count as present.
            scalar_word(raw, |_, quoted| quoted.then(String::new))
                .is_some_and(|(_, present)| present)
                || expand(raw, state).is_ok_and(|fields| fields.len() == 1)
        })
}

fn classify(argv: &[String], span: Range<usize>) -> Result<Vec<CredentialFileWrite>, ()> {
    let Some(name) = argv.first() else {
        return Ok(Vec::new());
    };
    let basename = policy_executable_basename(name);
    // Empty unquoted leading words may disappear and expose a frontend that
    // was not in the pre-expansion argv0 slot. Do not hand an unresolved
    // frontend to the destination classifier as if it were the final writer.
    if execution_frontend(basename.as_ref()) {
        return Err(());
    }
    let mut hits = Vec::new();
    if matches!(basename.as_ref(), "tee" | "gtee") {
        let mut append = false;
        let mut options = true;
        let mut destinations = Vec::new();
        for word in &argv[1..] {
            if options && word == "--" {
                options = false;
                continue;
            }
            if options && matches!(word.as_str(), "--help" | "--version") {
                return Ok(hits);
            }
            if options && word.starts_with('-') && word != "-" {
                if word == "--append" {
                    append = true;
                } else if word == "--ignore-interrupts"
                    || word == "--output-error"
                    || word.starts_with("--output-error=")
                {
                    // These flags do not change destinations or append mode.
                } else if word[1..].chars().all(|ch| matches!(ch, 'a' | 'i' | 'p')) {
                    append |= word.contains('a');
                } else {
                    return Err(());
                }
            } else {
                // POSIXLY_CORRECT can stop getopt at the first operand. A
                // later --help is then a filename, not proof of no writes;
                // a later -a cannot prove earlier targets are append-only.
                // Retain this valid, more destructive reading even when a
                // GNU option-permuting invocation would do less damage.
                options = false;
                destinations.push(word);
            }
        }
        // Ask the same native path policy once for EACH tee destination. This
        // also keeps credential and Git rules independent under allowlisting.
        for path in destinations {
            let invocation = format!(
                "tee {}-- {}",
                if append { "-a " } else { "" },
                quote_field(path)
            );
            if let Some(mut hit) =
                shell::classify_credential_file_write(&invocation, ShellDialect::Posix)
            {
                hit.span = span.clone();
                hits.push(hit);
            }
        }
    } else {
        // The shared native classifier intentionally returns the first write in
        // a simple command. IFS reconstruction can create several concrete file
        // operands, though: sed/perl in-place mode may rewrite every one of
        // them. Re-run the exact same native policy after replacing only the
        // already-reported operand with inert data. This keeps option parsing,
        // writer semantics and protected-path resolution centralized while
        // retaining later rule families for independent allowlisting.
        let mut rendered = render(argv);
        for _ in 0..MAX_FIELDS {
            let Some(mut hit) =
                shell::classify_credential_file_write(&rendered, ShellDialect::Posix)
            else {
                return Ok(hits);
            };
            let local = hit.span.clone();
            if local.start >= local.end
                || local.end > rendered.len()
                || !rendered.is_char_boundary(local.start)
                || !rendered.is_char_boundary(local.end)
            {
                return Err(());
            }
            // Preserve byte offsets and surrounding quote/option syntax. A
            // same-length ASCII operand cannot itself name a protected path,
            // and a malformed/non-target span fails closed above.
            rendered.replace_range(local.clone(), &"x".repeat(local.len()));
            hit.span = span.clone();
            hits.push(hit);
        }
        // More findings than the argv bound means the proof did not finish.
        return Err(());
    }
    Ok(hits)
}

/// Bash's `%n` conversion assigns the byte count to a named shell variable.
/// Do not confuse it with `%%n`, an ordinary conversion followed by `n`, or
/// strftime's `%n` (a newline) inside `%(...)T`. Width, precision and length
/// modifiers do not make a count assignment harmless. Backslash escapes do
/// not protect a source `%`: `\%n` still performs the assignment, whereas
/// `\045n` only prints percent/n and must not be re-parsed as a conversion.
pub(super) fn printf_format_may_assign(format: &str) -> bool {
    let bytes = format.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        index += 1;
        if bytes.get(index) == Some(&b'%') {
            index += 1;
            continue;
        }
        // This is a conservative conversion prefix, not a printf validator.
        // Invalid combinations can only add a refusal; they cannot conceal
        // an `n` accepted by Bash's width/precision/modifier parser.
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_digit() || b"#-+ '.*hlLjzt".contains(byte))
        {
            index += 1;
        }
        match bytes.get(index) {
            Some(b'n') => return true,
            Some(b'(') => {
                let mut depth = 1usize;
                index += 1;
                while depth > 0 {
                    match bytes.get(index) {
                        Some(b'(') => depth += 1,
                        Some(b')') => depth -= 1,
                        Some(_) => {}
                        None => return true,
                    }
                    index += 1;
                }
                // Only a complete time conversion owns the nested percent
                // sequences. Anything else is outside our bounded proof.
                if bytes.get(index) != Some(&b'T') {
                    return true;
                }
            }
            Some(conversion) if b"%bqQcCsSdiouxXaAeEfFgG".contains(conversion) => {}
            Some(_) => return true,
            None => break,
        }
        index += 1;
    }
    false
}

/// Both `-v` and a live `%n` in the format can mutate shell bindings. Find
/// the format after expanding leading arguments and the optional `--`;
/// unquoted empty words vanish, quoted empties do not. Arguments AFTER the
/// format are data, even when they contain `-v` or `%n`. Unknown leading
/// arguments can select either assignment form and forfeit the old values.
fn printf_may_assign(words: &[String], state: &State) -> bool {
    let mut options = true;
    for raw in words.iter().skip(1) {
        let Ok(fields) = expand(raw, state) else {
            return true;
        };
        for field in fields {
            if options && field == "--" {
                options = false;
                continue;
            }
            return options && field.starts_with("-v") || printf_format_may_assign(&field);
        }
    }
    false
}

pub(super) fn mutates_shell(name: &str) -> bool {
    matches!(
        name,
        "read"
            | "mapfile"
            | "readarray"
            | "eval"
            | "."
            | "source"
            | "let"
            | "declare"
            | "typeset"
            | "local"
            | "readonly"
            // Bare export uses the declaration-command path. A quoted or
            // escaped spelling can instead be parsed as an ordinary command;
            // its decoded name still mutates variables (ex''port S=value).
            | "export"
            | "unset"
            | "getopts"
            | "trap"
            | "alias"
            | "unalias"
            | "set"
            | "shopt"
            | "enable"
            | "builtin"
            | "command"
    )
}

pub(super) fn special_builtin(name: &str) -> bool {
    matches!(
        name,
        ":" | "."
            | "break"
            | "continue"
            | "eval"
            | "exec"
            | "exit"
            | "export"
            | "readonly"
            | "return"
            | "set"
            | "shift"
            | "times"
            | "trap"
            | "unset"
    )
}

/// The async terminator belongs to the whole statement, not to each
/// assignment inside it. Ask the syntax tree so line continuations before
/// `&`, and the distinct `&&` and `&>` operators, keep their shell meaning.
pub(super) fn has_async_terminator(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.get_inner_node()
        .next_sibling()
        .is_some_and(|sibling| sibling.kind() == "&")
}

/// Declaration arguments can undergo brace expansion even though an ordinary
/// scalar assignment does not: `export S={one,two}` assigns S twice in Bash.
/// A comma list or range-shaped brace pair therefore cannot establish one
/// literal value. Keep quoted/escaped braces and commas as data. This bounded
/// lexical check never enumerates alternatives (which can grow exponentially)
/// and deliberately treats malformed range candidates as uncertain too.
pub(super) fn declaration_may_expand_braces(raw: &str) -> bool {
    let mut quote = None;
    let mut braces = Vec::new();
    let mut previous_dot = false;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {}
            (None, '\'' | '"') => quote = Some(ch),
            (_, '\\') => {
                // Line continuation disappears before brace expansion, so
                // two dots separated by it still introduce a range.
                if chars.next() == Some('\n') {
                    continue;
                }
            }
            (None, '{') => braces.push(false),
            (None, ',') => {
                if let Some(expands) = braces.last_mut() {
                    *expands = true;
                }
            }
            (None, '.') => {
                if let Some(expands) = braces.last_mut() {
                    *expands |= previous_dot;
                }
                previous_dot = true;
                continue;
            }
            // Every `}` closes its group; the guard pops it either way.
            (None, '}') if braces.pop() == Some(true) => return true,
            _ => {}
        }
        previous_dot = false;
    }
    false
}

/// Scan the original source, before segmentation discards earlier bindings.
/// Unsupported control flow removes facts instead of preserving stale paths.
pub(super) fn scan(command: &str, dialect: ShellDialect) -> Vec<CredentialFileWrite> {
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) || !candidate(command) {
        return Vec::new();
    }
    if command.len() > MAX_BYTES {
        return uncertain(0..command.len());
    }
    // The shell removes a line continuation before it reads words, so
    // `I\` + newline + `FS=@` assigns IFS and `$TA\` + newline + `RGET` reads
    // TARGET. The grammar reads one as a word break instead (a command `I`
    // with the argument `FS=@`), which hid both from the binding model. Scan
    // the source as the shell reads it; every span is reported in `command`.
    let Some((joined, offsets)) = join_line_continuations(command) else {
        return scan_source(command);
    };
    let mut hits = scan_source(&joined);
    for hit in &mut hits {
        hit.span = offsets[hit.span.start]..offsets[hit.span.end];
    }
    hits
}

/// `command` with each line continuation (a backslash-newline outside single
/// quotes, `$'…'`, comments and heredoc bodies) removed, as the shell removes
/// it before reading words, and for each byte of that source the offset of the
/// same byte in `command`, with one more entry for the end. `None` when
/// nothing was removed.
pub(super) fn join_line_continuations(command: &str) -> Option<(String, Vec<usize>)> {
    if !command.contains("\\\n") {
        return None;
    }
    let bytes = command.as_bytes();
    let len = bytes.len();
    let bodies = crate::context::heredoc_body_ranges(command, crate::context::HeredocRules::Bash);
    let mut bodies = bodies.iter().map(|body| body.range.clone()).peekable();
    let mut joined = Vec::with_capacity(len);
    let mut offsets = Vec::with_capacity(len + 1);
    let keep = |joined: &mut Vec<u8>, offsets: &mut Vec<usize>, range: Range<usize>| {
        joined.extend_from_slice(&bytes[range.clone()]);
        offsets.extend(range);
    };
    let mut removed = false;
    let mut double_quoted = false;
    // Open parentheses, `true` for a substitution's (`$(`, `<(`, `>(`). A
    // word starts after the `)` of a subshell or an arithmetic command, not
    // after a substitution's, which ends no word: `(x)#…` is a comment and
    // `$(x)#…` a word.
    let mut parens: Vec<bool> = Vec::new();
    let mut after_group = false;
    let mut i = 0usize;
    while i < len {
        if bodies.peek().is_some_and(|body| body.start == i) {
            let body = bodies.next().unwrap_or(i..i);
            keep(&mut joined, &mut offsets, body.clone());
            i = body.end;
            continue;
        }
        let word_start = after_group
            || joined.last().is_none_or(|byte| {
                matches!(
                    byte,
                    b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b'<' | b'>'
                )
            });
        let mut closes_group = false;
        let end = match bytes[i] {
            b'\\' if bytes.get(i + 1) == Some(&b'\n') => {
                removed = true;
                i += 2;
                continue;
            }
            b'\\' => (i + 2).min(len),
            b'"' => {
                double_quoted = !double_quoted;
                i + 1
            }
            b'\'' if !double_quoted => {
                memchr::memchr(b'\'', &bytes[i + 1..]).map_or(len, |at| i + at + 2)
            }
            b'$' if !double_quoted && bytes.get(i + 1) == Some(&b'\'') => {
                let mut at = i + 2;
                while at < len && bytes[at] != b'\'' {
                    at += if bytes[at] == b'\\' { 2 } else { 1 };
                }
                (at + 1).min(len)
            }
            b'#' if !double_quoted && word_start => {
                memchr::memchr(b'\n', &bytes[i..]).map_or(len, |at| i + at)
            }
            b'(' if !double_quoted => {
                parens.push(
                    joined
                        .last()
                        .is_some_and(|byte| matches!(byte, b'$' | b'<' | b'>')),
                );
                i + 1
            }
            b')' if !double_quoted => {
                closes_group = parens.pop() == Some(false);
                i + 1
            }
            _ => i + 1,
        };
        // A heredoc body starts after a newline, never inside these spans.
        let end = bodies
            .peek()
            .map_or(end, |body| end.min(body.start.max(i + 1)));
        keep(&mut joined, &mut offsets, i..end);
        after_group = closes_group;
        i = end;
    }
    offsets.push(len);
    if !removed {
        return None;
    }
    // Only whole ASCII pairs were removed, between whole characters.
    String::from_utf8(joined)
        .ok()
        .map(|joined| (joined, offsets))
}

/// [`scan`] of a source with no line continuation left.
fn scan_source(command: &str) -> Vec<CredentialFileWrite> {
    let Ok(ast) = AstGrep::try_new(
        crate::context::shell_parse_source(command).as_ref(),
        SupportLang::Bash,
    ) else {
        return uncertain(0..command.len());
    };
    if ast.root().get_inner_node().has_error() {
        return uncertain(0..command.len());
    }
    let mut pending = vec![ast.root()];
    let mut events = Vec::new();
    let mut visited = 0;
    while let Some(node) = pending.pop() {
        visited += 1;
        if visited > MAX_EVENTS * 64 {
            return uncertain(0..command.len());
        }
        let kind = node.kind();
        let owned = kind == "variable_assignment"
            && node.parent().is_some_and(|parent| {
                matches!(parent.kind().as_ref(), "command" | "declaration_command")
            });
        let effect = matches!(
            kind.as_ref(),
            "command"
                | "variable_assignment"
                | "declaration_command"
                | "unset_command"
                | "arithmetic_expansion"
                | "test_command"
                | "for_statement"
                | "c_style_for_statement"
                | "if_statement"
                | "case_statement"
                | "while_statement"
                | "function_definition"
                | "compound_statement"
                | "subshell"
        );
        if !owned && effect || kind == "expansion" && scalar(node.text().as_ref()).is_none() {
            events.push(node.clone());
            if events.len() > MAX_EVENTS {
                return uncertain(0..command.len());
            }
        }
        pending.extend(node.children());
    }
    events.sort_by_key(|node| node.range().start);
    // Do not import the guard process's IFS, or assume a persistent caller
    // has its default value. An explicit assignment can establish the value;
    // appending to an unknown IFS must remain unknown (it may contain other
    // delimiters). This also preserves caller-side expansion of prefixes.
    let mut state = State::default();
    let mut hits = Vec::new();
    for node in events {
        let raw = node.text();
        let span = node.range();
        let mut ancestor = node.parent();
        let mut certain = !has_async_terminator(&node);
        let mut straight_line = true;
        while let Some(parent) = ancestor {
            // `S=safe T=x &` cannot change S in the parent shell. The first
            // assignment's own suffix is `T=x`, so checking that suffix
            // would incorrectly replace an older dangerous S with `safe`.
            // Inherit the async boundary from every enclosing statement.
            certain &= !has_async_terminator(&parent);
            match parent.kind().as_ref() {
                "program" | "variable_assignments" => {}
                // A redirection is part of command setup. If opening it fails,
                // an assignment-only command or a special/declaration builtin
                // may never establish the binding that follows. Treat the
                // state effect as uncertain while still analyzing the command
                // itself for protected writer destinations.
                "redirected_statement" | "pipeline" => certain = false,
                _ => {
                    certain = false;
                    straight_line = false;
                }
            }
            ancestor = parent.parent();
        }
        match node.kind().as_ref() {
            "variable_assignment" => state.assign(raw.as_ref(), certain),
            "declaration_command" => {
                let tokens =
                    crate::normalize::tokenize_for_shell_dialect(raw.as_ref(), ShellDialect::Posix);
                let words: Vec<_> = tokens
                    .iter()
                    .filter(|token| token.kind == NormalizeTokenKind::Word)
                    .filter_map(|token| token.text(raw.as_ref()))
                    .collect();
                // Export RHSs use the caller's environment, not values of
                // earlier arguments of the same declaration builtin.
                if words.first() == Some(&"export")
                    && words.iter().skip(1).all(|word| {
                        identifier(word)
                            || assignment(word).is_some_and(|(_, _, rhs)| literal(rhs).is_some())
                    })
                {
                    for word in words
                        .into_iter()
                        .skip(1)
                        .filter(|word| assignment(word).is_some())
                    {
                        // Every generated argument still starts with the same
                        // literal NAME= (or NAME+=). Only that binding becomes
                        // unknown; unrelated values and later explicit scalar
                        // rebindings retain their proofs. Ordinary assignment
                        // statements must not use this declaration-only rule.
                        state.assign(word, certain && !declaration_may_expand_braces(word));
                    }
                } else {
                    state.forget();
                    state.attributes_unknown = true;
                }
            }
            "command" => {
                if !straight_line {
                    state.forget();
                }
                let prefixes: Vec<_> = node
                    .children()
                    .filter(|child| child.kind() == "variable_assignment")
                    .map(|child| child.text().into_owned())
                    .collect();
                let prefix_ifs = prefixes
                    .iter()
                    .any(|prefix| assignment(prefix).is_some_and(|(name, _, _)| name == "IFS"));
                let words: Vec<_> = node
                    .children()
                    .filter(|child| {
                        child.is_named()
                            && !matches!(
                                child.kind().as_ref(),
                                "variable_assignment"
                                    | "file_redirect"
                                    | "heredoc_redirect"
                                    | "herestring_redirect"
                                    | "comment"
                            )
                    })
                    .map(|child| child.text().into_owned())
                    .collect();
                let original_name = words.first().and_then(|word| literal(word));
                if prefixes.iter().any(|prefix| {
                    assignment(prefix)
                        .is_none_or(|(_, _, rhs)| literal(rhs).is_none() && scalar(rhs).is_none())
                }) || words.iter().any(|word| {
                    // A passive scalar read must not manufacture an IFS
                    // mutation before a later `while IFS= read` (#566).
                    // Real effects and unsupported expansions still erase
                    // facts; unknown scalar values still fail reconstruction.
                    literal(word).is_none()
                        && scalar(word).is_none()
                        && word.contains(['$', '`'])
                        && scalar_word(word, |_, _| Some(String::new())).is_none()
                }) {
                    state.forget();
                }
                let joined = words.join(" ");
                let stripped = strip_wrapper_prefixes(&joined);
                let tokens = crate::normalize::tokenize_for_shell_dialect(
                    stripped.normalized.as_ref(),
                    ShellDialect::Posix,
                );
                let arguments: Vec<_> = tokens
                    .iter()
                    .filter(|token| token.kind == NormalizeTokenKind::Word)
                    .filter_map(|token| token.text(stripped.normalized.as_ref()))
                    .collect();
                let expanded_name = first_expanded_word(&arguments, &state);
                let unknown_command_name = expanded_name.is_err();
                let name = expanded_name.ok().flatten();
                let basename = name.as_deref().map(policy_executable_basename);
                let writer = basename.as_deref().is_none_or(shell::is_credential_writer);
                let unresolved_frontend = basename.as_deref().is_some_and(execution_frontend)
                    && !command_queries_only(&arguments);
                // Expansion can expose wrapper controls at a boundary that
                // normalization chose from raw source. This includes nice
                // $E -n 0 tee ... when E vanishes, and stdbuf $OPT tee ...
                // when OPT=-oL. Such fields do not prove a harmless argv0.
                let generated_wrapper_control = arguments
                    .first()
                    .is_some_and(|word| literal(word).is_none())
                    && name.as_deref().is_some_and(|word| {
                        stripped.stripped_wrappers.iter().any(|wrapper| {
                            wrapper_may_own_generated_control(wrapper.wrapper_type, word)
                        })
                    });
                let active = state.changed
                    || prefix_ifs
                    || words
                        .iter()
                        .any(|word| assignment(word).is_some_and(|(name, _, _)| name == "IFS"));
                let expands = argv_needs_field_analysis(node.clone());
                let unstable_prefix = active
                    && expands
                    && stripped.stripped_wrappers.iter().any(|wrapper| {
                        // Alias-bypass backslashes are syntax, not argv slots.
                        wrapper.wrapper_type != "backslash"
                            && !wrapper_prefix_preserves_fields(&wrapper.stripped_text, &state)
                    });
                if active
                    && expands
                    && (stripped.wrapper_limit_reached
                        || unknown_command_name
                        || unresolved_frontend
                        || generated_wrapper_control
                        || unstable_prefix)
                {
                    // The remaining argv0 may be another execution wrapper,
                    // not the eventual utility. An incomplete normalization
                    // cannot prove that this is a non-writer, nor can passing
                    // its incomplete argv to the path classifier prove safety.
                    // Preserve both native rule families and keep processing
                    // this command's state effects below.
                    hits.extend(uncertain(span.clone()));
                } else if active && writer && expands {
                    // Temporary prefixes do not supply this invocation's argv.
                    let mut argv = Vec::new();
                    let mut complete = true;
                    let mut bytes = 0usize;
                    for argument in arguments {
                        let Ok(fields) = expand(argument, &state) else {
                            complete = false;
                            break;
                        };
                        for field in fields {
                            bytes = bytes.saturating_add(field.len());
                            argv.push(field);
                        }
                        if bytes > MAX_BYTES || argv.len() > MAX_FIELDS {
                            complete = false;
                            break;
                        }
                    }
                    if complete {
                        match classify(&argv, span.clone()) {
                            Ok(found) => hits.extend(found),
                            Err(()) => hits.extend(uncertain(span.clone())),
                        }
                    } else {
                        hits.extend(uncertain(span.clone()));
                    }
                }
                if original_name.as_deref().is_some_and(special_builtin) {
                    // POSIX mode can retain these values; ordinary Bash can
                    // restore them. Neither is a proven value for later argv.
                    for prefix in &prefixes {
                        state.assign(prefix, false);
                    }
                }
                if original_name.as_deref().is_none_or(mutates_shell)
                    || original_name.as_deref() == Some("printf")
                        && printf_may_assign(&words, &state)
                {
                    state.forget();
                    state.attributes_unknown = true;
                }
            }
            "function_definition" => {
                // A later literal command name can invoke this function and
                // mutate any binding. Until calls/scopes are modeled, do not
                // re-establish scalar facts after seeing the definition.
                state.forget();
                state.attributes_unknown = true;
            }
            _ => state.forget(),
        }
    }
    hits
}

/// A cheap candidate gate, NOT a claim that a write exists. Keep this at the
/// pack-selection boundary too: a runtime-only destination has no raw `/etc`
/// substring from which the keyword gate could select the filesystem pack.
pub(super) fn candidate(command: &str) -> bool {
    if !command.contains(['$', '`']) {
        return false;
    }
    if command.contains("IFS") {
        return true;
    }
    // Declaration builtins also accept quote-removed names: export I'F'S=@.
    // Continuations can split IFS itself. Ignore these bytes only for this
    // lexical superset; the original source and offsets still reach the AST.
    // Quoted data may select the pass, but cannot establish a shell binding.
    let mut prefix = 0;
    for ch in command
        .split("\\\n")
        .flat_map(|part| part.split("\\\r\n"))
        .flat_map(str::chars)
        .filter(|ch| !matches!(*ch, '\'' | '"' | '\\'))
    {
        prefix = match (prefix, ch) {
            (_, 'I') => 1,
            (1, 'F') => 2,
            (2, 'S') => return true,
            _ => 0,
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_spelling_matches_the_existing_native_writer_policy() {
        for (raw, expected) in [
            ("tee", "tee"),
            ("/usr/bin/tee.exe", "tee"),
            ("C:/Tools/TEE.EXE", "tee"),
            ("GTEE.exe", "gtee"),
            ("/opt/é/CP.EXE", "cp"),
            ("tee.exe.bak", "tee.exe.bak"),
            ("teetool.exe", "teetool"),
            ("tee.Exe", "tee.exe"),
            (r"tools\tee.exe", r"tools\tee"),
            ("/", ""),
        ] {
            assert_eq!(policy_executable_basename(raw), expected, "{raw}");
        }
        // A static native-policy witness prevents this selector's accepted
        // spelling set from drifting away from the classifier behind it.
        for (executable, tail, setup, arguments) in [
            ("tee.exe", "/etc/shadow", "S=/tmp/a@/etc/shadow", "$S"),
            ("GTEE.EXE", "/etc/shadow", "S=/tmp/a@/etc/shadow", "$S"),
            ("CP.EXE", "source /etc/shadow", "S=source@/etc/shadow", "$S"),
            ("mv.exe", "source /etc/shadow", "S=source@/etc/shadow", "$S"),
            (
                "install.exe",
                "source /etc/shadow",
                "S=source@/etc/shadow",
                "$S",
            ),
            ("DD.EXE", "of=/etc/shadow", "S=of=/etc/shadow", "$S"),
            (
                "SED.EXE",
                "-i s/a/b/ /etc/shadow",
                "S=/etc/shadow",
                "-i s/a/b/ $S",
            ),
            (
                "perl.exe",
                "-i -pe 1 /etc/shadow",
                "S=/etc/shadow",
                "-i -pe 1 $S",
            ),
        ] {
            let literal_source = format!("{executable} {tail}");
            let literal_hit =
                shell::classify_credential_file_write(&literal_source, ShellDialect::Posix)
                    .unwrap_or_else(|| panic!("missing existing native witness: {literal_source}"));
            assert_eq!(literal_hit.rule, shell::CREDENTIAL_FILE_WRITE_NAME);
            let source = format!("IFS=@; {setup}; {executable} {arguments}");
            let start = source.rfind("; ").unwrap() + 2;
            assert!(
                scan(&source, ShellDialect::Posix).iter().any(|hit| {
                    hit.rule == literal_hit.rule
                        && hit.reason != UNCERTAIN
                        && hit.span == (start..source.len())
                }),
                "the IFS selector lost a writer the native policy recognizes: {source}"
            );
        }
    }

    #[test]
    fn executable_tee_variants_check_all_destinations_and_keep_append_mode() {
        for executable in ["tee.exe", "TEE.EXE", "/usr/bin/tee.exe", "GTEE.EXE"] {
            let source = format!("S=/tmp/a@/etc/shadow@.git/config; IFS=@; {executable} $S");
            let start = source.rfind("; ").unwrap() + 2;
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter().any(|hit| hit.rule == rule
                        && hit.reason != UNCERTAIN
                        && hit.span == (start..source.len())),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
            for (arguments, protected) in [
                (vec!["-a", "/home/example/.ssh/known_hosts"], false),
                (vec!["/home/example/.ssh/known_hosts", "-a"], true),
                (vec!["/etc/shadow", "--help"], true),
                (vec!["--help", "/etc/shadow"], false),
            ] {
                let argv: Vec<_> = std::iter::once(executable)
                    .chain(arguments)
                    .map(str::to_owned)
                    .collect();
                assert_eq!(
                    !classify(&argv, 0..0).unwrap().is_empty(),
                    protected,
                    "{argv:?}"
                );
            }
        }
    }

    #[test]
    fn in_place_writers_keep_every_split_protected_destination() {
        for argv in [
            vec!["sed", "-i", "s/x/y/", "/etc/shadow", ".git/config"],
            vec!["perl", "-i", "-pe", "1", "/etc/shadow", ".git/config"],
        ] {
            let argv: Vec<_> = argv.into_iter().map(str::to_owned).collect();
            let hits = classify(&argv, 0..7).expect("bounded concrete argv");
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.span == (0..7)),
                    "{argv:?}: missing {rule}: {hits:?}"
                );
            }
        }

        for writer in ["sed -i s/x/y/", "perl -i -pe 1"] {
            for source in [
                format!("S=/etc/shadow@.git/config; IFS=@; {writer} $S"),
                format!("S=.git/config@/etc/shadow; IFS=@; {writer} $S"),
            ] {
                let start = source.rfind("; ").unwrap() + 2;
                let hits = scan(&source, ShellDialect::Posix);
                for rule in [
                    shell::CREDENTIAL_FILE_WRITE_NAME,
                    shell::GIT_INTERNALS_WRITE_NAME,
                ] {
                    assert!(
                        hits.iter().any(|hit| {
                            hit.rule == rule
                                && hit.reason != UNCERTAIN
                                && hit.span == (start..source.len())
                        }),
                        "{source}: missing {rule}: {hits:?}"
                    );
                }
            }
            let source = format!("S=/tmp/a@/tmp/b; IFS=@; {writer} $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn executable_spelling_preserves_quotes_data_and_frontend_uncertainty() {
        for invocation in [
            "tee.exe $S",
            "T''EE.EXE $S",
            "W=tee.exe; $W $S",
            "tee.exe \"$S\"",
            "printf '%s' 'TEE.EXE' $S",
            "teetool.exe $S",
            "tee.exe.bak $S",
        ] {
            let source = format!("S=/tmp/a@/tmp/b; IFS=@; {invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for invocation in ["tee.exe \"$S\"", "tee.exe '$S'", "tee.exe \\$S"] {
            let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for invocation in [
            "ENV.EXE tee $S",
            "/usr/bin/env.exe tee $S",
            "W=ENV.EXE; $W tee $S",
        ] {
            let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "an executable frontend must not be mistaken for a non-writer: {source}"
                );
            }
        }
    }

    #[test]
    fn generated_options_belong_to_all_execution_wrappers_not_shell_syntax() {
        for wrapper in [
            "sudo",
            "env",
            "command",
            "exec",
            "nohup",
            "time",
            "nice",
            "ionice",
            "setsid",
            "timeout",
            "stdbuf",
            "chrt",
            "busybox",
            "mise-exec",
        ] {
            for word in ["-n", "--", "-oL", "--adjustment=0"] {
                assert!(
                    wrapper_may_own_generated_control(wrapper, word),
                    "{wrapper}: {word}"
                );
            }
            for word in ["tee", "printf", "/tmp/safe-option-like-name"] {
                assert!(
                    !wrapper_may_own_generated_control(wrapper, word),
                    "{wrapper}: {word}"
                );
            }
        }
        for wrapper in ["assignment", "backslash"] {
            for word in ["-n", "--", "NAME=value"] {
                assert!(
                    !wrapper_may_own_generated_control(wrapper, word),
                    "{wrapper}: {word}"
                );
            }
        }
        for wrapper in ["command", "env"] {
            assert!(wrapper_may_own_generated_control(wrapper, "NAME=value"));
        }
        for wrapper in ["nice", "stdbuf", "exec", "nohup"] {
            assert!(!wrapper_may_own_generated_control(wrapper, "NAME=value"));
        }
    }

    #[test]
    fn generated_frontend_options_cannot_hide_native_writer_destinations() {
        for (setup, invocation, wrapper) in [
            ("OPT=-n", "nice $OPT 0 tee $S", "nice"),
            ("E=", "nice $E -n 0 tee $S", "nice"),
            ("E=", "nice ${E}${E} --adjustment=0 tee $S", "nice"),
            ("E=", "nice $E -- tee $S", "nice"),
            (
                "OPT=--adjustment=0",
                r#"/usr/bin/nice "$OPT" tee $S"#,
                "nice",
            ),
            ("OPT=-oL", "stdbuf $OPT tee $S", "stdbuf"),
            ("E=", "stdbuf -oL $E -eL tee $S", "stdbuf"),
            ("E=", "/usr/bin/time $E -p tee $S", "time"),
            ("E=", "nohup $E -- tee $S", "nohup"),
            ("OPT=-w", "setsid $OPT tee $S", "setsid"),
            ("E=", "ionice $E -c 2 tee $S", "ionice"),
            ("E=", "exec $E -a label tee $S", "exec"),
            ("E=", "sudo $E -u root tee $S", "sudo"),
        ] {
            let normalized = strip_wrapper_prefixes(invocation);
            assert!(!normalized.wrapper_limit_reached);
            assert!(
                normalized
                    .stripped_wrappers
                    .iter()
                    .any(|item| item.wrapper_type == wrapper),
                "the raw-source command boundary must be exercised: {invocation}"
            );
            for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
                let source = format!("S={value}; IFS=@; {setup}; {invocation}");
                let ast = AstGrep::try_new(source.as_str(), SupportLang::Bash).unwrap();
                assert!(!ast.root().get_inner_node().has_error(), "{source}");
                let start = source.rfind("; ").unwrap() + 2;
                let hits = scan(&source, ShellDialect::Posix);
                for rule in [
                    shell::CREDENTIAL_FILE_WRITE_NAME,
                    shell::GIT_INTERNALS_WRITE_NAME,
                ] {
                    assert!(
                        hits.iter().any(|hit| hit.rule == rule
                            && hit.reason == UNCERTAIN
                            && hit.span == (start..source.len())),
                        "generated options cannot waive {rule}: {source}: {hits:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn resolved_frontends_and_literal_empty_arguments_keep_their_roles() {
        for prefix in [
            "nice -n 0 ",
            "stdbuf -oL ",
            "nohup -- ",
            "/usr/bin/time -p ",
            "setsid -w ",
            "ionice -c 2 ",
        ] {
            for (value, rule) in [
                ("/tmp/a@/etc/shadow", shell::CREDENTIAL_FILE_WRITE_NAME),
                ("/tmp/a@.git/config", shell::GIT_INTERNALS_WRITE_NAME),
            ] {
                let source = format!("S={value}; IFS=@; {prefix}tee $S");
                assert!(
                    scan(&source, ShellDialect::Posix)
                        .iter()
                        .any(|hit| hit.rule == rule && hit.reason != UNCERTAIN),
                    "resolved wrappers must keep concrete attribution: {source}"
                );
            }
            let source = format!("S=/tmp/a@/tmp/b; IFS=@; {prefix}tee $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
            let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {prefix}printf '%s' '-n' $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for invocation in [r#"nice "$E" -n 0 tee $S"#, r#"nohup "$E" -- tee $S"#] {
            let source = format!("E=; S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            // A quoted empty executable is not removed by the shell, so it
            // cannot expose these later words as options to the wrapper.
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for invocation in [
            "nice $E printf '%s' $S",
            "stdbuf -oL $E printf '%s' $S",
            "nohup $E printf '%s' $S",
        ] {
            let source = format!("E=; S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn executable_selection_skips_only_proven_vanishing_fields() {
        let mut state = State::default();
        state.assign("IFS=@", true);
        state.assign("E=", true);
        state.assign("FLAGS=-p@--", true);
        for (words, expected) in [
            (vec![], Ok(None)),
            (vec!["$E", "tee"], Ok(Some("tee"))),
            (vec!["$E", "${E}${E}", "env"], Ok(Some("env"))),
            (vec!["$E", "$E", "-p"], Ok(Some("-p"))),
            (vec!["$E", "$FLAGS"], Ok(Some("-p"))),
            (vec![r#""$E""#, "tee"], Ok(Some(""))),
            (vec!["''", "tee"], Ok(Some(""))),
            (vec!["$E", "${E}''", "tee"], Ok(Some(""))),
            (vec!["$UNKNOWN", "tee"], Err(())),
            (vec!["$E", "$UNKNOWN", "tee"], Err(())),
            (vec!["$E", "'$UNKNOWN'"], Ok(Some("$UNKNOWN"))),
        ] {
            assert_eq!(
                first_expanded_word(&words, &state),
                expected.map(|name| name.map(str::to_owned)),
                "{words:?}"
            );
        }
        state.assign("E=@", true);
        assert_eq!(
            first_expanded_word(&["$E", "tee"], &state),
            Ok(Some(String::new()))
        );
        state.assign("IFS=' '", true);
        state.assign("E='   '", true);
        assert_eq!(
            first_expanded_word(&["$E", "tee"], &state),
            Ok(Some("tee".to_owned()))
        );
        let mut words = vec!["$E"; MAX_FIELDS - 1];
        words.push("tee");
        assert_eq!(
            first_expanded_word(&words, &state),
            Ok(Some("tee".to_owned()))
        );
        words.insert(0, "$E");
        assert!(first_expanded_word(&words, &state).is_err());
        let source = format!(
            "E=; S=/tmp/a@/etc/shadow; IFS=@; command {}-p tee $S",
            "$E ".repeat(MAX_FIELDS + 1)
        );
        let hits = scan(&source, ShellDialect::Posix);
        for rule in [
            shell::CREDENTIAL_FILE_WRITE_NAME,
            shell::GIT_INTERNALS_WRITE_NAME,
        ] {
            assert!(
                hits.iter()
                    .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN)
            );
        }
    }

    #[test]
    fn vanishing_words_cannot_hide_wrapper_options_or_assignments() {
        for invocation in [
            "command $E -p tee $S",
            "command $E $E -p -- tee $S",
            "command ${E}${E} -p tee $S",
            "command $E $OPT tee $S",
            "env $E DCG_X=1 tee $S",
            "env $E $SETTING tee $S",
            "env $E -i tee $S",
            "env $E -- tee $S",
            "command env $E DCG_X=1 tee $S",
            "/usr/bin/env $E -i tee $S",
        ] {
            let normalized = strip_wrapper_prefixes(invocation);
            assert!(!normalized.wrapper_limit_reached);
            assert!(normalized.normalized.starts_with('$'), "{invocation}");
            for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
                let source = format!("E=; OPT=-p; SETTING=DCG_X=1; S={value}; IFS=@; {invocation}");
                let start = source.rfind("; ").unwrap() + 2;
                let hits = scan(&source, ShellDialect::Posix);
                for rule in [
                    shell::CREDENTIAL_FILE_WRITE_NAME,
                    shell::GIT_INTERNALS_WRITE_NAME,
                ] {
                    assert!(
                        hits.iter().any(|hit| hit.rule == rule
                            && hit.reason == UNCERTAIN
                            && hit.span == (start..source.len())),
                        "vanishing words cannot hide {rule}: {source}: {hits:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn first_surviving_writer_retains_concrete_destination_checks() {
        for invocation in ["$E tee $S", "command $E tee $S", "env $E tee $S"] {
            for (value, rule) in [
                ("/tmp/a@/etc/shadow", shell::CREDENTIAL_FILE_WRITE_NAME),
                ("/tmp/a@.git/config", shell::GIT_INTERNALS_WRITE_NAME),
            ] {
                let source = format!("E=; S={value}; IFS=@; {invocation}");
                assert!(
                    scan(&source, ShellDialect::Posix)
                        .iter()
                        .any(|hit| hit.rule == rule && hit.reason != UNCERTAIN),
                    "{source}"
                );
            }
            let source = format!("E=; S=/tmp/a@/tmp/b; IFS=@; {invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for invocation in [
            "command $E printf '%s' $S",
            "env $E printf '%s' $S",
            "command -v $E tee",
            "command -V $E tee",
        ] {
            let source = format!("E=; S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn source_continuations_preserve_single_quotes_and_escaped_backslashes() {
        for (raw, expected) in [
            ("I\\\nFS=@", "IFS=@"),
            ("$TA\\\nRGET", "$TARGET"),
            ("${TA\\\nRGET}", "${TARGET}"),
            ("\"$TA\\\nRGET\"", "\"$TARGET\""),
            ("'$TA\\\nRGET'", "'$TA\\\nRGET'"),
            ("\\$TA\\\nRGET", "\\$TARGET"),
            ("\"$TA\"\\\nRGET", "\"$TA\"RGET"),
            ("$TA\\\\\nRGET", "$TA\\\\\nRGET"),
            ("S='a\\\nb'", "S='a\\\nb'"),
            ("S=\"a\\\nb\"", "S=\"ab\""),
            ("S='x'\\\n'y'", "S='x''y'"),
            ("S=trailing\\", "S=trailing\\"),
        ] {
            assert_eq!(source_word_without_continuations(raw), expected, "{raw:?}");
        }
    }

    #[test]
    fn continued_names_are_recognized_before_assignment_and_field_expansion() {
        let mut state = State::default();
        state.assign("TA=/tmp/safe", true);
        state.assign("TA\\\nRGET=/tmp/a@/etc/shadow", true);
        state.assign("I\\\nF\\\nS=@", true);
        for raw in ["$TA\\\nRGET", "${TA\\\nRGET}"] {
            assert_eq!(expand(raw, &state).unwrap(), ["/tmp/a", "/etc/shadow"]);
        }
        assert_eq!(
            expand("\"$TA\\\nRGET\"", &state).unwrap(),
            ["/tmp/a@/etc/shadow"]
        );
        assert_eq!(
            expand("\"$TA\"\\\nRGET", &state).unwrap(),
            ["/tmp/safeRGET"]
        );
        state.assign("COPY=$TA\\\nRGET", true);
        assert_eq!(state.value("COPY"), Some("/tmp/a@/etc/shadow"));
        state.assign("TA\\\nRGET+=@.git/config", true);
        assert_eq!(
            expand("$TA\\\nRGET", &state).unwrap(),
            ["/tmp/a", "/etc/shadow", ".git/config"]
        );
        // A continuation-shaped sequence inside a VALUE is data. It must
        // not be removed after expansion or copied into executable syntax.
        state.assign("VALUE='a\\\nb'", true);
        assert_eq!(expand("\"$VALUE\"", &state).unwrap(), ["a\\\nb"]);
        assert_eq!(expand("$VALUE", &state).unwrap(), ["a\\\nb"]);
    }

    #[test]
    fn candidate_gate_sees_continued_ifs_without_joining_ordinary_lines() {
        for source in [
            "I\\\nFS=@; tee $TARGET",
            "IF\\\nS=@; tee $TARGET",
            "I\\\nF\\\nS=@; tee $TARGET",
            "export I\\\nFS=@; tee $TARGET",
            "I\\\r\nFS=@; tee $TARGET",
            "export I'F'S=@; tee $TARGET",
        ] {
            assert!(candidate(source), "{source:?}");
        }
        for source in [
            "I\nFS=@; echo $TARGET",
            "IF\nS=@; echo $TARGET",
            "I FS=@; echo $TARGET",
            "IFS=@",
            "tee /tmp/safe",
        ] {
            assert!(!candidate(source), "{source:?}");
        }
    }

    #[test]
    fn continued_ifs_and_parameter_names_reach_concrete_native_policy() {
        for (target, rule) in [
            ("/etc/shadow", shell::CREDENTIAL_FILE_WRITE_NAME),
            (".git/config", shell::GIT_INTERNALS_WRITE_NAME),
        ] {
            for (ifs, binding, read) in [
                ("I\\\nFS=@", "TARGET", "$TARGET"),
                ("IF\\\nS=@", "TARGET", "$TARGET"),
                ("I\\\nF\\\nS=@", "TARGET", "$TARGET"),
                ("IFS=@", "TA\\\nRGET", "$TARGET"),
                ("IFS=@", "TARGET", "$TA\\\nRGET"),
                ("IFS=@", "TARGET", "${TA\\\nRGET}"),
            ] {
                let source = format!("TA=/tmp/safe; {binding}=/tmp/a@{target}; {ifs}; tee {read}");
                let start = source.rfind("; ").unwrap() + 2;
                let hits = scan(&source, ShellDialect::Posix);
                assert!(
                    hits.iter().any(|hit| hit.rule == rule
                        && hit.reason != UNCERTAIN
                        && hit.span == (start..source.len())),
                    "continued names cannot hide a concrete destination: {source:?}: {hits:?}"
                );
            }
        }
        let source = "NA=DCG_UNUSED; NAME=DCG_UNUSED@tee; S=/tmp/a@/etc/shadow; IFS=@; env -u $NA\\\nME echo $S";
        let hits = scan(source, ShellDialect::Posix);
        for rule in [
            shell::CREDENTIAL_FILE_WRITE_NAME,
            shell::GIT_INTERNALS_WRITE_NAME,
        ] {
            assert!(
                hits.iter()
                    .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                "continued wrapper options must not bind to a shorter name: {hits:?}"
            );
        }
    }

    /// The source is read as the shell reads it: each line continuation is
    /// removed where the shell removes one, and only there. A comment ends at
    /// its line whatever it ends in; a `#` starts one where a word starts,
    /// after a subshell's `)` too, but not after a substitution's.
    #[test]
    fn line_continuations_are_removed_where_the_shell_removes_them() {
        for (command, joined) in [
            ("I\\\nFS=@; tee $T", Some("IFS=@; tee $T")),
            ("echo \"a\\\nb\"", Some("echo \"ab\"")),
            ("echo $(x)#a\\\nb", Some("echo $(x)#ab")),
            ("echo $((1))#a\\\nb", Some("echo $((1))#ab")),
            ("echo 'a\\\nb'; I\\\nFS=@", Some("echo 'a\\\nb'; IFS=@")),
            ("echo a # b\\\nI\\\nFS=@", Some("echo a # b\\\nIFS=@")),
            ("(x)#a\\\nIFS=@", None),
            ("((1))#a\\\nIFS=@", None),
            (
                "cat <<'EOF'\na\\\nEOF\nI\\\nFS=@",
                Some("cat <<'EOF'\na\\\nEOF\nIFS=@"),
            ),
            ("echo a", None),
        ] {
            let result = join_line_continuations(command);
            assert_eq!(
                result.as_ref().map(|(joined, _)| joined.as_str()),
                joined,
                "{command:?}"
            );
            if let Some((joined, offsets)) = result {
                assert_eq!(offsets.len(), joined.len() + 1, "{command:?}");
                for (at, byte) in joined.bytes().enumerate() {
                    assert_eq!(command.as_bytes()[offsets[at]], byte, "{command:?}");
                }
            }
        }
    }

    #[test]
    fn quoted_continuation_data_empty_ifs_and_read_idioms_remain_harmless() {
        for source in [
            "TARGET=/tmp/a@/tmp/b; I\\\nFS=@; tee $TARGET",
            "TARGET=/tmp/a@/etc/shadow; I\\\nFS=; tee $TARGET",
            "TARGET=/tmp/a@/etc/shadow; I\\\nFS=@; tee \"$TARGET\"",
            "TA=/tmp/safe; TARGET=/etc/shadow; IFS=@; tee \"$TA\"\\\nRGET",
            "IFS=@; printf '%s' '$TA\\\nRGET'",
            "I\\\nFS= read -r line",
            "TA\\\nRGET=/tmp/safe",
            "IFS=@; S='a\\\nb'; tee \"$S\"",
            "NA=DCG_UNUSED; NAME=DCG_UNUSED@tee; S=/tmp/a@/etc/shadow; IFS=@; env -u \"$NA\\\nME\" echo $S",
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source:?}");
        }
    }

    #[test]
    fn command_query_proof_requires_literal_options_before_operands() {
        for (words, expected) in [
            (vec!["command", "-v", "$S"], true),
            (vec!["command", "-V", "$S"], true),
            (vec!["command", "-p", "'-v'", "$S"], true),
            (vec!["c'om'mand", "-pV", "$S"], true),
            (vec!["command", "-vp", "$S"], true),
            (vec!["command", "--", "-v", "$S"], false),
            (vec!["command", "$OPT", "-v", "$S"], false),
            (vec!["command", "tee", "-v", "$S"], false),
            (vec!["command", "-p", "tee", "$S"], false),
            (vec!["command", "-", "-v", "$S"], false),
            (vec!["command", "-xv", "$S"], false),
            (vec!["$TOOL", "-v", "$S"], false),
            (vec!["env", "-v", "$S"], false),
        ] {
            assert_eq!(command_queries_only(&words), expected, "{words:?}");
        }
    }

    #[test]
    fn short_unresolved_frontends_cannot_hide_split_destinations() {
        for (setup, invocation) in [
            ("N=DCG_UNUSED@tee", "env -u $N echo $S"),
            ("N=DCG_UNUSED@tee", "env --unset=$N echo $S"),
            ("N=", "env -u $N tee $S"),
            ("D=1@tee", "timeout $D echo $S"),
            ("P=0@tee", "nice -n $P echo $S"),
            ("B=L@tee", "stdbuf -o $B echo $S"),
            ("U=root@tee", "sudo -u $U echo $S"),
            ("W=env", "$W tee $S"),
            ("OPT=-p", "command $OPT tee $S"),
            ("SETTING=DCG_X=1", "env $SETTING tee $S"),
            ("E=; N=DCG_UNUSED", r#"$E env -u "$N" tee $S"#),
            ("N=DCG_UNUSED", r#""env" -u "$N" tee $S"#),
            ("W=env", "command $W tee $S"),
            ("N=DCG_UNUSED@tee", "/usr/bin/env -u $N echo $S"),
            ("OPT=-p", "builtin command $OPT tee $S"),
        ] {
            let normalized = strip_wrapper_prefixes(invocation);
            assert!(!normalized.wrapper_limit_reached);
            if invocation.ends_with("echo $S") {
                assert_eq!(normalized.normalized.as_ref(), "echo $S", "{invocation}");
            }
            for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config"] {
                let source = format!("S={value}; IFS=@; {setup}; {invocation}");
                let ast = AstGrep::try_new(source.as_str(), SupportLang::Bash).unwrap();
                assert!(!ast.root().get_inner_node().has_error(), "{source}");
                let start = source.rfind("; ").unwrap() + 2;
                let hits = scan(&source, ShellDialect::Posix);
                for rule in [
                    shell::CREDENTIAL_FILE_WRITE_NAME,
                    shell::GIT_INTERNALS_WRITE_NAME,
                ] {
                    assert!(
                        hits.iter().any(|hit| hit.rule == rule
                            && hit.reason == UNCERTAIN
                            && hit.span == (start..source.len())),
                        "incomplete frontend proof cannot waive {rule}: {source}: {hits:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn resolved_frontend_options_and_command_queries_keep_their_roles() {
        for invocation in [
            "command -v tee $S",
            "command -p -V tee $S",
            "command -pv tee $S",
            "command -- printf '%s' $S",
            "env -u DCG_UNUSED printf '%s' $S",
            "timeout 1 printf '%s' $S",
            "nice -n 0 printf '%s' $S",
            "printf '%s' 'env' $S",
            r#"env -u "$UNKNOWN" printf '%s' $S"#,
        ] {
            let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for prefix in ["env -u DCG_UNUSED ", "timeout 1 ", "nice -n 0 "] {
            for (value, rule) in [
                ("/tmp/a@/etc/shadow", shell::CREDENTIAL_FILE_WRITE_NAME),
                ("/tmp/a@.git/config", shell::GIT_INTERNALS_WRITE_NAME),
            ] {
                let source = format!("S={value}; IFS=@; {prefix}tee $S");
                assert!(
                    scan(&source, ShellDialect::Posix)
                        .iter()
                        .any(|hit| hit.rule == rule && hit.reason != UNCERTAIN),
                    "{source}"
                );
            }
            let source = format!("S=/tmp/a@/tmp/b; IFS=@; {prefix}tee $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
        for invocation in [
            "env -u $N tee $S",
            r#"env -u "$N" tee $S"#,
            r#"env --unset="$N" tee $S"#,
            r#"env -u "$UNKNOWN" tee $S"#,
            r#"timeout "$D" tee $S"#,
            r#"nice -n "$P" tee $S"#,
            r#"stdbuf -o "$B" tee $S"#,
            r"\tee $S",
        ] {
            let source =
                format!("N=DCG_UNUSED; D=1; P=0; B=L; S=/tmp/a@/etc/shadow; IFS=@; {invocation}");
            assert!(
                scan(&source, ShellDialect::Posix).iter().any(|hit| {
                    hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME && hit.reason != UNCERTAIN
                }),
                "{source}"
            );
        }
        // Quoting the option value prevents an extra command word, even
        // when that value contains IFS separators or cannot be resolved.
        let source = r#"N=DCG_UNUSED@tee; S=/tmp/a@/etc/shadow; IFS=@; env -u "$N" echo $S"#;
        assert!(scan(source, ShellDialect::Posix).is_empty());
    }

    #[test]
    fn discarded_wrapper_words_need_single_field_proofs() {
        let mut state = State::default();
        state.assign("IFS=@", true);
        state.assign("N=DCG_UNUSED@tee", true);
        state.assign("E=", true);
        for prefix in ["env -u $N", "env --unset=$N", "env -u $E", "env -u *"] {
            assert!(!wrapper_prefix_preserves_fields(prefix, &state), "{prefix}");
        }
        for prefix in [
            r#"env -u "$N""#,
            r#"env -u "$UNKNOWN""#,
            r#"env --unset="$UNKNOWN""#,
            "env -u DCG_UNUSED",
            "command -p",
            "env -u '$N'",
        ] {
            assert!(wrapper_prefix_preserves_fields(prefix, &state), "{prefix}");
        }
        state.assign("N=DCG_UNUSED", true);
        assert!(wrapper_prefix_preserves_fields("env -u $N", &state));
        assert!(!wrapper_prefix_preserves_fields(
            &"command ".repeat(MAX_FIELDS + 1),
            &state
        ));
    }

    #[test]
    fn wrapper_exhaustion_cannot_skip_ifs_destination_analysis() {
        for wrapper in ["command ", "command -p ", "env "] {
            for depth in [33, 64, 96] {
                let invocation = format!("{}tee $S", wrapper.repeat(depth));
                assert!(strip_wrapper_prefixes(&invocation).wrapper_limit_reached);
                for value in ["/tmp/a@/etc/shadow", "/tmp/a@.git/config", "/tmp/safe"] {
                    let source = format!("S={value}; IFS=@; {invocation}");
                    let start = source.rfind("; ").unwrap() + 2;
                    let hits = scan(&source, ShellDialect::Posix);
                    for rule in [
                        shell::CREDENTIAL_FILE_WRITE_NAME,
                        shell::GIT_INTERNALS_WRITE_NAME,
                    ] {
                        assert!(
                            hits.iter().any(|hit| hit.rule == rule
                                && hit.reason == UNCERTAIN
                                && hit.span == (start..source.len())),
                            "unresolved wrapper cannot exempt either family: {source}: {hits:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn resolved_wrappers_keep_concrete_findings_and_harmless_controls() {
        for wrapper in ["command ", "command -p ", "env "] {
            for depth in [1, 8, 31] {
                let prefix = wrapper.repeat(depth);
                assert!(!strip_wrapper_prefixes(&format!("{prefix}tee $S")).wrapper_limit_reached);
                for (value, rule) in [
                    ("/tmp/a@/etc/shadow", shell::CREDENTIAL_FILE_WRITE_NAME),
                    ("/tmp/a@.git/config", shell::GIT_INTERNALS_WRITE_NAME),
                ] {
                    let source = format!("S={value}; IFS=@; {prefix}tee $S");
                    let hits = scan(&source, ShellDialect::Posix);
                    assert!(
                        hits.iter()
                            .any(|hit| hit.rule == rule && hit.reason != UNCERTAIN)
                    );
                }
                for invocation in ["tee $S", "printf '%s' $S", "tee \"$S\""] {
                    let source = format!("S=/tmp/a@/tmp/b; IFS=@; {prefix}{invocation}");
                    assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
                }
            }
        }
        // No field expansion means this pass has no additional argv to check.
        // Do not turn literal data or quoted scalars into a splitting hazard.
        let prefix = "command ".repeat(64);
        for invocation in ["tee /tmp/safe", "tee '$S'", "tee \"$S\""] {
            let source = format!("S=/tmp/a@/tmp/b; IFS=@; {prefix}{invocation}");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn declaration_braces_preserve_quote_and_escape_provenance() {
        for raw in [
            "S={one,two}",
            "S+=prefix{one,two}",
            "S={1..3}",
            "S={a..z..2}",
            "S={a.\\\n.z}",
            "S=outer{inner{one,two}}",
            "S=\"prefix\"{one,'two'}",
            "S={one,\"two\"}",
        ] {
            assert!(declaration_may_expand_braces(raw), "{raw}");
        }
        for raw in [
            "S=one,two",
            "S={literal}",
            "S=unclosed{one,two",
            "S='{one,two}'",
            r#"S="{one,two}""#,
            r"S=\{one,two\}",
            r"S={one\,two}",
            "S={one','two}",
            "S='{1..3}'",
            r"S=\{1..3\}",
            "S=/tmp/*",
            "IFS=*",
        ] {
            assert!(!declaration_may_expand_braces(raw), "{raw}");
        }
    }

    #[test]
    fn brace_expanded_exports_cannot_establish_false_literal_destinations() {
        for declaration in [
            "export S={/tmp/safe,/tmp/a@/etc/shadow}",
            "export S=/tmp/{safe,a@/etc/shadow}",
            "export S=/tmp/{safe,{other,a@/etc/shadow}}",
            "export S=/tmp/a@/etc/{s..s}hadow",
            "export S=/tmp/a@/etc/{s.\\\n.s}hadow",
            "export S+={,\"@/etc/shadow\"}",
            "export IFS={d..f}; S=/tmp/af/etc/shadow",
        ] {
            let source = format!("S=/tmp/safe; IFS=@; {declaration}; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn declaration_braces_do_not_erase_unrelated_or_reestablished_facts() {
        for source in [
            "IFS=@; export S='/tmp/{safe,a@/etc/shadow}'; tee $S",
            r#"IFS=@; export S="/tmp/{safe,a@/etc/shadow}"; tee $S"#,
            r"IFS=@; export S=/tmp/\{safe,a@/etc/shadow\}; tee $S",
            "IFS=@; S=/tmp/{safe,a@/etc/shadow}; tee $S",
            "IFS=@; export S=/tmp/{literal}; tee $S",
            "S=/tmp/safe; IFS=@; export T={one,two}; tee $S",
            "IFS=@; export S={one,two} S=/tmp/safe; tee $S",
            "IFS=@; export S={one,two}; S=/tmp/safe; tee $S",
            "export IFS={d..f}; IFS=@; S=/tmp/a@/tmp/b; tee $S",
            "export IFS=*; S='/tmp/a*/tmp/b'; tee $S",
            "IFS=@; export S={/tmp/safe,/etc/shadow}",
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
        // Losing the brace-affected value must not poison future proofs.
        let source = "IFS=@; export S={one,two}; S=/tmp/a@/etc/shadow; tee $S";
        assert!(scan(source, ShellDialect::Posix).iter().any(|hit| {
            hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME && hit.reason != UNCERTAIN
        }));
    }

    #[test]
    fn async_terminators_use_statement_syntax_not_assignment_suffixes() {
        for (source, expected) in [
            ("S=safe T=x & echo ok", true),
            ("S=safe T=x \\\n& echo ok", true),
            ("S=safe \\\n& echo ok", true),
            ("export S=safe T=x & echo ok", true),
            ("S=safe T=x; echo ok", false),
            ("S=safe T=x && echo ok", false),
            ("S=safe T=x &>/tmp/out; echo ok", false),
            ("S='safe&' T=x; echo ok", false),
        ] {
            let ast = AstGrep::try_new(source, SupportLang::Bash).unwrap();
            assert!(!ast.root().get_inner_node().has_error(), "{source}");
            let statement = ast.root().children().find(Node::is_named).unwrap();
            assert_eq!(has_async_terminator(&statement), expected, "{source}");
        }
    }

    #[test]
    fn background_assignment_groups_cannot_hide_parent_destinations() {
        for mutation in [
            "S=/tmp/safe T=x &",
            "T=x S=/tmp/safe U=y &",
            "IFS=: T=x &",
            "T=x IFS=: U=y &",
            "export S=/tmp/safe T=x &",
            "export IFS=: T=x &",
            "S=/tmp/safe \\\n&",
            "S=/tmp/safe T=x \\\n&",
            "IFS=: T=x \\\n&",
        ] {
            let source = format!("S=/tmp/a@/etc/shadow; IFS=@; {mutation} tee $S");
            let start = source.rfind("tee $S").unwrap();
            for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
                let hits = scan(&source, dialect);
                for rule in [
                    shell::CREDENTIAL_FILE_WRITE_NAME,
                    shell::GIT_INTERNALS_WRITE_NAME,
                ] {
                    assert!(
                        hits.iter().any(|hit| hit.rule == rule
                            && hit.reason == UNCERTAIN
                            && hit.span == (start..source.len())),
                        "{source}: missing {rule} in {dialect:?}: {hits:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn foreground_groups_and_unrelated_background_bindings_remain_precise() {
        for source in [
            "S=/tmp/a@/etc/shadow; IFS=@; S=/tmp/safe T=x; tee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; IFS=: T=x; tee $S",
            "S=/tmp/safe; IFS=@; T=x U=y & tee $S",
            "S=/tmp/safe; IFS=@; T=x U=y \\\n& tee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; S=/tmp/other T=x & S=/tmp/safe; tee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; IFS=: T=x & IFS=; tee $S",
            "S='safe&'; IFS=@; T=x U=y; tee $S",
            "IFS=@; S=/tmp/safe T=x &",
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    /// Execute only fixed assignments and argv printing, never a writer.
    /// Assert the production scan separately against the corresponding source.
    #[test]
    #[cfg(unix)]
    fn background_binding_regressions_match_real_shell_argv() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for mutation in [
                "S=/tmp/safe T=x &",
                "T=x S=/tmp/safe U=y &",
                "IFS=: T=x &",
                "T=x IFS=: U=y &",
                "S=/tmp/safe T=x \\\n&",
                "IFS=: T=x \\\n&",
            ] {
                let prefix = format!("S=/tmp/a@/etc/shadow; IFS=@; {mutation}");
                let source = format!("{prefix} tee $S");
                assert!(
                    scan(&source, ShellDialect::Posix)
                        .iter()
                        .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME),
                    "native scan lost the inherited destination: {source}"
                );
                let script = format!(
                    "{prefix} set -- $S; printf '%s\\0' \"$#\"; for arg; do printf '%s\\0' \"$arg\"; done; wait"
                );
                let output = std::process::Command::new(shell)
                    .args(["-c", &script])
                    .env_clear()
                    .output()
                    .expect("background assignment argv probe");
                assert!(output.status.success(), "{shell}: {output:?}");
                assert_eq!(
                    output.stdout, b"2\0/tmp/a\0/etc/shadow\0",
                    "{shell}: {mutation}"
                );
            }
        }
    }

    #[test]
    fn scalar_word_syntax_distinguishes_reads_from_effects_566() {
        for raw in [
            "$S/e2e.log",
            "${S}/e2e.log",
            r#""${S}"/e2e.log"#,
            "prefix${S}${T}/file",
            r"${S}'$(not executed)'",
        ] {
            assert!(
                scalar_word(raw, |_, _| Some(String::new())).is_some(),
                "{raw}"
            );
        }
        for raw in [
            "${IFS:=@}/file",
            "${S:-$T}",
            "${!S}",
            "${S[0]}",
            "${S[@]}",
            "$@/file",
            "${@:1}",
            "$((IFS=1))",
            "$(command)/file",
            "`command`/file",
            "$'text'${S}",
            "$S/*",
            "~/$S",
            "${S}{a,b}",
            "\"${S}",
            r#"${S}"`not executed`""#,
        ] {
            assert!(
                scalar_word(raw, |_, _| Some(String::new())).is_none(),
                "{raw}"
            );
        }
    }

    #[test]
    fn single_field_scalar_paths_preserve_quotes_and_null_arguments_566() {
        let mut state = State::default();
        state.assign("IFS=", true);
        state.assign("S='/tmp/élève work'", true);
        state.assign("E=", true);
        for (raw, expected) in [
            ("$S/e2e.log", vec!["/tmp/élève work/e2e.log"]),
            ("${S}/e2e.log", vec!["/tmp/élève work/e2e.log"]),
            (r#""$S"/e2e.log"#, vec!["/tmp/élève work/e2e.log"]),
            ("${E}${E}", vec![]),
            ("${E}''${E}", vec![""]),
            ("${E}/file", vec!["/file"]),
            (r"${S}'*'", vec!["/tmp/élève work*"]),
        ] {
            assert_eq!(expand(raw, &state).unwrap(), expected, "{raw}");
        }
        state.assign("S=/tmp/work", true);
        state.assign("IFS=@", true);
        assert_eq!(expand("$S/a@b", &state).unwrap(), ["/tmp/work/a@b"]);
        state.assign("IFS=/", true);
        assert!(expand("$S/file", &state).is_err());
        assert_eq!(expand(r#""$S"/file"#, &state).unwrap(), ["/tmp/work/file"]);
    }

    #[test]
    fn concatenation_never_quotes_away_unknown_splitting_or_patterns_566() {
        let mut state = State::default();
        state.assign("S=/tmp/work", true);
        assert!(
            expand("$S/file", &state).is_err(),
            "IFS is not inherited from dcg"
        );
        state.assign("IFS=@", true);
        for value in ["/tmp/a@/etc", "-i@/etc", "*.txt", "a?", "[ab]", "@(a|b)"] {
            state.values.insert("S".into(), value.into());
            assert!(expand("${S}/profile", &state).is_err(), "{value}");
            assert_eq!(
                expand(r#""${S}"/profile"#, &state).unwrap(),
                [format!("{value}/profile")]
            );
        }
        assert!(expand("${UNRESOLVED}/file", &state).is_err());
        state.values.insert("S".into(), "x".repeat(MAX_VALUE_BYTES));
        assert!(expand("${S}/file", &state).is_err());
        assert!(scalar_word(&"x".repeat(MAX_VALUE_BYTES + 1), |_, _| None).is_none());
    }

    #[test]
    fn log_readers_do_not_invent_an_earlier_ifs_mutation_566() {
        for source in [
            "S=/tmp/work; IFS= ; sed -n 3,8p $S/e2e.log",
            "S=/tmp/work; sed -n 3,8p $S/e2e.log | while IFS= read -r l; do echo \"$l\"; done",
            "S=/tmp/work; sed -n p $S/e2e.log | while IFS= read -r l; do echo; done",
            "S=/tmp/work; cat log | sed -n p ${S}/e2e.log | while IFS= read -r l; do echo; done",
            "S=/tmp/work; IFS=@; sed -n p $S/e2e.log",
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn resolved_scalar_paths_reach_native_writers_with_original_spans_566() {
        // Use destinations present in the shared native policy. In
        // particular, /etc/profile is not in that policy's table, so a
        // resolved /etc/profile field proves nothing about recovery.
        for (source, rule) in [
            (
                "S=/etc; IFS=; tee $S/shadow",
                shell::CREDENTIAL_FILE_WRITE_NAME,
            ),
            (
                "S=.git; IFS=; tee ${S}/config",
                shell::GIT_INTERNALS_WRITE_NAME,
            ),
            (
                "S=/etc; IFS=; cp source $S/shadow",
                shell::CREDENTIAL_FILE_WRITE_NAME,
            ),
            (
                "S=/etc; IFS=; dd of=${S}/shadow",
                shell::CREDENTIAL_FILE_WRITE_NAME,
            ),
            (
                "S=/etc; IFS=; sed -i s/x/y/ $S/shadow",
                shell::CREDENTIAL_FILE_WRITE_NAME,
            ),
        ] {
            let start = source.rfind("; ").unwrap() + 2;
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| hit.rule == rule
                    && hit.reason != UNCERTAIN
                    && hit.span == (start..source.len())),
                "resolved paths must not bypass native policy: {source}: {hits:?}"
            );
        }
    }

    #[test]
    fn unresolved_scalar_paths_keep_both_rule_families_566() {
        for source in [
            "S=/tmp/a@/etc/profile; IFS=@; tee prefix${S}",
            "S=/tmp/a@/etc; IFS=@; IFS= tee ${S}/profile",
            "S=/tmp/work; IFS=$CUSTOM; tee ${S}/profile",
            "S=/tmp/safe; IFS=; printf -v S /etc; tee $S/profile",
            "S=/tmp/work; IFS=; tee ${UNRESOLVED}/profile",
            "S=-i@/etc; IFS=@; sed -n p ${S}/profile",
            "S=/tmp/work; IFS=@; echo ${S}; tee ${S}/${IFS:=/}",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "uncertainty cannot grant either family: {source}: {hits:?}"
                );
            }
        }
    }

    /// Only fixed parameter-read words are executed by this oracle. Values
    /// arrive through the environment and are never evaluated as shell source.
    #[test]
    #[cfg(unix)]
    fn reconstructed_scalar_words_match_native_shell_argv_566() {
        for shell in ["/bin/sh", "/bin/bash"] {
            for ifs in ["", "@", DEFAULT_IFS] {
                for value in ["", "/tmp/work", "élève", "a b", "a@b", "literal*text"] {
                    for raw in [
                        "${S}/file",
                        r#""${S}"/file"#,
                        "${E}${E}",
                        "${E}''",
                        "${S}/a@b",
                    ] {
                        let mut state = State {
                            ifs: Some(ifs.into()),
                            ..State::default()
                        };
                        state.values.insert("S".into(), value.into());
                        state.values.insert("E".into(), String::new());
                        let Ok(expected) = expand(raw, &state) else {
                            continue; // no claim about unsupported field joins/globs
                        };
                        let script = format!(
                            "IFS=$DCG_TEST_IFS; S=$DCG_TEST_VALUE; E=; set -- {raw}; printf '%s\\0' \"$#\"; for arg; do printf '%s\\0' \"$arg\"; done"
                        );
                        let output = std::process::Command::new(shell)
                            .args(["-c", &script])
                            .env_clear()
                            .env("DCG_TEST_IFS", ifs)
                            .env("DCG_TEST_VALUE", value)
                            .output()
                            .expect("native scalar-word oracle");
                        assert!(output.status.success(), "{shell}: {output:?}");
                        let printed = String::from_utf8(output.stdout).unwrap();
                        let mut parts = printed.split_terminator('\0');
                        let count: usize = parts.next().unwrap().parse().unwrap();
                        let actual: Vec<_> = parts.collect();
                        assert_eq!(count, actual.len());
                        assert_eq!(
                            expected, actual,
                            "{shell}: IFS={ifs:?}, S={value:?}, word={raw}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn splitting_preserves_posix_whitespace_and_empty_field_rules() {
        for (value, ifs, expected) in [
            ("", "@", vec![]),
            ("a@b", "@", vec!["a", "b"]),
            ("@a@@b@", "@", vec!["", "a", "", "b"]),
            ("@@", "@", vec!["", ""]),
            (" a \t b\n", DEFAULT_IFS, vec!["a", "b"]),
            ("  @ a @ @ b @  ", " @", vec!["", "a", "", "b"]),
            ("a@b", "", vec!["a@b"]),
            ("a b@c d", "@", vec!["a b", "c d"]),
            ("α@β", "@", vec!["α", "β"]),
            ("/tmp/a@/etc/profile", "@", vec!["/tmp/a", "/etc/profile"]),
            ("a*b", "*", vec!["a", "b"]),
        ] {
            assert_eq!(fields(value, ifs), Ok(expected), "{value:?}, {ifs:?}");
        }
    }

    #[test]
    fn expansion_bounds_and_unresolved_pathname_expansion_fail_closed() {
        for (value, ifs) in [("*.txt", "@"), ("x", "é"), ("x\0y", "@")] {
            assert!(fields(value, ifs).is_err());
        }
        assert!(fields(&"x".repeat(MAX_VALUE_BYTES + 1), "@").is_err());
        assert!(fields(&"x@".repeat(MAX_FIELDS + 1), "@").is_err());
        assert_eq!(
            fields(&"x@".repeat(MAX_FIELDS), "@").unwrap().len(),
            MAX_FIELDS
        );
    }

    #[test]
    fn assignment_quotes_do_not_protect_later_unquoted_fields() {
        let mut state = State {
            ifs: Some(DEFAULT_IFS.to_owned()),
            ..State::default()
        };
        state.assign("S='/tmp/a@/etc/profile'", true);
        state.assign("IFS+=@", true);
        assert_eq!(expand("$S", &state).unwrap(), ["/tmp/a", "/etc/profile"]);
        assert_eq!(expand(r#""$S""#, &state).unwrap(), ["/tmp/a@/etc/profile"]);
        state.assign("IFS=", true);
        assert_eq!(expand("${S}", &state).unwrap(), ["/tmp/a@/etc/profile"]);
    }

    #[test]
    fn static_quote_removal_retains_pattern_provenance() {
        let state = State::default();
        for raw in [r#""/tmp/"*"#, r"/tmp/\a?", r"/tmp/{a,b}"] {
            assert!(expand(raw, &state).is_err(), "{raw}");
        }
        for raw in [r"'/tmp/*'", r"/tmp/\*", r#""/tmp/*""#] {
            assert_eq!(expand(raw, &state).unwrap(), ["/tmp/*"]);
        }
        for (raw, expected) in [
            (r#""$S""#, false),
            (r"\$S", false),
            (r"'$S'", false),
            (r#""prefix"${S}"#, true),
            (r#""$S"$T"#, true),
        ] {
            let source = format!("tee {raw}");
            let ast = AstGrep::try_new(source.as_str(), SupportLang::Bash).unwrap();
            assert_eq!(argv_needs_field_analysis(ast.root()), expected, "{raw}");
        }
    }

    /// The #558 vectors name a destination the shared native policy actually
    /// protects. They first used /etc/profile, which that table has never
    /// listed (00ffdb6 leaves every unlisted /etc file to the ordinary
    /// truncation rules), so a plain `tee /etc/profile` is allowed and those
    /// vectors could not show the split field reaching the policy.
    #[test]
    fn native_policy_sees_every_rebound_ifs_destination() {
        for source in [
            "S=/tmp/a@/etc/shadow; IFS=@; echo x | tee $S",
            "IFS=@; S=/tmp/a@/etc/shadow; tee $S",
            "S=/tmp/a@/etc/shadow IFS=@; tee $S",
            "IFS=@ S=/tmp/a@/etc/shadow; tee ${S}",
            "IFS=' '; S=/tmp/a@/etc/shadow; IFS+=@; tee $S",
            "S=/tmp/a@/etc/shadow; export IFS=@; tee $S",
            "export S=/tmp/a@/etc/shadow IFS=@; tee $S",
            "S=/etc/shadow@/tmp/a; IFS=@; tee $S",
            "S=/tmp/a@/tmp/b@/etc/shadow; IFS=@; tee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; command tee -- $S",
            "S=/tmp/a@/etc/shadow; IFS=@; /usr/bin/tee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; gtee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; tee -a $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter()
                    .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME),
                "{source}: {hits:?}"
            );
            assert!(
                hits.iter().any(|hit| hit.reason != UNCERTAIN),
                "must resolve literal fields: {source}"
            );
            assert!(
                hits.iter()
                    .all(|hit| source[hit.span.clone()].contains("tee"))
            );
        }
    }

    #[test]
    fn each_native_rule_family_survives_the_same_tee_invocation() {
        let source = "S=/tmp/a@/etc/shadow@.git/config; IFS=@; tee $S";
        let hits = scan(source, ShellDialect::Posix);
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME)
        );
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::GIT_INTERNALS_WRITE_NAME)
        );
    }

    #[test]
    fn quoted_scalars_read_idioms_and_safe_paths_remain_harmless() {
        for source in [
            "S=/tmp/scratch/a@/tmp/scratch/b; IFS=@; echo x | tee $S",
            // A protected split field, so each control is not vacuous.
            "S=/tmp/a@/etc/shadow; IFS=@; tee \"$S\"",
            "S=/tmp/a@/etc/shadow; IFS=@; tee \"${S}\"",
            "S=/tmp/a@/etc/shadow; IFS=; tee $S",
            "S=/tmp/a@/etc/shadow; IFS=@; tee '$S'",
            "S=/tmp/a@/etc/shadow; IFS=@; printf '%s' \"$S\"",
            "S=/tmp/a@/etc/shadow; IFS=@; echo 'tee $S'",
            "S=/tmp/a@/etc/shadow; IFS=@",
            "OIFS=$IFS",
            "while IFS= read -r l; do :; done < /etc/hostname",
            "IFS=, read a b <<< 'x,y'",
            "S=/tmp/safe; IFS=@; S=/tmp/a@/etc/shadow IFS=: tee $S",
            "IFS=@; S=/tmp/a@/tmp/b; tee $S; tee /tmp/other",
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn unknown_state_and_unsupported_expansions_require_native_review() {
        for source in [
            "S=/tmp/a@/etc/profile; IFS+=@; tee $S",
            "S=/tmp/a@/etc/profile IFS=@ tee $S",
            "S=/tmp/a@/etc/profile; IFS=$CUSTOM; tee $S",
            "IFS=@; tee $UNKNOWN",
            "S=/tmp/a@/etc/profile; IFS=@; tee prefix${S}",
            "S=/tmp/a@/etc/profile; IFS=@; tee $S \"/tmp/\"*",
            "S=/tmp/safe; IFS=@; S=/tmp/a@/etc/profile :; tee $S",
            "S=/tmp/safe; IFS=@; printf -v S /tmp/a@/etc/profile; tee $S",
            "f() { S=/tmp/a@/etc/profile; }; S=/tmp/safe; IFS=@; f; tee $S",
            "declare -n S=T; T=/tmp/a@/etc/profile; IFS=@; tee $S",
            "IFS=@; A=(/tmp/a /etc/profile); tee \"${A[@]}\"",
            "S=/tmp/a@/etc/profile; export I'F'S=@; tee $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| hit.reason == UNCERTAIN),
                "{source}: {hits:?}"
            );
        }
    }

    #[test]
    fn writer_arguments_are_not_limited_to_tee() {
        for source in [
            "S=/tmp/source@/etc/shadow; IFS=@; cp $S",
            "S=/tmp/source@/etc/shadow; IFS=@; mv $S",
            "S=if=/tmp/source@of=/etc/shadow; IFS=@; dd $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter()
                    .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME),
                "{source}: {hits:?}"
            );
        }
    }

    #[test]
    fn printf_assignment_options_follow_expansion_and_format_boundaries() {
        let mut state = State::default();
        state.assign("IFS=@", true);
        state.assign("F=-v", true);
        state.assign("A=-v@S", true);
        state.assign("E=", true);
        state.assign("FORMAT=%s", true);
        for (arguments, expected) in [
            (vec!["-v", "S", "%s", "value"], true),
            (vec!["'-v'", "S", "%s", "value"], true),
            (vec![r#""-v""#, "S", "%s", "value"], true),
            (vec!["-''v", "S", "%s", "value"], true),
            (vec![r"\-v", "S", "%s", "value"], true),
            (vec!["'-vS'", "%s", "value"], true),
            (vec!["$F", "S", "%s", "value"], true),
            (vec![r#""$F""#, "S", "%s", "value"], true),
            (vec!["$A", "%s", "value"], true),
            (vec!["$E", "'-v'", "S", "%s", "value"], true),
            (vec!["$UNKNOWN", "S", "%s", "value"], true),
            (vec![r#""$UNKNOWN""#, "S", "%s", "value"], true),
            (vec!["--", "-v", "S", "value"], false),
            (vec!["'%s'", "-v", "S", "value"], false),
            (vec![r#""$FORMAT""#, "-v", "S", "value"], false),
            (vec!["''", "-v", "S", "value"], false),
            (vec![r#""$E""#, "-v", "S", "value"], false),
            (vec!["$E"], false),
            (vec![], false),
        ] {
            let words: Vec<_> = std::iter::once("printf")
                .chain(arguments)
                .map(str::to_owned)
                .collect();
            assert_eq!(printf_may_assign(&words, &state), expected, "{words:?}");
        }
    }

    #[test]
    fn printf_count_conversions_preserve_format_ownership() {
        for format in [
            "%n", "abcde%n", "%5n", "%+05.2n", "%*.*n", "%hn", "%lln", "%zn", "%jn", "%tn", "%Ln",
            "%%%n", r"\%n", r"\\%n", "%(%n)T%n",
        ] {
            assert!(printf_format_may_assign(format), "{format}");
        }
        for format in [
            "",
            "%s",
            "%b",
            "%q",
            "n",
            "%%n",
            "%%%%n",
            "%dn",
            "%sn",
            "%s%%n",
            r"\045n",
            r"\x25n",
            "%(%n)T",
            "%(a(b)%n)T",
            "%10(%n)T",
            "%(%%n)T",
        ] {
            assert!(!printf_format_may_assign(format), "{format}");
        }
        for format in ["%(", "%(%n", "%(date)%n", "%I64n", "%Y"] {
            assert!(printf_format_may_assign(format), "{format}");
        }

        let mut state = State::default();
        state.assign("IFS=@", true);
        state.assign("F=abcde%n", true);
        state.assign("A=--@abcde%n@SEP", true);
        state.assign("E=", true);
        for arguments in [
            vec!["'abcde%n'", "SEP"],
            vec!["--", "'abcde%n'", "SEP"],
            vec![r#""$F""#, "SEP"],
            vec!["$A"],
            vec!["$E", "--", "'abcde%n'", "SEP"],
        ] {
            let words: Vec<_> = std::iter::once("printf")
                .chain(arguments)
                .map(str::to_owned)
                .collect();
            assert!(printf_may_assign(&words, &state), "{words:?}");
        }
    }

    #[test]
    fn printf_count_assignment_cannot_leave_stale_separator_facts() {
        for printing in [
            "printf 'abcde%n' SEP",
            "printf -- 'abcde%n' SEP",
            "printf 'abcde%05n' SEP",
            "printf 'abcde%*.*n' 0 0 SEP",
            "printf 'abcde%ln' SEP",
            "printf '%s%n' abcde SEP",
            r#"F=abcde%n; printf "$F" SEP"#,
            "F=--@abcde%n@SEP; printf $F",
            "E=; printf $E 'abcde%n' SEP",
            "p''rintf 'abcde%n' SEP",
        ] {
            let source =
                format!("SEP=@; IFS=@; S=/tmp/a5/etc/profile; {printing}; IFS=$SEP; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn printf_literal_count_text_does_not_forfeit_safe_separator_facts() {
        for printing in [
            "printf '%s' 'abcde%n' SEP",
            "printf '%b' 'abcde%n' SEP",
            "printf '%q' 'abcde%n' SEP",
            "printf '%%n' SEP",
            "printf '%dn' 5",
            r"printf '\045n' SEP",
            "printf '%(%n)T' 0",
            "printf '%(a(b)%n)T' 0",
            "printf -- -- 'abcde%n' SEP",
            r#"F=%%n; printf "$F" SEP"#,
            r#"E=; printf "$E" 'abcde%n' SEP"#,
        ] {
            // If SEP were wrongly taken to be 5, /etc/shadow would be split
            // out and denied: this negative control is not vacuous.
            let source =
                format!("SEP=@; IFS=@; S=/tmp/a5/etc/shadow; {printing}; IFS=$SEP; tee $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    /// Exercise this Rust predicate against Bash's real builtin, not a model
    /// translated into another language. The constant script only mutates
    /// its private COUNT variable; neither shell source nor paths are input.
    #[test]
    #[cfg(unix)]
    fn printf_count_detection_matches_bash_builtin() {
        for (format, arguments) in [
            ("%n", vec!["COUNT"]),
            ("abcde%n", vec!["COUNT"]),
            ("%5n", vec!["COUNT"]),
            ("%*n", vec!["5", "COUNT"]),
            ("%.*n", vec!["2", "COUNT"]),
            ("%ln", vec!["COUNT"]),
            ("%%%n", vec!["COUNT"]),
            (r"\%n", vec!["COUNT"]),
            ("%%n", vec!["COUNT"]),
            ("%s", vec!["%n"]),
            ("%b", vec!["%n"]),
            ("%q", vec!["%n"]),
            ("%dn", vec!["5"]),
            (r"\045n", vec!["COUNT"]),
            ("%(%n)T", vec!["0"]),
            ("%(a(b)%n)T", vec!["0"]),
        ] {
            let output = std::process::Command::new("/bin/bash")
                .args([
                    "--noprofile",
                    "--norc",
                    "-c",
                    "COUNT=untouched; printf -- \"$@\" >/dev/null; printf '%s' \"$COUNT\"",
                    "dcg-printf-count-probe",
                    format,
                ])
                .args(arguments)
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .expect("Bash builtin count probe");
            assert!(output.status.success(), "{format}: {output:?}");
            assert_eq!(
                printf_format_may_assign(format),
                output.stdout.as_slice() != b"untouched",
                "{format}: {output:?}"
            );
        }
    }

    #[test]
    fn decoded_assignment_builtins_cannot_leave_stale_writer_destinations() {
        for mutation in [
            "ex''port S=/tmp/a@/etc/profile",
            r#""export" S=/tmp/a@/etc/profile"#,
            r"\export S=/tmp/a@/etc/profile",
            r#"e'x'p"o"rt S=/tmp/a@/etc/profile"#,
            "printf '-v' S '%s' /tmp/a@/etc/profile",
            r#"printf "-v" S %s /tmp/a@/etc/profile"#,
            "printf -''v S %s /tmp/a@/etc/profile",
            r"printf \-v S %s /tmp/a@/etc/profile",
            "printf '-vS' %s /tmp/a@/etc/profile",
            "F=-v; printf $F S %s /tmp/a@/etc/profile",
            r#"F=-v; printf "$F" S %s /tmp/a@/etc/profile"#,
            "F=-v@S; printf $F %s /tmp/a@/etc/profile",
            "E=; printf $E '-v' S %s /tmp/a@/etc/profile",
            "printf $UNKNOWN S %s /tmp/a@/etc/profile",
            "ex''port IFS=:; S=/tmp/a:/etc/profile",
            "printf '-v' IFS %s :; S=/tmp/a:/etc/profile",
        ] {
            let source = format!("S=/tmp/safe; IFS=@; {mutation}; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn printf_data_arguments_do_not_invalidate_safe_destination_bindings() {
        for printing in [
            "printf '%s' '-v' S /tmp/a@/etc/shadow",
            "printf -- '-v' S /tmp/a@/etc/shadow",
            "printf '' '-v' S /tmp/a@/etc/shadow",
            r#"F=%s; printf "$F" '-v' S /tmp/a@/etc/shadow"#,
            r#"E=; printf "$E" -v S /tmp/a@/etc/shadow"#,
            "printf '%s' '$@' '-v' S /tmp/a@/etc/shadow",
        ] {
            let source = format!("S=/tmp/safe; IFS=@; {printing}; tee $S");
            assert!(scan(&source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn redirected_state_changes_cannot_replace_older_dangerous_bindings() {
        for mutation in [
            "S=/tmp/safe >/definitely/missing/parent/file",
            "export S=/tmp/safe >/definitely/missing/parent/file",
            "IFS=: >/definitely/missing/parent/file",
            "export IFS=: >/definitely/missing/parent/file",
        ] {
            let source = format!("S=/tmp/a@/etc/profile; IFS=@; {mutation}; tee $S");
            let hits = scan(&source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| hit.reason == UNCERTAIN),
                "{source}: {hits:?}"
            );
        }
    }

    #[test]
    fn candidate_gate_and_original_source_entry_point_do_not_lose_bindings() {
        let source = "S=/tmp/a@/etc/shadow; IFS=@; tee $S";
        let hits = super::super::classify_embedded_credential_file_writes(
            source,
            ShellDialect::Posix,
            |_, _| false,
        );
        assert!(
            hits.iter()
                .any(|hit| hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME)
        );
        assert!(super::super::may_name_protected_path("IFS=@; tee $UNKNOWN"));
        assert!(!candidate("tee /tmp/safe"));
        assert!(scan(source, ShellDialect::PowerShell).is_empty());
        assert!(scan(source, ShellDialect::Cmd).is_empty());
    }

    #[test]
    fn quoted_list_parameters_and_operators_are_not_scalar_proofs() {
        for raw in [
            "$@",
            "${@}",
            "${@:1}",
            "${@:1:2}",
            "${@#prefix}",
            "${@%suffix}",
            "${@/old/new}",
            "${@:-fallback}",
            "${@@Q}",
            "${A[@]:1}",
            "${!A[@]}",
            "${!prefix@}",
            "${!S}",
            "${!1}",
        ] {
            assert!(parameter_can_produce_multiple_fields(raw), "{raw}");
        }
        for raw in [
            "$S",
            "$*",
            "$!",
            "${S}",
            "${#@}",
            "${#A[@]}",
            "${A[*]}",
            "${!A[*]}",
            "${!prefix*}",
            "${!}",
            "${S@Q}",
        ] {
            assert!(!parameter_can_produce_multiple_fields(raw), "{raw}");
        }
    }

    #[test]
    fn argv_analysis_keeps_quote_and_execution_provenance() {
        for (raw, expected) in [
            (r#""${@:1}""#, true),
            (r#""${!S}""#, true),
            (r#""${S:+$@}""#, true),
            (r#""${S:-$@}""#, true),
            (r#""${S:+x$@}""#, true),
            (r#""${S:+'$@'}""#, true),
            (r#""${S:+'${A[@]}'}""#, true),
            (r#""${S:+'${!T}'}""#, true),
            (r#""${S:+'${@:1}'}""#, true),
            (r#""${S:-"$@"}""#, true),
            (r#""${S[@]:0:2}""#, true),
            (r#"é"${@:1}"ø"#, true),
            (r#"$(printf '%s' "$@")"#, true),
            (r#""$S"'${@:1}'"#, false),
            (r#""$S"'[@]'"#, false),
            (r#""\${@:1}""#, false),
            (r"'${@:1}'", false),
            (r"$'${@:1}'", false),
            (r#""${#@}""#, false),
            (r#""${S:+\$@}""#, false),
            (r#""${S:+/tmp/a}""#, false),
            (r#""${S:-'/tmp/a'}""#, false),
            (r#""${S:+${#A[@]}}""#, false),
            (r#""${#S[@]}""#, false),
            (r#""${S[*]}""#, false),
            (r#""${!S[*]}""#, false),
            (r#""$(printf '%s' "$@")""#, false),
            (r#""$((1 + ${#S[@]}))""#, false),
        ] {
            let source = format!("tee {raw}");
            let ast = AstGrep::try_new(source.as_str(), SupportLang::Bash).unwrap();
            assert!(!ast.root().get_inner_node().has_error(), "{raw}");
            assert_eq!(argv_needs_field_analysis(ast.root()), expected, "{raw}");
        }
    }

    #[test]
    fn quoted_list_destinations_require_native_review_without_custom_packs() {
        for source in [
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@:1}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@#/missing/}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${@%/missing}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; S=@; tee "${!S}""#,
            r#"IFS=@; A=(/tmp/a /etc/profile); S='A[@]'; tee "${!S}""#,
            r#"IFS=@; A=(/tmp/a /etc/profile); tee "${A[@]:0:2}""#,
            r#"set -- /tmp/a /etc/profile; IFS=@; tee "${S:-"$@"}""#,
            // #565: the parser hides these `$@` reads inside the operator.
            r#"set -- /tmp/a /etc/passwd; S=x; IFS=@; echo x | tee "${S:+$@}""#,
            r#"set -- /tmp/a /etc/passwd; IFS=@; echo x | tee "${S:-$@}""#,
            r#"set -- /tmp/a /etc/passwd x; S=x; IFS=@; tee "${S:+'$@'}""#,
        ] {
            let hits = scan(source, ShellDialect::Posix);
            for rule in [
                shell::CREDENTIAL_FILE_WRITE_NAME,
                shell::GIT_INTERNALS_WRITE_NAME,
            ] {
                assert!(
                    hits.iter()
                        .any(|hit| hit.rule == rule && hit.reason == UNCERTAIN),
                    "{source}: missing {rule}: {hits:?}"
                );
            }
        }
    }

    #[test]
    fn literal_list_text_and_quoted_scalar_results_do_not_trigger_ifs_refusal() {
        for source in [
            r#"IFS=@; S=ok; tee "$S"'[@]'"#,
            r#"IFS=@; S=ok; tee "$S"'${@:1}'"#,
            r#"IFS=@; tee "\${@:1}""#,
            r"IFS=@; tee '${@:1}'",
            r#"IFS=@; tee "${#@}""#,
            r#"IFS=@; tee "${#A[@]}""#,
            r#"IFS=@; tee "${A[*]}""#,
            r#"IFS=@; tee "$(printf '%s' "$@")""#,
            r#"IFS=@; S=x; tee "${S:+\$@}""#,
            r#"IFS=@; S=x; tee "${S:+/tmp/a}""#,
        ] {
            assert!(scan(source, ShellDialect::Posix).is_empty(), "{source}");
        }
    }

    #[test]
    fn later_tee_options_cannot_exempt_earlier_destinations() {
        for source in [
            "S=/tmp/a@/etc/shadow@--help; IFS=@; POSIXLY_CORRECT=1 tee $S",
            "S=/tmp/a@/etc/shadow@--version; IFS=@; env POSIXLY_CORRECT=1 tee $S",
            "S=/tmp/a@/etc/shadow@--help; IFS=@; tee $S",
            "S=/home/example/.ssh/known_hosts@-a; IFS=@; POSIXLY_CORRECT=1 tee $S",
            "S=/home/example/.ssh/known_hosts@--append; IFS=@; tee $S",
        ] {
            let hits = scan(source, ShellDialect::Posix);
            assert!(
                hits.iter().any(|hit| {
                    hit.rule == shell::CREDENTIAL_FILE_WRITE_NAME && hit.reason != UNCERTAIN
                }),
                "must check the concrete destination: {source}: {hits:?}"
            );
        }
        for argv in [
            vec!["tee", "--help", "/etc/shadow"],
            vec!["tee", "--version", "/etc/shadow"],
            vec!["tee", "-a", "/home/example/.ssh/known_hosts"],
            vec!["tee", "--append", "/home/example/.ssh/known_hosts"],
        ] {
            let argv: Vec<_> = argv.into_iter().map(str::to_owned).collect();
            assert!(classify(&argv, 0..0).unwrap().is_empty(), "{argv:?}");
        }
    }

    /// This checks the production Rust splitter against a real POSIX shell.
    /// The script is constant and only prints argv; values are passed as data
    /// in the child environment. No analyzed command or destination is run.
    #[test]
    #[cfg(unix)]
    fn field_splitting_matches_posix_shell_argv() {
        use std::process::Command;

        let values = [
            "",
            "a",
            "@",
            "@@",
            "@a",
            "a@",
            "a@@b@",
            " a ",
            " a b ",
            " a\tb\n",
            " @ a @ @ b @ ",
            "a,b:c",
            "α@β",
            "a'@'b",
            "/tmp/a@/etc/profile",
        ];
        for ifs in ["", DEFAULT_IFS, "@", " @", "@\t\n", ",:", "a", "/"] {
            for value in values {
                let output = Command::new("/bin/sh")
                    .args(["-c", "IFS=$DCG_TEST_IFS; set -- $DCG_TEST_VALUE; printf '%s\\0' \"$#\"; for arg; do printf '%s\\0' \"$arg\"; done"])
                    .env_clear()
                    .env("DCG_TEST_IFS", ifs)
                    .env("DCG_TEST_VALUE", value)
                    .output()
                    .expect("POSIX shell argv probe");
                assert!(output.status.success());
                let printed = String::from_utf8(output.stdout).expect("UTF-8 argv");
                let mut parts = printed.split_terminator('\0');
                let count: usize = parts.next().expect("argc").parse().expect("numeric argc");
                let actual: Vec<_> = parts.collect();
                assert_eq!(actual.len(), count);
                assert_eq!(
                    fields(value, ifs).unwrap(),
                    actual,
                    "IFS={ifs:?}, value={value:?}"
                );
            }
        }
    }
}

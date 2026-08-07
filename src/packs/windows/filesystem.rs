//! Windows core filesystem pack — the Windows analogue of `core.filesystem`.
//!
//! Blocks recursive/forced filesystem destruction in **cmd.exe** and
//! **PowerShell**, the single most valuable protection for a native-Windows
//! agent:
//!   - cmd: `del`/`erase` with `/s` (recursive), `rd`/`rmdir` with `/s`,
//!     `format <drive>:`.
//!   - PowerShell: `Remove-Item -Recurse` (with or without `-Force`) and its aliases
//!     (`rm`/`del`/`rd`/`rmdir`/`ri`/`erase`), `Clear-Content` (empties a file),
//!     `Clear-RecycleBin` (purges the Recycle Bin so deletes become unrecoverable),
//!     and the .NET filesystem APIs PowerShell can call with no external tool:
//!     `[System.IO.Directory]::Delete($path, $true)` (also the `[IO.Directory]`
//!     accelerator spelling) and `<DirectoryInfo>.Delete($true)`, both of which
//!     are the API equivalent of `Remove-Item -Recurse -Force`.
//!
//! Whitelist-first: PowerShell `-WhatIf` previews on cmdlets that actually honor
//! it are allowed. Recursive temp cleanup is intentionally reviewed: ambient
//! temp variables are caller-controlled, and a regex cannot prove that every
//! target in a multi-target delete remains inside one literal temp directory.
//!
//! Every pattern carries an inline `(?i)` flag (Windows is case-insensitive) and
//! a stable rule id (e.g. `windows.filesystem:del-recursive`). See
//! `super`-module docs for the keyword-casing convention.

use crate::normalize::{
    NormalizeToken, NormalizeTokenKind, ShellDialect, ShellTokenDecoder, ShellTokenRole,
    tokenize_for_shell_dialect,
};
use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};
use std::borrow::Cow;
use std::ops::Range;

const MAX_WINDOWS_FILESYSTEM_SEMANTIC_BYTES: usize = 64 * 1024;
const MAX_WINDOWS_FILESYSTEM_SEMANTIC_SEGMENTS: usize = 128;
const MAX_WINDOWS_FILESYSTEM_SEMANTIC_TOKENS: usize = 512;

pub(crate) const WINDOWS_FILESYSTEM_UNVERIFIED_RULE: &str =
    "windows-filesystem-semantic-unverified";
const WINDOWS_FILESYSTEM_UNVERIFIED_REASON: &str = "The Windows filesystem command contains unresolved shell syntax in an executable or destructive option position.";

/// Result of the bounded, caller-dialect-aware Windows filesystem pass.
///
/// `Unverified` is intentionally distinct from `NoMatch`: the former means a
/// protected executable or destructive option can be produced only after
/// runtime shell expansion, so the evaluator must fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsFilesystemSemanticDecision {
    NoMatch,
    Safe,
    Destructive(&'static str),
    Unverified,
}

#[derive(Debug, Default)]
struct PowerShellCallOperatorAnalysis {
    decision: Option<WindowsFilesystemSemanticDecision>,
    inert_target_spans: Vec<Range<usize>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsFilesystemWord {
    decoded: String,
    dynamic: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PossibleSwitch {
    exact: bool,
    possible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoveItemParameter {
    Recurse,
    Force,
    WhatIf,
    Value,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PowerShellSwitchValue {
    Enabled,
    Disabled,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PowerShellValueLookahead {
    Data,
    NamedParameter,
    Dynamic,
    EndOfParameters,
}

// PowerShell accepts an unambiguous leading substring of a parameter name.
// Keep the superset exposed by Remove-Item across the supported PowerShell
// editions/providers so a prefix is never treated as unique merely because a
// colliding dynamic parameter is absent on the host running dcg. In
// particular, `-R` uniquely identifies Recurse, but `-F` is ambiguous between
// Filter and Force (`-Fo` is the shortest unambiguous Force spelling).
const REMOVE_ITEM_PARAMETER_NAMES: &[&str] = &[
    "confirm",
    "credential",
    "debug",
    "erroraction",
    "errorvariable",
    "exclude",
    "filter",
    "force",
    "include",
    "informationaction",
    "informationvariable",
    "literalpath",
    "outbuffer",
    "outvariable",
    "path",
    "pipelinevariable",
    "progressaction",
    "recurse",
    "stream",
    "usetransaction",
    "verbose",
    "warningaction",
    "warningvariable",
    "whatif",
];

const REMOVE_ITEM_PARAMETER_ALIASES: &[(&str, RemoveItemParameter)] = &[
    ("cf", RemoveItemParameter::Other),
    ("db", RemoveItemParameter::Other),
    ("ea", RemoveItemParameter::Value),
    ("ev", RemoveItemParameter::Value),
    ("infa", RemoveItemParameter::Value),
    ("iv", RemoveItemParameter::Value),
    ("lp", RemoveItemParameter::Value),
    ("ob", RemoveItemParameter::Value),
    ("ov", RemoveItemParameter::Value),
    ("proga", RemoveItemParameter::Value),
    ("pspath", RemoveItemParameter::Value),
    ("pv", RemoveItemParameter::Value),
    ("vb", RemoveItemParameter::Other),
    ("wa", RemoveItemParameter::Value),
    ("wv", RemoveItemParameter::Value),
    ("wi", RemoveItemParameter::WhatIf),
];

const DEL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "del /s /q <dir> /p",
        "Add /p to confirm each file, or scope the path precisely before deleting",
    ),
    PatternSuggestion::new(
        "Move-Item <dir> $env:TEMP\\trash",
        "Move to a temp/trash location instead of an irreversible recursive delete",
    ),
];

const REMOVE_ITEM_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "Remove-Item -Recurse <path> -WhatIf",
        "Re-run with -WhatIf first to preview exactly what would be deleted",
    ),
    PatternSuggestion::new(
        "Move-Item <path> $env:TEMP\\trash",
        "Move to a temp/trash location instead of permanently deleting (Remove-Item bypasses the Recycle Bin)",
    ),
];

const DOTNET_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "Remove-Item -Recurse <path> -WhatIf",
        "Preview the deletion with the cmdlet equivalent before running anything irreversible",
    ),
    PatternSuggestion::new(
        "Move-Item <path> $env:TEMP\\trash",
        "Move the directory to a temp/trash location instead of deleting it (the .NET APIs bypass the Recycle Bin)",
    ),
];

const FORMAT_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-Volume",
    "List volumes and confirm the exact drive before any format — formatting is irreversible",
)];

const CLEAR_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "Get-Content <file>",
    "Read the file first; Clear-Content empties it in place with no undo",
)];

const CMD_PROTECTED_EXECUTABLES: &[&str] = &[
    "del",
    "del.exe",
    "erase",
    "erase.exe",
    "rd",
    "rd.exe",
    "rmdir",
    "rmdir.exe",
    "format",
    "format.com",
    "format.exe",
];

const POWERSHELL_PROTECTED_EXECUTABLES: &[&str] = &[
    "remove-item",
    "rmdir",
    "rd",
    "ri",
    "rm",
    "del",
    "erase",
    "clear-content",
    "clc",
    "clear-recyclebin",
];

/// `[System.IO.Directory]::Delete($path, $true)` (or the `[IO.Directory]`
/// accelerator spelling) with a literally-true second argument, anchored to the
/// start of a word token by the semantic caller. PowerShell type literals are
/// case-insensitive and tolerate whitespace around `[`, `]`, and `::`.
static DOTNET_DIRECTORY_DELETE_RECURSIVE_EXPRESSION: LazyCompiledRegex = LazyCompiledRegex::new(
    r#"(?i)^\[\s*(?:system\.)?io\.directory\s*\]\s*::\s*delete\s*\((?=[^|&\r\n]*?,\s*(?:\$true|1|"true"|'true')\s*\))"#,
);

/// Any `[System.IO.Directory]::Delete(...)` call, anchored to a word start.
/// Covers the single-argument form (removes an empty directory) and calls
/// whose second argument is dynamic — PowerShell coerces any truthy value
/// (including every non-empty string) to `$true`, so an unresolved flag must
/// still be reviewed.
static DOTNET_DIRECTORY_DELETE_EXPRESSION: LazyCompiledRegex =
    LazyCompiledRegex::new(r"(?i)^\[\s*(?:system\.)?io\.directory\s*\]\s*::\s*delete\s*\(");

/// `<DirectoryInfo>.Delete($true)` instance-method spelling, for example
/// `(Get-Item $path).Delete($true)` or a `[System.IO.DirectoryInfo]` variable.
/// `$true` is required so that unrelated `.delete(...)` member calls in inline
/// scripts of other languages do not match.
static DIRECTORYINFO_DELETE_RECURSIVE_MEMBER: LazyCompiledRegex =
    LazyCompiledRegex::new(r"(?i)\.\s*delete\s*\(\s*\$true\s*\)");

fn syntax_is_incomplete(raw: &str, dialect: ShellDialect) -> bool {
    let mut chars = raw.chars().peekable();
    let mut single = false;
    let mut double = false;
    while let Some(character) = chars.next() {
        match dialect {
            ShellDialect::PowerShell => match character {
                '`' if !single => {
                    if chars.next().is_none() {
                        return true;
                    }
                }
                '\'' if !double => {
                    if single && chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        single = !single;
                    }
                }
                '"' if !single => double = !double,
                _ => {}
            },
            ShellDialect::Cmd => match character {
                '^' if !double => {
                    if chars.next().is_none() {
                        return true;
                    }
                }
                '"' => double = !double,
                _ => {}
            },
            ShellDialect::Posix | ShellDialect::Unknown => return false,
        }
    }
    single || double
}

fn token_has_active_expansion(raw: &str, dialect: ShellDialect) -> bool {
    let mut chars = raw.chars().peekable();
    let mut single = false;
    let mut double = false;
    let mut at_word_start = true;
    while let Some(character) = chars.next() {
        match dialect {
            ShellDialect::PowerShell => match character {
                '`' if !single => {
                    chars.next();
                    at_word_start = false;
                }
                '\'' if !double => {
                    if single && chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        single = !single;
                    }
                }
                '"' if !single => double = !double,
                '$' if !single => return true,
                '@' if !single
                    && !double
                    && (at_word_start || matches!(chars.peek(), Some('(' | '{'))) =>
                {
                    return true;
                }
                _ => at_word_start = false,
            },
            ShellDialect::Cmd => match character {
                '^' if !double => {
                    chars.next();
                    at_word_start = false;
                }
                '"' => double = !double,
                // cmd.exe expands both percent variables and delayed `!VAR!`
                // variables inside double quotes. Quotes protect whitespace;
                // they do not make expansion inert.
                '%' | '!' => return true,
                _ => at_word_start = false,
            },
            ShellDialect::Posix | ShellDialect::Unknown => return false,
        }
    }
    false
}

fn decode_syntax_word(
    decoder: &mut ShellTokenDecoder,
    raw: &str,
    dialect: ShellDialect,
) -> Option<WindowsFilesystemWord> {
    let dynamic = token_has_active_expansion(raw, dialect) || syntax_is_incomplete(raw, dialect);
    decoder
        .decode(raw, ShellTokenRole::Syntax)
        .map(|decoded| WindowsFilesystemWord {
            decoded: decoded.into_owned(),
            dynamic,
        })
}

fn dynamic_fragments(decoded: &str, dialect: ShellDialect) -> Vec<String> {
    let mut fragments = vec![String::new()];
    let characters: Vec<char> = decoded.chars().collect();
    let mut index = 0usize;
    let mut saw_dynamic = false;
    while index < characters.len() {
        let starts_dynamic = match dialect {
            ShellDialect::PowerShell => matches!(characters[index], '$' | '@' | '`'),
            ShellDialect::Cmd => matches!(characters[index], '%' | '!' | '^'),
            ShellDialect::Posix | ShellDialect::Unknown => false,
        };
        if !starts_dynamic {
            let Some(fragment) = fragments.last_mut() else {
                // Conservatively represent an unconstrained dynamic word if a
                // future refactor ever violates the seeded-fragment invariant.
                return vec![String::new()];
            };
            fragment.push(characters[index]);
            index += 1;
            continue;
        }

        saw_dynamic = true;
        fragments.push(String::new());
        match (dialect, characters[index]) {
            (ShellDialect::PowerShell, '$') => {
                index += 1;
                if matches!(characters.get(index), Some('{' | '(')) {
                    let opener = characters[index];
                    let closer = if opener == '{' { '}' } else { ')' };
                    index += 1;
                    let mut depth = 1usize;
                    while index < characters.len() && depth > 0 {
                        if characters[index] == opener {
                            depth += 1;
                        } else if characters[index] == closer {
                            depth -= 1;
                        }
                        index += 1;
                    }
                } else {
                    while index < characters.len()
                        && (characters[index].is_ascii_alphanumeric()
                            || matches!(characters[index], '_' | ':' | '?' | '*' | '#'))
                    {
                        index += 1;
                    }
                }
            }
            (ShellDialect::PowerShell, '@') => {
                index += 1;
                while index < characters.len()
                    && (characters[index].is_ascii_alphanumeric()
                        || matches!(characters[index], '_' | ':'))
                {
                    index += 1;
                }
            }
            (ShellDialect::Cmd, delimiter @ ('%' | '!')) => {
                index += 1;
                if delimiter == '%' && characters.get(index).is_some_and(char::is_ascii_digit) {
                    index += 1;
                } else {
                    while index < characters.len() && characters[index] != delimiter {
                        index += 1;
                    }
                    index += usize::from(index < characters.len());
                }
            }
            (ShellDialect::PowerShell, '`') | (ShellDialect::Cmd, '^') => {
                index += 1;
                index += usize::from(index < characters.len());
            }
            _ => index += 1,
        }
    }
    if saw_dynamic {
        fragments
    } else {
        vec![decoded.to_string()]
    }
}

fn symbolic_word_may_equal(
    word: &WindowsFilesystemWord,
    dialect: ShellDialect,
    candidate: &str,
) -> bool {
    if !word.dynamic {
        return word.decoded.eq_ignore_ascii_case(candidate);
    }
    let decoded = word.decoded.to_ascii_lowercase();
    let candidate = candidate.to_ascii_lowercase();
    let fragments = dynamic_fragments(&decoded, dialect);
    let Some(first) = fragments.first() else {
        return true;
    };
    let Some(last) = fragments.last() else {
        return true;
    };
    if !candidate.starts_with(first) || !candidate.ends_with(last) {
        return false;
    }
    let mut offset = first.len();
    for fragment in fragments
        .iter()
        .take(fragments.len().saturating_sub(1))
        .skip(1)
    {
        let Some(relative) = candidate.get(offset..).and_then(|tail| tail.find(fragment)) else {
            return false;
        };
        offset += relative + fragment.len();
    }
    offset <= candidate.len().saturating_sub(last.len())
}

fn executable_word(word: WindowsFilesystemWord, dialect: ShellDialect) -> WindowsFilesystemWord {
    let decoded = if dialect == ShellDialect::Cmd {
        word.decoded.trim_start_matches('@')
    } else {
        word.decoded.as_str()
    };
    let basename = decoded.rsplit(['/', '\\']).next().unwrap_or(decoded);
    WindowsFilesystemWord {
        decoded: basename.to_string(),
        dynamic: word.dynamic,
    }
}

fn possible_switch(
    word: &WindowsFilesystemWord,
    dialect: ShellDialect,
    candidates: &[&str],
) -> PossibleSwitch {
    if !word.dynamic
        && candidates
            .iter()
            .any(|candidate| word.decoded.eq_ignore_ascii_case(candidate))
    {
        return PossibleSwitch {
            exact: true,
            possible: true,
        };
    }
    PossibleSwitch {
        exact: false,
        possible: word.dynamic
            && candidates
                .iter()
                .any(|candidate| symbolic_word_may_equal(word, dialect, candidate)),
    }
}

fn remove_item_parameter_kind(name: &str) -> RemoveItemParameter {
    match name {
        "recurse" => RemoveItemParameter::Recurse,
        "force" => RemoveItemParameter::Force,
        "whatif" => RemoveItemParameter::WhatIf,
        "credential"
        | "erroraction"
        | "errorvariable"
        | "exclude"
        | "filter"
        | "include"
        | "informationaction"
        | "informationvariable"
        | "literalpath"
        | "outbuffer"
        | "outvariable"
        | "path"
        | "pipelinevariable"
        | "progressaction"
        | "stream"
        | "warningaction"
        | "warningvariable" => RemoveItemParameter::Value,
        _ => RemoveItemParameter::Other,
    }
}

fn resolve_remove_item_parameter(name: &str) -> Option<RemoveItemParameter> {
    let name = name.to_ascii_lowercase();
    if name.is_empty() {
        return None;
    }
    if let Some((_, parameter)) = REMOVE_ITEM_PARAMETER_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
    {
        return Some(*parameter);
    }
    if REMOVE_ITEM_PARAMETER_NAMES.contains(&name.as_str()) {
        return Some(remove_item_parameter_kind(&name));
    }

    let mut matches = REMOVE_ITEM_PARAMETER_NAMES
        .iter()
        .copied()
        .filter(|candidate| candidate.starts_with(&name));
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(remove_item_parameter_kind(first))
}

fn remove_item_parameter_name_is_recognized_or_ambiguous(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !name.is_empty()
        && (REMOVE_ITEM_PARAMETER_ALIASES
            .iter()
            .any(|(alias, _)| *alias == name)
            || REMOVE_ITEM_PARAMETER_NAMES
                .iter()
                .any(|candidate| candidate.starts_with(&name)))
}

fn dynamic_parameter_may_resolve_to(
    word: &WindowsFilesystemWord,
    target: RemoveItemParameter,
) -> bool {
    for full_name in REMOVE_ITEM_PARAMETER_NAMES.iter().copied() {
        if remove_item_parameter_kind(full_name) != target {
            continue;
        }
        for prefix_len in 1..=full_name.len() {
            let Some(prefix) = full_name.get(..prefix_len) else {
                continue;
            };
            if resolve_remove_item_parameter(prefix) != Some(target) {
                continue;
            }
            let candidate = format!("-{prefix}");
            if symbolic_word_may_equal(word, ShellDialect::PowerShell, &candidate) {
                return true;
            }
        }
    }
    REMOVE_ITEM_PARAMETER_ALIASES
        .iter()
        .filter(|(_, parameter)| *parameter == target)
        .any(|(alias, _)| {
            symbolic_word_may_equal(word, ShellDialect::PowerShell, &format!("-{alias}"))
        })
}

fn powershell_parameter_colon(raw: &str) -> Option<usize> {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, character) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '`' && !single {
            escaped = true;
            continue;
        }
        if character == '\'' && !double {
            single = !single;
            continue;
        }
        if character == '"' && !single {
            double = !double;
            continue;
        }
        if character == ':' && !single && !double {
            return Some(index);
        }
    }
    None
}

/// Return the UTF-8 width of a character PowerShell accepts as the leading
/// dash of a parameter token.
///
/// PowerShell deliberately treats the typographic en dash, em dash, and
/// horizontal bar exactly like ASCII hyphen-minus during parameter binding.
/// Other visually similar characters (notably U+2212 MINUS SIGN) remain
/// ordinary argument data and must not be canonicalized.
fn powershell_parameter_dash_width(raw: &str) -> Option<usize> {
    raw.chars()
        .next()
        .filter(|character| matches!(character, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}'))
        .map(char::len_utf8)
}

fn canonicalize_powershell_parameter_dash(word: &mut WindowsFilesystemWord) -> bool {
    let Some(width) = powershell_parameter_dash_width(&word.decoded) else {
        return false;
    };
    if width != 1 {
        word.decoded.replace_range(..width, "-");
    }
    true
}

fn powershell_value_lookahead(raw: &str) -> PowerShellValueLookahead {
    if powershell_wholly_quoted(raw) || powershell_parameter_dash_width(raw).is_none() {
        return PowerShellValueLookahead::Data;
    }
    let mut decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
    let Some(mut parameter) = decode_syntax_word(&mut decoder, raw, ShellDialect::PowerShell)
    else {
        return PowerShellValueLookahead::Dynamic;
    };
    if parameter.dynamic {
        return PowerShellValueLookahead::Dynamic;
    }
    if !canonicalize_powershell_parameter_dash(&mut parameter) {
        return PowerShellValueLookahead::Data;
    }
    if parameter.decoded == "--" {
        return PowerShellValueLookahead::EndOfParameters;
    }
    parameter
        .decoded
        .strip_prefix('-')
        .filter(|name| remove_item_parameter_name_is_recognized_or_ambiguous(name))
        .map_or(PowerShellValueLookahead::Data, |_| {
            PowerShellValueLookahead::NamedParameter
        })
}

fn powershell_switch_value(raw: Option<&str>) -> PowerShellSwitchValue {
    let Some(raw) = raw else {
        return PowerShellSwitchValue::Unresolved;
    };
    if raw.eq_ignore_ascii_case("$true") {
        PowerShellSwitchValue::Enabled
    } else if raw.eq_ignore_ascii_case("$false") || raw.eq_ignore_ascii_case("$null") {
        PowerShellSwitchValue::Disabled
    } else {
        // Expressions, ordinary variables, quoted strings, and malformed
        // values are runtime-dependent (or binding errors). None may justify
        // an allow decision for a destructive switch.
        PowerShellSwitchValue::Unresolved
    }
}

fn record_powershell_switch(
    switch: &mut PossibleSwitch,
    value: PowerShellSwitchValue,
    exact_parameter: bool,
) -> bool {
    match value {
        PowerShellSwitchValue::Enabled => {
            switch.exact |= exact_parameter;
            switch.possible = true;
            !exact_parameter
        }
        PowerShellSwitchValue::Disabled => false,
        PowerShellSwitchValue::Unresolved => {
            switch.possible = true;
            true
        }
    }
}

fn cmd_drive_target(decoded: &str) -> bool {
    let bytes = decoded.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || matches!(bytes[2], b'\\' | b'/'))
}

fn cmd_segment_semantic_decision(segment: &str) -> WindowsFilesystemSemanticDecision {
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::Cmd);
    let word_count = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .count();
    if word_count == 0 {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }

    let mut raw_words = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .filter_map(|token| token.text(segment));
    let Some(mut raw_executable) = raw_words.next() else {
        return WindowsFilesystemSemanticDecision::NoMatch;
    };
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Cmd);
    let Some(mut executable) = decode_syntax_word(&mut decoder, raw_executable, ShellDialect::Cmd)
    else {
        return WindowsFilesystemSemanticDecision::Unverified;
    };
    executable = executable_word(executable, ShellDialect::Cmd);
    if !executable.dynamic && executable.decoded.eq_ignore_ascii_case("call") {
        let Some(next) = raw_words.next() else {
            return WindowsFilesystemSemanticDecision::NoMatch;
        };
        raw_executable = next;
        let Some(decoded) = decode_syntax_word(&mut decoder, raw_executable, ShellDialect::Cmd)
        else {
            return WindowsFilesystemSemanticDecision::Unverified;
        };
        executable = executable_word(decoded, ShellDialect::Cmd);
    }

    let might_be_protected = CMD_PROTECTED_EXECUTABLES
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::Cmd, candidate));
    if !might_be_protected {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    if word_count > MAX_WINDOWS_FILESYSTEM_SEMANTIC_TOKENS {
        return WindowsFilesystemSemanticDecision::Unverified;
    }

    let exact_del = !executable.dynamic
        && matches!(
            executable.decoded.to_ascii_lowercase().as_str(),
            "del" | "del.exe" | "erase" | "erase.exe"
        );
    let exact_rd = !executable.dynamic
        && matches!(
            executable.decoded.to_ascii_lowercase().as_str(),
            "rd" | "rd.exe" | "rmdir" | "rmdir.exe"
        );
    let exact_format = !executable.dynamic
        && matches!(
            executable.decoded.to_ascii_lowercase().as_str(),
            "format" | "format.com" | "format.exe"
        );

    let mut recursive = PossibleSwitch::default();
    let mut help = false;
    let mut drive_target = PossibleSwitch::default();
    let mut literal_temp_targets = 0usize;
    let mut non_temp_target = false;
    for raw in raw_words {
        let Some(decoded) = decode_syntax_word(&mut decoder, raw, ShellDialect::Cmd) else {
            return WindowsFilesystemSemanticDecision::Unverified;
        };
        if decoded.decoded.starts_with('/') || decoded.dynamic {
            let candidate = possible_switch(&decoded, ShellDialect::Cmd, &["/s"]);
            recursive.exact |= candidate.exact;
            recursive.possible |= candidate.possible;
            help |= !decoded.dynamic && decoded.decoded == "/?";
            // A runtime-expanded non-option word can become a drive designator
            // (for example `%DRIVE%:`).  It is not safe to treat every dynamic
            // word as an option merely because it could also expand to `/s`.
            if decoded.dynamic && !decoded.decoded.starts_with('/') {
                drive_target.possible = true;
            }
            // A runtime expansion can also resolve to a target outside the
            // temp tree, so it disqualifies the literal-temp carve-out.
            non_temp_target |= decoded.dynamic;
        } else {
            // Deterministic Cmd quoting/carets are shell syntax even for a
            // target.  Decode them before recognizing a quoted drive such as
            // `"C:"`, while never reinterpreting runtime expansions as exact.
            drive_target.exact |= cmd_drive_target(&decoded.decoded);
            drive_target.possible |= drive_target.exact;
            if crate::packs::core::filesystem::windows_literal_user_temp_subpath(&decoded.decoded) {
                literal_temp_targets += 1;
            } else {
                non_temp_target = true;
            }
        }
    }

    if help && !recursive.possible {
        return WindowsFilesystemSemanticDecision::Safe;
    }
    // #285: recursive deletes whose every target is a literal per-user temp
    // subpath (`C:\Users\<user>\AppData\Local\Temp\<subpath>`) get the same
    // carve-out as `rm -rf /tmp/<subpath>`. `%TEMP%`-style dynamic roots and
    // the machine-wide `C:\Windows\Temp` remain reviewed.
    if (exact_del || exact_rd) && recursive.exact && literal_temp_targets > 0 && !non_temp_target {
        return WindowsFilesystemSemanticDecision::Safe;
    }
    if exact_del && recursive.exact {
        return WindowsFilesystemSemanticDecision::Destructive("del-recursive");
    }
    if exact_rd && recursive.exact {
        return WindowsFilesystemSemanticDecision::Destructive("rd-recursive");
    }
    if exact_format && drive_target.exact {
        return WindowsFilesystemSemanticDecision::Destructive("format-drive");
    }

    let possible_del = ["del", "del.exe", "erase", "erase.exe"]
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::Cmd, candidate));
    let possible_rd = ["rd", "rd.exe", "rmdir", "rmdir.exe"]
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::Cmd, candidate));
    let possible_format = ["format", "format.com", "format.exe"]
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::Cmd, candidate));
    if executable.dynamic && (possible_del || possible_rd) && recursive.possible
        || (exact_del || exact_rd) && recursive.possible && !recursive.exact
        || possible_format && drive_target.possible && (executable.dynamic || !drive_target.exact)
    {
        return WindowsFilesystemSemanticDecision::Unverified;
    }
    WindowsFilesystemSemanticDecision::NoMatch
}

fn powershell_wholly_quoted(raw: &str) -> bool {
    matches!(raw.as_bytes().first(), Some(b'\'' | b'"'))
}

/// Return whether a raw PowerShell target word is provably one literal
/// per-user Windows temp subpath (#285).
///
/// Single quotes are fully literal in PowerShell; double-quoted and bare
/// spellings stay literal only without expansion syntax (`$`, backtick). The
/// path-shape policy itself lives in
/// [`crate::packs::core::filesystem::windows_literal_user_temp_subpath`].
fn powershell_literal_target_is_user_temp(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let literal = if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        Some(&raw[1..raw.len() - 1])
    } else if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        let inner = &raw[1..raw.len() - 1];
        (!inner.contains(['$', '`', '"'])).then_some(inner)
    } else {
        (!raw.contains(['$', '`', '\'', '"'])).then_some(raw)
    };
    literal.is_some_and(crate::packs::core::filesystem::windows_literal_user_temp_subpath)
}

/// Return whether a statically resolved Remove-Item value parameter names
/// deletion targets (`-Path`/`-LiteralPath`, including the `lp`/`PSPath`
/// aliases). The caller has already proven the spelling unambiguous via
/// [`resolve_remove_item_parameter`].
fn remove_item_value_parameter_binds_path(decoded: &str) -> bool {
    decoded.strip_prefix('-').is_some_and(|name| {
        let name = name.to_ascii_lowercase();
        !name.is_empty()
            && (matches!(name.as_str(), "lp" | "pspath")
                || "path".starts_with(name.as_str())
                || "literalpath".starts_with(name.as_str()))
    })
}

/// Return whether a raw PowerShell word is exactly one variable expression.
///
/// A bare variable at the start of a statement is a value expression, not an
/// executable. PowerShell requires the call operator (`& $command`) to invoke
/// the string stored in a variable; that executable role is handled by the
/// dedicated call-operator analysis.
fn powershell_bare_variable_expression(raw: &str) -> bool {
    let Some(rest) = raw.strip_prefix('$') else {
        return false;
    };
    if let Some(braced) = rest.strip_prefix('{') {
        return braced
            .strip_suffix('}')
            .is_some_and(|name| !name.is_empty() && !name.chars().any(char::is_control));
    }
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'?'))
}

fn powershell_here_string_end(command: &str, start: usize) -> Option<usize> {
    let bytes = command.as_bytes();
    if bytes.get(start) != Some(&b'@') {
        return None;
    }
    let quote = *bytes.get(start + 1)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }

    let mut header_end = start + 2;
    let content_start = loop {
        let character = command.get(header_end..)?.chars().next()?;
        match character {
            '\r' if bytes.get(header_end + 1) == Some(&b'\n') => break header_end + 2,
            '\r' | '\n' => break header_end + 1,
            horizontal if horizontal.is_whitespace() => header_end += horizontal.len_utf8(),
            _ => return None,
        }
    };

    let mut line_start = content_start;
    while line_start < bytes.len() {
        if bytes.get(line_start) == Some(&quote) && bytes.get(line_start + 1) == Some(&b'@') {
            return Some(line_start + 2);
        }
        let mut newline = line_start;
        while newline < bytes.len() && !matches!(bytes[newline], b'\r' | b'\n') {
            newline += 1;
        }
        if newline == bytes.len() {
            return None;
        }
        line_start = if bytes.get(newline..newline + 2) == Some(b"\r\n") {
            newline + 2
        } else {
            newline + 1
        };
    }
    None
}

/// Mask PowerShell comments and complete here-strings while preserving byte
/// offsets, newlines, and executable syntax outside those inert regions.
///
/// The raw PowerShell tokenizer keeps a here-string together as one word, but
/// its contents are still visible to semantic keyword checks. That is useful
/// when the string is later executed by `Invoke-Expression` (handled by the
/// evaluator's nested-code analysis), but this direct filesystem pass must not
/// treat an example inside an assignment as an immediate delete.
fn mask_powershell_comments_and_here_strings(command: &str) -> Cow<'_, str> {
    let classified = crate::context::classify_command(command);
    let inert_context_ranges: Vec<Range<usize>> = classified
        .spans()
        .iter()
        .filter(|span| {
            matches!(
                span.kind,
                crate::context::SpanKind::Argument
                    | crate::context::SpanKind::Data
                    | crate::context::SpanKind::Comment
            )
        })
        .map(|span| span.byte_range.clone())
        .collect();
    let mask_ranges: Vec<Range<usize>> = classified
        .spans()
        .iter()
        .filter(|span| span.kind == crate::context::SpanKind::Comment)
        .map(|span| span.byte_range.clone())
        .collect();
    let mut here_string_ranges = Vec::<Range<usize>>::new();

    let bytes = command.as_bytes();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'@'
            && matches!(bytes[index + 1], b'\'' | b'"')
            && !inert_context_ranges
                .iter()
                .any(|range| range.contains(&index))
            && let Some(end) = powershell_here_string_end(command, index)
        {
            here_string_ranges.push(index..end);
            index = end;
        } else {
            index += 1;
        }
    }

    if mask_ranges.is_empty() && here_string_ranges.is_empty() {
        return Cow::Borrowed(command);
    }
    let mut masked = command.as_bytes().to_vec();
    for range in mask_ranges {
        for byte in &mut masked[range] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    for range in here_string_ranges {
        for byte in &mut masked[range.clone()] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
        // Keep the replacement syntactically valid. Leaving only whitespace
        // after `$value =` makes the semantic parser correctly fail closed on
        // an incomplete assignment; a multiline single-quoted empty value
        // preserves the inert expression role without changing byte offsets.
        masked[range.start] = b'\'';
        masked[range.end - 1] = b'\'';
    }
    Cow::Owned(String::from_utf8(masked).expect("masking ASCII bytes preserves UTF-8"))
}

/// Detect a .NET directory-delete expression in an executable position within
/// one PowerShell segment.
///
/// `[System.IO.Directory]::Delete($path, $true)` and
/// `<DirectoryInfo>.Delete($true)` execute without any external tool, so the
/// cmdlet-oriented executable analysis above never sees them. The scan starts
/// only at word tokens that are not wholly quoted: a quoted string in an
/// ordinary statement is data, not an invocation (evaluating it requires a
/// call operator or `Invoke-Expression`, which are analyzed elsewhere). For
/// the member-call spelling, a match inside a wholly quoted word is likewise
/// ignored.
fn powershell_dotnet_directory_delete_rule(
    segment: &str,
    tokens: &[NormalizeToken],
) -> Option<&'static str> {
    // The intact-command caller uses this detector before PowerShell's
    // structural parentheses are split. Preserve that benefit without
    // reinterpreting examples inside comments, quoted arguments, or
    // here-strings as executable .NET calls.
    let inert_ranges: Vec<Range<usize>> = crate::context::classify_command(segment)
        .spans()
        .iter()
        .filter(|span| {
            matches!(
                span.kind,
                crate::context::SpanKind::Argument
                    | crate::context::SpanKind::Data
                    | crate::context::SpanKind::Comment
            )
        })
        .map(|span| span.byte_range.clone())
        .collect();
    let quoted_word_ranges: Vec<Range<usize>> = tokens
        .iter()
        .filter(|token| {
            token.kind == NormalizeTokenKind::Word
                && token.text(segment).is_some_and(powershell_wholly_quoted)
        })
        .map(|token| token.byte_range.clone())
        .collect();
    for token in tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
    {
        let Some(raw) = token.text(segment) else {
            continue;
        };
        if powershell_wholly_quoted(raw) {
            continue;
        }
        let Some(tail) = segment.get(token.byte_range.start..) else {
            continue;
        };
        if let Some((match_start, _)) = DOTNET_DIRECTORY_DELETE_RECURSIVE_EXPRESSION.find(tail) {
            let absolute = token.byte_range.start.saturating_add(match_start);
            if !inert_ranges.iter().any(|range| range.contains(&absolute)) {
                return Some("dotnet-directory-delete-recursive");
            }
        }
        if let Some((match_start, _)) = DOTNET_DIRECTORY_DELETE_EXPRESSION.find(tail) {
            let absolute = token.byte_range.start.saturating_add(match_start);
            if !inert_ranges.iter().any(|range| range.contains(&absolute)) {
                return Some("dotnet-directory-delete");
            }
        }
        if let Some((match_start, _)) = DIRECTORYINFO_DELETE_RECURSIVE_MEMBER.find(tail) {
            let absolute = token.byte_range.start.saturating_add(match_start);
            if !quoted_word_ranges
                .iter()
                .any(|range| range.contains(&absolute))
                && !inert_ranges.iter().any(|range| range.contains(&absolute))
            {
                return Some("directoryinfo-delete-recursive");
            }
        }
    }
    None
}

fn powershell_segment_semantic_decision(
    segment: &str,
    quoted_executable_is_command: bool,
) -> WindowsFilesystemSemanticDecision {
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::PowerShell);
    let word_count = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .count();
    if word_count == 0 {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    // .NET filesystem-delete expressions execute without any protected
    // executable, so they are detected before (and independently of) the
    // cmdlet-oriented analysis below.
    if let Some(rule) = powershell_dotnet_directory_delete_rule(segment, &tokens) {
        return WindowsFilesystemSemanticDecision::Destructive(rule);
    }
    let raw_words: Vec<_> = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .filter_map(|token| token.text(segment))
        .collect();
    let Some(raw_executable) = raw_words.first().copied() else {
        return WindowsFilesystemSemanticDecision::NoMatch;
    };
    // A quoted string at the start of an ordinary PowerShell statement is
    // data, not a command invocation. The call-operator pre-pass below sets
    // `quoted_executable_is_command` only when a statement-leading `&` proves
    // that the string occupies an executable role.
    if !quoted_executable_is_command && powershell_wholly_quoted(raw_executable) {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    if !quoted_executable_is_command && powershell_bare_variable_expression(raw_executable) {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    let mut decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
    let Some(decoded) = decode_syntax_word(&mut decoder, raw_executable, ShellDialect::PowerShell)
    else {
        return WindowsFilesystemSemanticDecision::Unverified;
    };
    let executable = executable_word(decoded, ShellDialect::PowerShell);
    if !POWERSHELL_PROTECTED_EXECUTABLES
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::PowerShell, candidate))
    {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    if word_count > MAX_WINDOWS_FILESYSTEM_SEMANTIC_TOKENS {
        return WindowsFilesystemSemanticDecision::Unverified;
    }

    let exact_name = (!executable.dynamic).then(|| executable.decoded.to_ascii_lowercase());
    let is_remove_item = exact_name.as_deref().is_some_and(|name| {
        matches!(
            name,
            "remove-item" | "rmdir" | "rd" | "ri" | "rm" | "del" | "erase"
        )
    });
    let is_clear_content = exact_name
        .as_deref()
        .is_some_and(|name| matches!(name, "clear-content" | "clc"));
    let is_clear_recycle_bin = exact_name.as_deref() == Some("clear-recyclebin");
    // cmd.exe deletion words typed at a PowerShell prompt (#280). PowerShell
    // resolves them to Remove-Item aliases, where `/s` is a literal path
    // argument, so the classification below keys on the cmd-style `/s` switch
    // separately from genuine Remove-Item parameter binding.
    let cmd_style_rule = exact_name.as_deref().and_then(|name| match name {
        "rd" | "rmdir" => Some("rd-recursive"),
        "del" | "erase" => Some("del-recursive"),
        _ => None,
    });
    let mut cmd_style_recursive = false;

    let mut recurse = PossibleSwitch::default();
    let mut force = PossibleSwitch::default();
    let mut what_if = PossibleSwitch::default();
    let mut unresolved_remove_binding = false;
    let mut invalid_static_remove_parameter = false;
    let mut splatted_options = false;
    let mut stop_parsing = false;
    let mut literal_temp_targets = 0usize;
    let mut non_temp_target = false;
    let mut index = 1usize;
    while index < raw_words.len() {
        let raw = raw_words[index];
        index += 1;
        if stop_parsing {
            // Words past `--%` or a failed decode are unproven; they may name
            // targets outside the temp tree.
            non_temp_target = true;
            continue;
        }
        let syntax_role = powershell_parameter_dash_width(raw).is_some()
            || raw.starts_with('@')
            || matches!(raw, "--%" | "'--%'" | "\"--%\"");
        if !syntax_role {
            if cmd_style_rule.is_some()
                && (raw.eq_ignore_ascii_case("/s") || raw.eq_ignore_ascii_case("/q"))
            {
                // A bare cmd-style switch, not a deletion target (#280).
                cmd_style_recursive |= raw.eq_ignore_ascii_case("/s");
                continue;
            }
            // Positional word: a deletion target. Track whether every proven
            // target stays inside a literal per-user temp subtree (#285).
            if powershell_literal_target_is_user_temp(raw) {
                literal_temp_targets += 1;
            } else {
                non_temp_target = true;
            }
            continue;
        }

        if raw.starts_with('@') {
            let Some(decoded) = decode_syntax_word(&mut decoder, raw, ShellDialect::PowerShell)
            else {
                stop_parsing = true;
                continue;
            };
            if decoded.dynamic {
                splatted_options = true;
            }
            continue;
        }

        let colon = powershell_parameter_colon(raw);
        let (raw_parameter, raw_value) = if let Some(colon) = colon {
            let parameter = raw.get(..colon).unwrap_or(raw);
            let attached = raw.get(colon.saturating_add(1)..).unwrap_or_default();
            if attached.is_empty() {
                let value = raw_words.get(index).copied();
                index += usize::from(value.is_some());
                (parameter, value)
            } else {
                (parameter, Some(attached))
            }
        } else {
            (raw, None)
        };
        let Some(mut parameter) =
            decode_syntax_word(&mut decoder, raw_parameter, ShellDialect::PowerShell)
        else {
            stop_parsing = true;
            continue;
        };
        if !canonicalize_powershell_parameter_dash(&mut parameter) {
            continue;
        }
        if !parameter.dynamic && parameter.decoded == "--" {
            // PowerShell treats `--` as the end-of-parameters marker for
            // cmdlets. Every later dash-prefixed word is positional data: it
            // cannot invalidate an earlier -Recurse, and a later `-WhatIf`
            // does not enable preview mode.
            stop_parsing = true;
            continue;
        }
        let switch_value = if colon.is_some() {
            powershell_switch_value(raw_value)
        } else {
            PowerShellSwitchValue::Enabled
        };

        let static_parameter = (!parameter.dynamic)
            .then(|| parameter.decoded.strip_prefix('-'))
            .flatten()
            .and_then(resolve_remove_item_parameter);
        if let Some(static_parameter) = static_parameter {
            match static_parameter {
                RemoveItemParameter::Recurse => {
                    unresolved_remove_binding |=
                        record_powershell_switch(&mut recurse, switch_value, true);
                }
                RemoveItemParameter::Force => {
                    unresolved_remove_binding |=
                        record_powershell_switch(&mut force, switch_value, true);
                }
                RemoveItemParameter::WhatIf => {
                    unresolved_remove_binding |=
                        record_powershell_switch(&mut what_if, switch_value, true);
                }
                RemoveItemParameter::Value => {
                    // `-Path`/`-LiteralPath` values are deletion targets and
                    // join the literal-temp accounting; other value-taking
                    // parameters (-Include, -ErrorAction, ...) select within
                    // or beside the targets and do not name new ones.
                    let binds_target = remove_item_value_parameter_binds_path(&parameter.decoded);
                    if colon.is_some() {
                        if let Some(value) = raw_value {
                            if binds_target {
                                if powershell_literal_target_is_user_temp(value) {
                                    literal_temp_targets += 1;
                                } else {
                                    non_temp_target = true;
                                }
                            }
                        } else {
                            invalid_static_remove_parameter = true;
                        }
                    } else {
                        match raw_words
                            .get(index)
                            .copied()
                            .map(powershell_value_lookahead)
                        {
                            Some(PowerShellValueLookahead::Data) => {
                                if binds_target {
                                    let value = raw_words.get(index).copied().unwrap_or_default();
                                    if powershell_literal_target_is_user_temp(value) {
                                        literal_temp_targets += 1;
                                    } else {
                                        non_temp_target = true;
                                    }
                                }
                                index += 1;
                            }
                            Some(PowerShellValueLookahead::NamedParameter) | None => {
                                // A recognized or ambiguous named parameter
                                // starts a new binding; the current value-taking
                                // parameter is therefore missing its argument.
                                invalid_static_remove_parameter = true;
                            }
                            Some(PowerShellValueLookahead::Dynamic) => {
                                // Runtime expansion can turn this token into a
                                // value (allowing deletion) or a recognized
                                // parameter (causing a binding error).
                                unresolved_remove_binding = true;
                                index += 1;
                            }
                            Some(PowerShellValueLookahead::EndOfParameters) => {
                                index += 1;
                                if raw_words.get(index).is_some() {
                                    index += 1;
                                    stop_parsing = true;
                                    // The word past `--` bound to this
                                    // parameter is unexamined data.
                                    non_temp_target = true;
                                } else {
                                    invalid_static_remove_parameter = true;
                                }
                            }
                        }
                    }
                }
                RemoveItemParameter::Other => {
                    if colon.is_some() && switch_value == PowerShellSwitchValue::Unresolved {
                        unresolved_remove_binding = true;
                    }
                }
            }
            continue;
        }

        if parameter.dynamic {
            if dynamic_parameter_may_resolve_to(&parameter, RemoveItemParameter::Recurse) {
                unresolved_remove_binding |=
                    record_powershell_switch(&mut recurse, switch_value, false);
            }
            if dynamic_parameter_may_resolve_to(&parameter, RemoveItemParameter::Force) {
                unresolved_remove_binding |=
                    record_powershell_switch(&mut force, switch_value, false);
            }
            if dynamic_parameter_may_resolve_to(&parameter, RemoveItemParameter::WhatIf) {
                unresolved_remove_binding |=
                    record_powershell_switch(&mut what_if, switch_value, false);
            }
        } else if is_remove_item
            && parameter
                .decoded
                .strip_prefix('-')
                .is_some_and(|name| name.chars().next().is_some_and(char::is_alphabetic))
        {
            // PowerShell binds every named parameter before invoking the
            // cmdlet. A literal unknown or ambiguous spelling (notably `-F`,
            // which collides between Filter and Force) therefore prevents
            // Remove-Item from executing at all. Do not manufacture a
            // destructive result from the otherwise valid `-Recurse` token.
            invalid_static_remove_parameter = true;
        }
    }

    if is_remove_item && invalid_static_remove_parameter {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    if (is_remove_item || is_clear_content || is_clear_recycle_bin) && what_if.exact {
        return WindowsFilesystemSemanticDecision::Safe;
    }
    if is_clear_content {
        return WindowsFilesystemSemanticDecision::Destructive("clear-content");
    }
    if is_clear_recycle_bin {
        return WindowsFilesystemSemanticDecision::Destructive("clear-recyclebin");
    }
    // #280: `rd /s /q X` (and `del`/`erase`/`rmdir` `/s`) under the PowerShell
    // dialect. PowerShell would only report an error (the switches bind as
    // path arguments to the Remove-Item alias), but the author almost
    // certainly intended cmd.exe semantics, so classify exactly like the Cmd
    // scanner. Literal per-user temp targets keep the #285 carve-out for
    // parity with that scanner.
    if let Some(rule) = cmd_style_rule
        && cmd_style_recursive
    {
        if literal_temp_targets > 0
            && !non_temp_target
            && !unresolved_remove_binding
            && !splatted_options
        {
            return WindowsFilesystemSemanticDecision::Safe;
        }
        return WindowsFilesystemSemanticDecision::Destructive(rule);
    }
    if is_remove_item && recurse.possible && (unresolved_remove_binding || splatted_options) {
        return WindowsFilesystemSemanticDecision::Unverified;
    }
    if is_remove_item && recurse.exact {
        // #285: recursive deletes whose every proven target is a literal
        // per-user temp subpath (`C:\Users\<user>\AppData\Local\Temp\<x>`)
        // get the same carve-out as `rm -rf /tmp/<subpath>`. `$env:TEMP`
        // spellings stay reviewed like `$TMPDIR` (caller-controlled), and
        // the machine-wide `C:\Windows\Temp` is not carved out.
        if literal_temp_targets > 0 && !non_temp_target {
            return WindowsFilesystemSemanticDecision::Safe;
        }
        return WindowsFilesystemSemanticDecision::Destructive(if force.exact {
            "remove-item-recurse-force"
        } else {
            "remove-item-recurse"
        });
    }
    let possible_remove = ["remove-item", "rmdir", "rd", "ri", "rm", "del", "erase"]
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::PowerShell, candidate));
    let possible_clear = ["clear-content", "clc", "clear-recyclebin"]
        .iter()
        .any(|candidate| symbolic_word_may_equal(&executable, ShellDialect::PowerShell, candidate));
    let recurse_possible = recurse.possible || splatted_options;
    if executable.dynamic && possible_clear
        || possible_remove
            && recurse_possible
            && (executable.dynamic || !recurse.exact || splatted_options)
    {
        return WindowsFilesystemSemanticDecision::Unverified;
    }
    WindowsFilesystemSemanticDecision::NoMatch
}

/// Evaluate PowerShell call-operator targets before the generic segment pass.
///
/// The dialect tokenizer represents bare `&` as a separator because it can be
/// PowerShell's background operator.  At the beginning of a statement,
/// however, `&` is the call operator and a quoted string becomes executable.
/// Retaining that distinction is necessary for forms such as
/// `& "Clear`-Content" file`, whose protected verb is otherwise inert data.
fn powershell_static_call_postfix_preserves_executable(call: &str, tail: &str) -> bool {
    let Some(target_len) = call.len().checked_sub(tail.len()) else {
        return false;
    };
    let target = call.get(..target_len).unwrap_or_default().trim_end();
    let Some(rest) = target
        .trim_start()
        .strip_prefix('&')
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        .map(str::trim_start)
    else {
        return false;
    };
    let (array_expression, opening_parenthesis) = if rest.starts_with("@(") {
        (true, 1usize)
    } else if rest.starts_with("$(") {
        (false, 1usize)
    } else if rest.starts_with('(') {
        (false, 0usize)
    } else {
        return false;
    };

    let mut depth = 0usize;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut expression_end = None;
    for (index, character) in rest.char_indices().skip(opening_parenthesis) {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '`' && !single {
            escaped = true;
            continue;
        }
        if character == '\'' && !double {
            single = !single;
            continue;
        }
        if character == '"' && !single {
            double = !double;
            continue;
        }
        if single || double {
            continue;
        }
        match character {
            '(' => depth = depth.saturating_add(1),
            ')' => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
                if depth == 0 {
                    expression_end = Some(index + character.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(expression_end) = expression_end else {
        return false;
    };
    let postfix = rest.get(expression_end..).unwrap_or_default().trim();
    if postfix.is_empty() {
        return true;
    }

    // Only the identity selection from the single-element array expression is
    // statically equivalent to the parser's decoded executable. Parenthesized
    // strings index characters, and runtime/multiple indices can select a
    // different value. Keep those forms fail-closed rather than reusing a
    // literal that no longer necessarily occupies the executable role.
    let Some(index) = postfix
        .strip_prefix('[')
        .and_then(|postfix| postfix.strip_suffix(']'))
        .map(str::trim)
    else {
        return false;
    };
    array_expression && index == "0"
}

fn powershell_call_operator_analysis(command: &str) -> PowerShellCallOperatorAnalysis {
    let tokens = tokenize_for_shell_dialect(command, ShellDialect::PowerShell);
    let mut saw_word_in_statement = false;
    let mut saw_safe = false;
    let mut saw_unverified = false;
    let mut inert_target_spans = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        match token.kind {
            NormalizeTokenKind::Word => saw_word_in_statement = true,
            NormalizeTokenKind::Separator => {
                let is_call_operator = !saw_word_in_statement && token.text(command) == Some("&");
                if is_call_operator {
                    let call = command[token.byte_range.start..].trim_start();
                    let expression_decision =
                        crate::packs::core::git::powershell_static_call_executable(call).map(
                            |(executable, tail)| {
                                if !powershell_static_call_postfix_preserves_executable(call, tail)
                                {
                                    return WindowsFilesystemSemanticDecision::Unverified;
                                }
                                let Some(executable) = executable else {
                                    return WindowsFilesystemSemanticDecision::Unverified;
                                };
                                let basename = executable
                                    .rsplit(['/', '\\'])
                                    .next()
                                    .unwrap_or(&executable)
                                    .to_ascii_lowercase();
                                if !POWERSHELL_PROTECTED_EXECUTABLES
                                    .iter()
                                    .any(|candidate| basename == *candidate)
                                {
                                    let tail_start = command.len().saturating_sub(tail.len());
                                    if token.byte_range.start < tail_start {
                                        inert_target_spans.push(token.byte_range.start..tail_start);
                                    }
                                    return WindowsFilesystemSemanticDecision::NoMatch;
                                }
                                let first_tail = crate::packs::split_command_segments_in_dialect(
                                    tail,
                                    ShellDialect::PowerShell,
                                )
                                .into_iter()
                                .next()
                                .unwrap_or("");
                                let reconstructed = format!("{basename} {first_tail}");
                                powershell_segment_semantic_decision(&reconstructed, true)
                            },
                        );
                    let tail_start = token.byte_range.end;
                    let tail_end = tokens
                        .iter()
                        .skip(index + 1)
                        .find(|next| next.kind == NormalizeTokenKind::Separator)
                        .map_or(command.len(), |next| next.byte_range.start);
                    let tail = command[tail_start..tail_end].trim();
                    let decision = if let Some(decision) = expression_decision {
                        decision
                    } else if tail.is_empty() {
                        // Parenthesized, indexed, and other expression targets
                        // are split at their opening control token. Their
                        // runtime executable cannot be proven harmless here.
                        WindowsFilesystemSemanticDecision::Unverified
                    } else {
                        powershell_segment_semantic_decision(tail, true)
                    };
                    match decision {
                        decision @ WindowsFilesystemSemanticDecision::Destructive(_) => {
                            return PowerShellCallOperatorAnalysis {
                                decision: Some(decision),
                                inert_target_spans,
                            };
                        }
                        WindowsFilesystemSemanticDecision::Unverified => saw_unverified = true,
                        WindowsFilesystemSemanticDecision::Safe => saw_safe = true,
                        WindowsFilesystemSemanticDecision::NoMatch => {}
                    }
                }
                saw_word_in_statement = false;
            }
        }
    }

    let decision = if saw_unverified {
        Some(WindowsFilesystemSemanticDecision::Unverified)
    } else if saw_safe {
        Some(WindowsFilesystemSemanticDecision::Safe)
    } else {
        None
    };
    PowerShellCallOperatorAnalysis {
        decision,
        inert_target_spans,
    }
}

fn powershell_static_call_is_non_filesystem_command(command: &str) -> bool {
    let Some((Some(executable), tail)) =
        crate::packs::core::git::powershell_static_call_executable(command)
    else {
        return false;
    };
    if !powershell_static_call_postfix_preserves_executable(command, tail) {
        return false;
    }
    let basename = executable.rsplit(['/', '\\']).next().unwrap_or(&executable);
    !POWERSHELL_PROTECTED_EXECUTABLES
        .iter()
        .any(|candidate| basename.eq_ignore_ascii_case(candidate))
}

/// Return whether a command contains a case-insensitive spelling of a
/// PowerShell filesystem verb or alias as a shell-sized word.
///
/// PowerShell command resolution is case-insensitive, while the shared keyword
/// index is intentionally case-sensitive. This bounded prefilter closes that
/// mismatch without forcing the semantic parser for every PowerShell command;
/// the role-aware parser still decides whether the word is executable or inert
/// data.
fn contains_powershell_protected_word_case_insensitive(command: &str) -> bool {
    command
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        })
        .any(|word| {
            POWERSHELL_PROTECTED_EXECUTABLES
                .iter()
                .any(|candidate| word.eq_ignore_ascii_case(candidate))
        })
}

/// Case-insensitive candidate check for the .NET directory-delete surface.
///
/// PowerShell type literals resolve case-insensitively while the shared
/// keyword index is case-sensitive. `[System.IO.Directory]::Delete` and
/// `[System.IO.DirectoryInfo]` both split into a bare `directory` /
/// `directoryinfo` word here; the bounded semantic parser still decides
/// whether the word actually occupies an executable expression.
fn contains_dotnet_directory_word_case_insensitive(command: &str) -> bool {
    command
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        })
        .any(|word| {
            word.eq_ignore_ascii_case("directory") || word.eq_ignore_ascii_case("directoryinfo")
        })
}

/// Analyze native-Windows filesystem syntax with bounded, caller-proven shell
/// decoding. The returned rule name is a member of this pack.
#[must_use]
pub(crate) fn windows_filesystem_semantic_decision_in_dialect(
    command: &str,
    dialect: ShellDialect,
) -> WindowsFilesystemSemanticDecision {
    if dialect == ShellDialect::Posix {
        return WindowsFilesystemSemanticDecision::NoMatch;
    }
    if dialect == ShellDialect::Unknown {
        let decisions = [
            windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell),
            windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::Cmd),
        ];
        if let Some(decision) = decisions
            .iter()
            .copied()
            .find(|decision| matches!(decision, WindowsFilesystemSemanticDecision::Destructive(_)))
        {
            return decision;
        }
        if decisions.contains(&WindowsFilesystemSemanticDecision::Unverified) {
            return WindowsFilesystemSemanticDecision::Unverified;
        }
        return if decisions.contains(&WindowsFilesystemSemanticDecision::Safe) {
            WindowsFilesystemSemanticDecision::Safe
        } else {
            WindowsFilesystemSemanticDecision::NoMatch
        };
    }

    if command.len() > MAX_WINDOWS_FILESYSTEM_SEMANTIC_BYTES {
        // Do not allocate or tokenize an attacker-controlled oversized shell
        // program.  Callers invoke this pass only for the enabled Windows pack;
        // failing closed is the only sound bounded result.
        return WindowsFilesystemSemanticDecision::Unverified;
    }

    if dialect == ShellDialect::PowerShell {
        // Parentheses are structural PowerShell separators, so segmenting first
        // would split `[IO.Directory]::Delete($path, $true)` into pieces and
        // hide the recursive flag from the .NET-expression detector. Inspect
        // the bounded intact command first; the detector remains token- and
        // quote-aware, so inert quoted spellings are still treated as data.
        let tokens = tokenize_for_shell_dialect(command, ShellDialect::PowerShell);
        if let Some(rule) = powershell_dotnet_directory_delete_rule(command, &tokens) {
            return WindowsFilesystemSemanticDecision::Destructive(rule);
        }
    }

    let masked_powershell;
    let command = if dialect == ShellDialect::PowerShell {
        masked_powershell = mask_powershell_comments_and_here_strings(command);
        masked_powershell.as_ref()
    } else {
        command
    };

    let has_dialect_syntax = match dialect {
        ShellDialect::PowerShell => {
            command.contains(['`', '$', '@', '&', '\u{2013}', '\u{2014}', '\u{2015}'])
        }
        ShellDialect::Cmd => command.contains(['^', '%', '!']),
        ShellDialect::Posix | ShellDialect::Unknown => false,
    };
    let lowercase_command = command.to_ascii_lowercase();
    let has_literal_keyword = CMD_PROTECTED_EXECUTABLES
        .iter()
        .chain(POWERSHELL_PROTECTED_EXECUTABLES)
        .any(|keyword| lowercase_command.contains(keyword));

    // The .NET directory-delete expressions are PowerShell call expressions
    // whose `(` and `)` the dialect tokenizer emits as statement-internal
    // separators. The generic segment splitter below therefore severs the
    // method name from its argument list, so neither `^`-anchored matcher
    // (both require the opening `(`) can ever fire on a proven-PowerShell
    // caller — the wiring gap behind issue #222, which left the fix visible
    // only through the Unknown-dialect raw-regex fallback. Detect them here
    // over whole-command tokens, before any paren-driven segmentation; the
    // matchers' own `[^|&\r\n]` guards keep every match inside one statement,
    // and wholly quoted spellings stay inert because the tokenizer groups a
    // quoted string into a single (skipped) word.
    if dialect == ShellDialect::PowerShell {
        let command_tokens = tokenize_for_shell_dialect(command, ShellDialect::PowerShell);
        if let Some(rule) = powershell_dotnet_directory_delete_rule(command, &command_tokens) {
            return WindowsFilesystemSemanticDecision::Destructive(rule);
        }
    }

    let segments = crate::packs::split_command_segments_in_dialect(command, dialect);
    if segments.len() > MAX_WINDOWS_FILESYSTEM_SEMANTIC_SEGMENTS {
        return if has_dialect_syntax || has_literal_keyword {
            WindowsFilesystemSemanticDecision::Unverified
        } else {
            WindowsFilesystemSemanticDecision::NoMatch
        };
    }
    let mut saw_safe = false;
    let mut saw_unverified = false;
    let call_analysis = if dialect == ShellDialect::PowerShell {
        let analysis = powershell_call_operator_analysis(command);
        if let Some(decision) = analysis.decision {
            match decision {
                decision @ WindowsFilesystemSemanticDecision::Destructive(_) => return decision,
                WindowsFilesystemSemanticDecision::Unverified => saw_unverified = true,
                WindowsFilesystemSemanticDecision::Safe => saw_safe = true,
                WindowsFilesystemSemanticDecision::NoMatch => {}
            }
        }
        Some(analysis)
    } else {
        None
    };
    let mut segment_search_start = 0usize;
    for segment in segments {
        let segment_range = command
            .get(segment_search_start..)
            .and_then(|tail| tail.find(segment))
            .map(|relative_start| {
                let start = segment_search_start.saturating_add(relative_start);
                start..start.saturating_add(segment.len())
            });
        if let Some(range) = &segment_range {
            segment_search_start = range.end;
        }
        let is_inert_call_target_fragment = segment_range.as_ref().is_some_and(|segment_range| {
            call_analysis.as_ref().is_some_and(|analysis| {
                analysis.inert_target_spans.iter().any(|target_range| {
                    target_range.start <= segment_range.start
                        && segment_range.end <= target_range.end
                })
            })
        });
        let decision = match dialect {
            ShellDialect::PowerShell if is_inert_call_target_fragment => {
                // The call-operator pass proved that this fragment belongs to
                // a bounded static non-filesystem executable. Preserve that
                // role across the generic splitter without hiding subsequent
                // statements or executable expressions in argument position.
                WindowsFilesystemSemanticDecision::NoMatch
            }
            ShellDialect::PowerShell
                if powershell_static_call_is_non_filesystem_command(segment) =>
            {
                // A bounded literal expression after PowerShell's call operator
                // resolves to a known non-filesystem command. Its remaining
                // arguments are data and must not be reinterpreted as a second
                // executable by the generic segment pass.
                WindowsFilesystemSemanticDecision::NoMatch
            }
            ShellDialect::PowerShell => powershell_segment_semantic_decision(segment, false),
            ShellDialect::Cmd => cmd_segment_semantic_decision(segment),
            ShellDialect::Posix | ShellDialect::Unknown => {
                WindowsFilesystemSemanticDecision::NoMatch
            }
        };
        match decision {
            decision @ WindowsFilesystemSemanticDecision::Destructive(_) => return decision,
            WindowsFilesystemSemanticDecision::Unverified => saw_unverified = true,
            WindowsFilesystemSemanticDecision::Safe => saw_safe = true,
            WindowsFilesystemSemanticDecision::NoMatch => {}
        }
    }
    if saw_unverified {
        WindowsFilesystemSemanticDecision::Unverified
    } else if saw_safe {
        WindowsFilesystemSemanticDecision::Safe
    } else {
        WindowsFilesystemSemanticDecision::NoMatch
    }
}

/// Candidate-selection override for native-Windows filesystem commands whose
/// protected executable or option is hidden by caller-proven shell syntax.
#[must_use]
pub(crate) fn windows_filesystem_semantic_scan_required(
    command: &str,
    dialect: ShellDialect,
) -> bool {
    let has_relevant_escape = match dialect {
        // A statement-leading `&` can turn a quoted string or expression into
        // an executable even when the protected spelling is assembled without
        // a backtick or variable (for example `& ('Clear' + '-Content')`).
        ShellDialect::PowerShell => {
            command.contains(['`', '$', '@', '&', '\u{2013}', '\u{2014}', '\u{2015}'])
        }
        ShellDialect::Cmd => command.contains(['^', '%', '!']),
        ShellDialect::Unknown => command.contains([
            '`', '$', '@', '&', '^', '%', '!', '\u{2013}', '\u{2014}', '\u{2015}',
        ]),
        ShellDialect::Posix => false,
    };
    let has_case_insensitive_powershell_candidate =
        matches!(dialect, ShellDialect::PowerShell | ShellDialect::Unknown)
            && (contains_powershell_protected_word_case_insensitive(command)
                || contains_dotnet_directory_word_case_insensitive(command));
    (has_relevant_escape || has_case_insensitive_powershell_candidate)
        && !matches!(
            windows_filesystem_semantic_decision_in_dialect(command, dialect),
            WindowsFilesystemSemanticDecision::NoMatch
        )
}

/// Create the Windows core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "windows.filesystem".to_string(),
        name: "Windows Filesystem",
        description: "Protects against recursive/forced filesystem destruction on Windows: cmd \
                      `del /s`, `rd /s`, `format <drive>:`, PowerShell `Remove-Item -Recurse \
                      (with or without `-Force`; aliases included), `Clear-Content`, \
                      `Clear-RecycleBin`, and the .NET recursive-delete APIs \
                      `[System.IO.Directory]::Delete($path, $true)` and \
                      `<DirectoryInfo>.Delete($true)`.",
        // Conventional casings retained for readable metadata (see the
        // super-module docs); quick-rejection itself is ASCII
        // case-insensitive. Aliases (rm/ri/clc) remain explicit because they
        // are different command names, not casing variants.
        keywords: &[
            // cmd recursive delete / format
            "del",
            "DEL",
            "erase",
            "ERASE",
            "rd",
            "RD",
            "rmdir",
            "RMDIR",
            "format",
            "FORMAT",
            // PowerShell cmdlets + aliases
            "Remove-Item",
            "remove-item",
            "REMOVE-ITEM",
            "rm",
            "RM",
            "ri",
            "RI",
            "Clear-Content",
            "clear-content",
            "CLEAR-CONTENT",
            "clc",
            "CLC",
            "Clear-RecycleBin",
            "clear-recyclebin",
            "CLEAR-RECYCLEBIN",
            // .NET directory-delete APIs. `IO.Directory` is a substring of
            // both `[System.IO.Directory]` and `[System.IO.DirectoryInfo]`;
            // `.Delete(` gates the DirectoryInfo member-call spelling.
            "IO.Directory",
            "io.directory",
            "Io.Directory",
            "IO.DIRECTORY",
            ".Delete(",
            ".delete(",
            ".DELETE(",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // `-WhatIf` => preview/dry-run, but only for PowerShell verbs that honor
        // it. A stray `-WhatIf` argument must not whitelist cmd.exe `del`, `rd`,
        // `format`, or Unix/Git-Bash `rm`, because those tools would still
        // execute.
        safe_pattern!(
            "whatif-preview",
            r"(?i)^\s*(?:(?:remove-item|ri|clear-content|clc|clear-recyclebin)\b(?![^|&;\r\n]*\s--(?:\s|$))[^|&;\r\n]*\s-whatif\b|rm\b(?=[^|&;\r\n]*\s-recurse\b)(?![^|&;\r\n]*\s--(?:\s|$))[^|&;\r\n]*\s-whatif\b)[^|&;\r\n]*$"
        ),
        // Read-only / preview cmd help on these verbs.
        safe_pattern!(
            "del-help",
            r"(?i)^\s*(?:del|rd|rmdir|format|erase)(?:\.exe)?\s+/\?\s*$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Evaluated explicitly by the bounded caller-dialect semantic pass.
        // The regex is deliberately unsatisfiable: raw text matching must not
        // manufacture a fail-closed finding without role-aware shell analysis.
        DestructivePattern {
            regex: crate::packs::regex_engine::LazyCompiledRegex::new(r"(?!)"),
            reason: WINDOWS_FILESYSTEM_UNVERIFIED_REASON,
            name: Some(WINDOWS_FILESYSTEM_UNVERIFIED_RULE),
            severity: crate::packs::Severity::Critical,
            explanation: Some(
                "Review the fully expanded Windows command before allowing execution. Dynamic or malformed shell syntax in the executable or recursive/forced option roles can conceal an irreversible filesystem operation.",
            ),
            suggestions: DEL_SUGGESTIONS,
        },
        // === cmd: recursive delete (del/erase /s) ===
        destructive_pattern!(
            "del-recursive",
            r"(?i)\b(?:del|erase)(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/s\b",
            "del /s recursively deletes every matching file in a directory tree.",
            Critical,
            "`del /s` recurses into subdirectories and deletes matching files; combined with `/q` \
             there is no per-file prompt and `/f` forces read-only files too. A wrong path or a \
             wildcard at a high level (e.g. `del /s /q C:\\src\\*`) destroys a whole tree with no \
             Recycle Bin and no undo.\n\n\
             Safer alternatives:\n\
             - Scope the path precisely and drop /q so deletions are confirmed\n\
             - Move the directory to %TEMP% instead of deleting it outright",
            DEL_SUGGESTIONS
        ),
        // === cmd: recursive directory removal (rd/rmdir /s) ===
        destructive_pattern!(
            "rd-recursive",
            r"(?i)\b(?:rd|rmdir)(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/s\b",
            "rd /s deletes a directory and its entire contents.",
            Critical,
            "`rd /s` (alias `rmdir /s`) removes a directory and every file and subfolder under it; \
             with `/q` it does so without confirmation. `rd /s /q C:\\path` is the Windows \
             equivalent of `rm -rf` and bypasses the Recycle Bin entirely.\n\n\
             Safer alternatives:\n\
             - Drop /q so the removal is confirmed\n\
             - Move the directory to %TEMP% first so it can be recovered",
            DEL_SUGGESTIONS
        ),
        // === PowerShell: Remove-Item -Recurse -Force (+ aliases) ===
        destructive_pattern!(
            "remove-item-recurse-force",
            r"(?i)\b(?:remove-item|rmdir|rd|ri|rm|del|erase)\b(?=[^|&\r\n]*\s(?:-recurse|-r)\b)(?=[^|&\r\n]*\s(?:-force|-f)\b)",
            "Remove-Item -Recurse -Force deletes a tree with no Recycle Bin and no prompt.",
            Critical,
            "`Remove-Item -Recurse -Force` (or an alias such as `rm`/`del`/`ri`) deletes a directory \
             and everything under it. `-Recurse` permanently descends and removes the whole tree; \
             `-Force` additionally includes hidden/read-only items. Remove-Item does not use the \
             Recycle Bin. \
             Pointed at a profile, repo, or drive root this is catastrophic and irreversible.\n\n\
             Safer alternatives:\n\
             - Re-run with -WhatIf to preview what would be removed\n\
             - Move-Item the target to a temp location instead of deleting",
            REMOVE_ITEM_SUGGESTIONS
        ),
        // === PowerShell: Remove-Item -Recurse without -Force (+ aliases) ===
        // Keep this after the force-specific pattern so raw matching preserves
        // the established rule id for commands that include both switches.
        destructive_pattern!(
            "remove-item-recurse",
            r"(?i)\b(?:remove-item|rmdir|rd|ri|rm|del|erase)\b(?=[^|&\r\n]*\s(?:-recurse|-r)\b)",
            "Remove-Item -Recurse permanently deletes a tree with no Recycle Bin.",
            Critical,
            "`Remove-Item -Recurse` (or an alias such as `rm`/`del`/`ri`) permanently deletes a \
             directory and everything under it. `-Force` is not required for recursive deletion; \
             it only broadens removal to hidden/read-only items. Remove-Item bypasses the Recycle \
             Bin, so a wrong path can destroy a profile, repository, or drive tree with no undo.\n\n\
             Safer alternatives:\n\
             - Re-run with -WhatIf to preview what would be removed\n\
             - Move-Item the target to a temp location instead of deleting",
            REMOVE_ITEM_SUGGESTIONS
        ),
        // === cmd: format a drive ===
        destructive_pattern!(
            "format-drive",
            r"(?i)\bformat(?:\.com|\.exe)?\s+(?:/\S+\s+)*[a-z]:(?:\s|\\|/|$)",
            "format <drive>: erases an entire volume.",
            Critical,
            "`format X:` re-creates the filesystem on a whole volume, destroying all data on it. \
             With `/q` (quick) and `/y` it proceeds with no confirmation. A wrong drive letter \
             formats the wrong disk.\n\n\
             Safer alternatives:\n\
             - Run `Get-Volume` / `wmic logicaldisk get name` and confirm the exact drive first\n\
             - Back up the volume before any format",
            FORMAT_SUGGESTIONS
        ),
        // === PowerShell: Clear-Content (empties a file in place) ===
        destructive_pattern!(
            "clear-content",
            r"(?i)\b(?:clear-content|clc)\b",
            "Clear-Content empties a file's contents in place with no undo.",
            High,
            "`Clear-Content` (alias `clc`) deletes everything inside a file while keeping the file \
             itself — the previous contents are gone with no Recycle Bin entry. Run against logs, \
             source, or config this silently destroys data.\n\n\
             Safer alternatives:\n\
             - Read or back up the file first (Get-Content / Copy-Item)\n\
             - If you must blank it, keep a copy: Copy-Item <f> <f>.bak first",
            CLEAR_SUGGESTIONS
        ),
        // === PowerShell: Clear-RecycleBin (makes prior deletes unrecoverable) ===
        destructive_pattern!(
            "clear-recyclebin",
            r"(?i)\bclear-recyclebin\b",
            "Clear-RecycleBin permanently purges the Recycle Bin.",
            Medium,
            "`Clear-RecycleBin` empties the Recycle Bin, permanently destroying every file that was \
             previously deleted into it — the usual last line of recovery for an accidental delete. \
             With `-Force` it does so without confirmation.\n\n\
             Safer alternatives:\n\
             - Restore or review the Recycle Bin contents before purging\n\
             - Leave the Recycle Bin intact so recent deletes remain recoverable",
            CLEAR_SUGGESTIONS
        ),
        // === .NET: [System.IO.Directory]::Delete($path, $true) ===
        // Keep the recursive-flag rule before the general rule so a literally
        // recursive call reports the more specific id and severity.
        destructive_pattern!(
            "dotnet-directory-delete-recursive",
            r#"(?i)\[\s*(?:system\.)?io\.directory\s*\]\s*::\s*delete\s*\((?=[^|&\r\n]*?,\s*(?:\$true|1|"true"|'true')\s*\))"#,
            "[System.IO.Directory]::Delete with a true recursive flag deletes an entire directory tree.",
            Critical,
            "`[System.IO.Directory]::Delete($path, $true)` (or the `[IO.Directory]` accelerator \
             spelling) is the .NET equivalent of `Remove-Item -Recurse -Force`: it removes the \
             directory and everything under it, bypasses the Recycle Bin, and needs no external \
             tool — plain PowerShell can call it directly. A wrong path, relative path, or \
             variable expansion destroys an entire working tree with no undo.\n\n\
             Safer alternatives:\n\
             - Preview with the cmdlet equivalent: Remove-Item -Recurse <path> -WhatIf\n\
             - Move the directory to a temp/trash location instead of deleting it",
            DOTNET_DELETE_SUGGESTIONS
        ),
        // === .NET: [System.IO.Directory]::Delete(...) — any other call ===
        destructive_pattern!(
            "dotnet-directory-delete",
            r"(?i)\[\s*(?:system\.)?io\.directory\s*\]\s*::\s*delete\s*\(",
            "[System.IO.Directory]::Delete removes a directory outside the Recycle Bin.",
            High,
            "`[System.IO.Directory]::Delete` permanently removes the target directory. With a \
             dynamic second argument the call can still recurse: PowerShell coerces any truthy \
             value — including every non-empty string — to `$true`. Even the single-argument \
             form deletes the directory (when empty) with no Recycle Bin entry.\n\n\
             Safer alternatives:\n\
             - Preview with the cmdlet equivalent: Remove-Item <path> -WhatIf\n\
             - Move the directory to a temp/trash location instead of deleting it",
            DOTNET_DELETE_SUGGESTIONS
        ),
        // === .NET: <DirectoryInfo>.Delete($true) instance-method spelling ===
        destructive_pattern!(
            "directoryinfo-delete-recursive",
            r"(?i)\.\s*delete\s*\(\s*\$true\s*\)",
            ".Delete($true) on a DirectoryInfo object recursively deletes the directory tree.",
            Critical,
            "`<DirectoryInfo>.Delete($true)` — for example `(Get-Item $path).Delete($true)` or a \
             `[System.IO.DirectoryInfo]` variable — recursively deletes the directory and all of \
             its contents, bypassing the Recycle Bin exactly like \
             `[System.IO.Directory]::Delete($path, $true)`.\n\n\
             Safer alternatives:\n\
             - Preview with the cmdlet equivalent: Remove-Item -Recurse <path> -WhatIf\n\
             - Move the directory to a temp/trash location instead of deleting it",
            DOTNET_DELETE_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "windows.filesystem");
        assert_eq!(pack.name, "Windows Filesystem");
        assert!(pack.keywords.contains(&"del"));
        assert!(pack.keywords.contains(&"Remove-Item"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn blocks_cmd_recursive_deletes() {
        let pack = create_pack();
        let checks = [
            ("del /s /q C:\\src", "del-recursive"),
            ("del /q /s C:\\src\\*", "del-recursive"),
            ("DEL /S /Q C:\\src", "del-recursive"),
            ("erase /s C:\\data", "del-recursive"),
            ("rd /s /q C:\\src", "rd-recursive"),
            ("RD /S /Q C:\\src", "rd-recursive"),
            ("rmdir /s C:\\build", "rd-recursive"),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_powershell_recursive_force_and_aliases() {
        let pack = create_pack();
        let checks = [
            "Remove-Item -Recurse -Force C:\\src",
            "Remove-Item -Force -Recurse C:\\src",
            "remove-item -recurse -force C:\\src",
            "rm -Recurse -Force C:\\src",
            "rm -r -f C:\\src -WhatIf",
            "del -r -f C:\\src",
            "ri -Force -Recurse $env:USERPROFILE\\repo",
        ];
        for command in checks {
            assert_blocks_with_pattern(&pack, command, "remove-item-recurse-force");
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_powershell_recursive_deletes_without_force() {
        let pack = create_pack();
        for command in [
            "Remove-Item -Recurse C:\\src",
            "remove-item -r C:\\src",
            "ri -R C:\\src",
            "rm -Recurse $env:USERPROFILE\\repo",
        ] {
            assert_blocks_with_pattern(&pack, command, "remove-item-recurse");
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_format_and_clear() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "format C: /q /y", "format-drive");
        assert_blocks_with_pattern(&pack, "format C: /q /y -WhatIf", "format-drive");
        assert_blocks_with_pattern(&pack, "format /fs:NTFS D:", "format-drive");
        assert_blocks_with_pattern(&pack, "Clear-Content C:\\app\\server.log", "clear-content");
        assert_blocks_with_pattern(&pack, "clc .\\notes.txt", "clear-content");
        assert_blocks_with_pattern(&pack, "Clear-RecycleBin -Force", "clear-recyclebin");
    }

    #[test]
    fn blocks_dotnet_directory_delete_recursive() {
        let pack = create_pack();
        let checks = [
            r"[System.IO.Directory]::Delete('E:\Dcg_test', $true)",
            r"[IO.Directory]::Delete($path, $true)",
            r"[io.directory]::delete($path,$true)",
            r"[System.IO.Directory]::Delete('D:\data', 1)",
            r#"[System.IO.Directory]::Delete($root, "true")"#,
            r"[ System.IO.Directory ] :: Delete ($repo, $true)",
            r"[System.IO.Directory]::Delete((Join-Path $root 'sub'), $true)",
        ];
        for command in checks {
            assert_blocks_with_pattern(&pack, command, "dotnet-directory-delete-recursive");
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_dotnet_directory_delete_other_forms() {
        let pack = create_pack();
        // Dynamic second argument (PowerShell coerces any truthy value to
        // $true) and the single-argument empty-directory form.
        for command in [
            r"[System.IO.Directory]::Delete($path, $flag)",
            r"[IO.Directory]::Delete('C:\obsolete-empty')",
        ] {
            assert_blocks_with_pattern(&pack, command, "dotnet-directory-delete");
            assert_blocks_with_severity(&pack, command, Severity::High);
        }
    }

    #[test]
    fn blocks_directoryinfo_recursive_delete() {
        let pack = create_pack();
        let checks = [
            r"$dir.Delete($true)",
            r"(Get-Item 'C:\tmp\scratch').Delete($true)",
            r"([System.IO.DirectoryInfo]'C:\src').Delete($true)",
            r"(New-Object System.IO.DirectoryInfo 'C:\src').Delete( $true )",
        ];
        for command in checks {
            assert_blocks_with_pattern(&pack, command, "directoryinfo-delete-recursive");
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn dotnet_directory_read_apis_do_not_match() {
        let pack = create_pack();
        assert_no_match(&pack, r"[System.IO.Directory]::Exists('C:\src')");
        assert_no_match(&pack, r"[IO.Directory]::GetFiles('C:\src')");
        assert_no_match(&pack, r"[System.IO.Directory]::CreateDirectory($path)");
        assert_no_match(&pack, r"[System.IO.Directory]::GetCurrentDirectory()");
        assert_no_match(&pack, r"[System.IO.File]::ReadAllText($path)");
        // Member calls without a literal $true recursive flag are not this
        // rule's target (a $false flag is the non-recursive one-arg form).
        assert_no_match(&pack, r"$dir.Delete($false)");
        assert_no_match(&pack, r"$queue.Delete($item)");
    }

    #[test]
    fn powershell_semantic_detects_dotnet_directory_delete() {
        let destructive = [
            (
                r"[System.IO.Directory]::Delete('E:\Dcg_test', $true)",
                "dotnet-directory-delete-recursive",
            ),
            (
                r"$x = [IO.Directory]::Delete($path, $true)",
                "dotnet-directory-delete-recursive",
            ),
            (
                r"[system.io.directory]::delete($path, $flag)",
                "dotnet-directory-delete",
            ),
            (r"$dir.Delete($true)", "directoryinfo-delete-recursive"),
            (
                r"(Get-Item 'C:\tmp\scratch').Delete($true)",
                "directoryinfo-delete-recursive",
            ),
        ];
        for (command, expected) in destructive {
            for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
                assert_eq!(
                    windows_filesystem_semantic_decision_in_dialect(command, dialect),
                    WindowsFilesystemSemanticDecision::Destructive(expected),
                    "{dialect:?} must classify {command}"
                );
            }
        }
        // A wholly quoted spelling in an ordinary statement is data for a
        // proven-PowerShell caller; executing it requires a call operator or
        // Invoke-Expression, which are analyzed elsewhere.
        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                r"Write-Output '[System.IO.Directory]::Delete($p, $true)'",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::NoMatch
        );
        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                r"Write-Output '$dir.Delete($true)'",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::NoMatch
        );
        for inert in [
            r"Write-Output ok # [System.IO.Directory]::Delete($p, $true)",
            r"<# [System.IO.Directory]::Delete($p, $true) #> Write-Output ok",
            r#"Write-Output "example: [System.IO.Directory]::Delete($p, $true)""#,
            "$text = @'\n[System.IO.Directory]::Delete($p, $true)\n'@; Write-Output $text",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(inert, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::NoMatch,
                "inert PowerShell data must not execute: {inert:?}"
            );
        }
        for active_after_inert in [
            "# [System.IO.Directory]::Delete($p, $true)\n[IO.Directory]::Delete($p, $true)",
            "<# [System.IO.Directory]::Delete($p, $true) #>; $dir.Delete($true)",
            "$text = @'\n[System.IO.Directory]::Delete($p, $true)\n'@\n[IO.Directory]::Delete($p, $true)",
            r#"Write-Output<#; [IO.Directory]::Delete("C:\src", $true); #>"#,
        ] {
            assert!(
                matches!(
                    windows_filesystem_semantic_decision_in_dialect(
                        active_after_inert,
                        ShellDialect::PowerShell,
                    ),
                    WindowsFilesystemSemanticDecision::Destructive(_)
                ),
                "an inert example must not hide a later executable delete: {active_after_inert:?}"
            );
        }
    }

    #[test]
    fn blocks_cmd_deletes_even_with_powershell_whatif_token() {
        let pack = create_pack();
        let checks = [
            ("del /s /q C:\\src -WhatIf", "del-recursive"),
            ("rd /s /q C:\\src -WhatIf", "rd-recursive"),
            ("rmdir /s C:\\build -whatif", "rd-recursive"),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
        }
    }

    #[test]
    fn keyword_quick_reject_passes_windows_verbs_both_cases() {
        // win-pack-quick-reject-keywords (.9.1): the keyword pre-filter must NOT
        // short-circuit Windows destructive commands (in either case) to ALLOW
        // before the (?i) regex runs, while still rejecting unrelated commands.
        // create_pack()'s might_match falls back to the same case-sensitive
        // keyword set the registry Aho-Corasick is built from, so this verifies
        // the realistic-casing convention covers the real forms.
        let pack = create_pack();
        for cmd in [
            "del /s /q C:\\src",
            "DEL /S /Q C:\\src",
            "rd /s /q C:\\src",
            "RD /S /Q C:\\src",
            "Remove-Item -Recurse -Force C:\\src",
            "remove-item -recurse -force C:\\src",
            "REMOVE-ITEM -RECURSE -FORCE C:\\src",
            "rm -Recurse -Force C:\\src",
            "format C: /q",
            "CLEAR-CONTENT C:\\app\\server.log",
            "CLEAR-RECYCLEBIN -Force",
            "[System.IO.Directory]::Delete('E:\\Dcg_test', $true)",
            "[io.directory]::delete($path, $true)",
            "$dir.Delete($true)",
            "$dir.delete($true)",
        ] {
            assert!(pack.might_match(cmd), "keyword gate should admit: {cmd}");
        }
        for cmd in ["ls -la", "cargo build", "git status", "echo hello world"] {
            assert!(!pack.might_match(cmd), "keyword gate should skip: {cmd}");
        }
    }

    #[test]
    fn allows_whatif_help_and_nonrecursive_commands() {
        let pack = create_pack();
        let allowed = [
            // -WhatIf previews
            "Remove-Item -Recurse C:\\src -WhatIf",
            "Remove-Item -Recurse -Force C:\\src -WhatIf",
            "ri -R C:\\src -WhatIf",
            "rm -Recurse C:\\src -WhatIf",
            "rm -Recurse -Force C:\\src -WhatIf",
            "Clear-Content C:\\app\\server.log -WhatIf",
            "Clear-RecycleBin -WhatIf",
            // help / read-only
            "del /?",
            "rd /?",
            // non-recursive single-file ops are not in this pack's destructive set
            "del C:\\src\\one.txt",
            "rd C:\\empty-dir",
            // benign command with no windows.filesystem keyword at all
            "Get-ChildItem C:\\src",
        ];
        for command in allowed {
            assert_allows(&pack, command);
        }
        assert_no_safe_match(&pack, "rm -r -f C:\\src -WhatIf");
        // NOTE: a destructive verb appearing as DATA (e.g. `echo del /s /q ...`)
        // is matched at the raw-pack level here by design; the evaluator's
        // context classification is what prevents that false positive in
        // hook/e2e mode (covered by win-pack-tests-e2e), not the pack itself.
    }

    #[test]
    fn recursive_temp_deletes_are_reviewed_and_cannot_shadow_other_targets() {
        let pack = create_pack();
        for command in [
            "del /s /q %TEMP%\\build",
            "rd /s /q %TMP%\\cache",
            "Remove-Item -Recurse -Force $env:TEMP\\build",
            "Remove-Item -Recurse -Force $env:LOCALAPPDATA\\Temp\\dcg",
            "rd /s /q C:\\Windows\\Temp\\stale",
            "Remove-Item -Recurse -Force ([System.IO.Path]::GetTempPath() + 'x')",
            "Remove-Item -Recurse -Force C:\\Windows\\Temp\\x C:\\Windows\\System32",
            "del /s /q C:\\Windows\\Temp\\x C:\\Windows\\System32",
        ] {
            assert!(
                pack.check(command).is_some(),
                "recursive temp cleanup must require review: {command}"
            );
        }
    }

    #[test]
    fn cmd_style_slash_s_deletes_are_blocked_under_the_powershell_dialect() {
        // Regression for #280: the hook maps the PowerShell tool to the ps
        // dialect, where `rd`/`del` alias Remove-Item and `/s` is a literal
        // path argument. The author almost certainly intended cmd.exe
        // semantics (PowerShell itself would only error), so the ps scanner
        // must classify exactly like the Cmd scanner.
        let destructive = [
            (
                r"rd /s /q C:\Users\test\Projekte\testordner",
                "rd-recursive",
            ),
            (r"RD /S /Q C:\src", "rd-recursive"),
            (r"rmdir /s C:\build", "rd-recursive"),
            (r"del /s /q C:\x", "del-recursive"),
            (r"erase /s C:\data", "del-recursive"),
            (r"rd /s /q $env:TEMP\x", "rd-recursive"),
        ];
        for (command, expected) in destructive {
            for dialect in [ShellDialect::PowerShell, ShellDialect::Unknown] {
                assert_eq!(
                    windows_filesystem_semantic_decision_in_dialect(command, dialect),
                    WindowsFilesystemSemanticDecision::Destructive(expected),
                    "{dialect:?} must classify {command}"
                );
            }
        }
        // Genuine PowerShell spellings without a cmd-style `/s` keep their
        // current classification.
        for command in [r"rd .\builddir", r"rd /q C:\builddir", r"del C:\file.txt"] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell),
                WindowsFilesystemSemanticDecision::NoMatch,
                "non-/s PowerShell spelling must stay unmatched: {command}"
            );
        }
    }

    #[test]
    fn literal_user_temp_subpath_deletes_are_carved_out() {
        // Regression for #285: recursive deletes whose every proven target is
        // a literal per-user temp subpath are temp cleanup, exactly like
        // `rm -rf /tmp/<subpath>` on Unix. Windows paths compare
        // case-insensitively.
        let safe = [
            (
                r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\some\subdir\file",
                ShellDialect::PowerShell,
            ),
            (
                r"Remove-Item -Recurse c:\users\u\appdata\local\TEMP\x",
                ShellDialect::PowerShell,
            ),
            (
                r"rd /s /q C:\Users\u\AppData\Local\Temp\sub",
                ShellDialect::PowerShell,
            ),
            (
                r"rd /s /q C:\Users\u\AppData\Local\Temp\sub",
                ShellDialect::Cmd,
            ),
            (
                r"del /s /q C:\Users\u\AppData\Local\Temp\build",
                ShellDialect::Cmd,
            ),
        ];
        for (command, dialect) in safe {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, dialect),
                WindowsFilesystemSemanticDecision::Safe,
                "{dialect:?} must carve out literal temp cleanup: {command}"
            );
        }
        // The carve-out must stay bounded: the temp root itself, non-temp
        // paths, prefix confusion, traversal, comma/multi-target smuggling,
        // the machine-wide C:\Windows\Temp, and dynamic roots stay denied.
        let destructive = [
            (
                r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp",
                ShellDialect::PowerShell,
                "remove-item-recurse-force",
            ),
            (
                r"Remove-Item -Recurse -Force C:\Users\u",
                ShellDialect::PowerShell,
                "remove-item-recurse-force",
            ),
            (
                r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Tempx\y",
                ShellDialect::PowerShell,
                "remove-item-recurse-force",
            ),
            (
                r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\x C:\Windows\System32",
                ShellDialect::PowerShell,
                "remove-item-recurse-force",
            ),
            (
                r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\x,C:\Windows",
                ShellDialect::PowerShell,
                "remove-item-recurse-force",
            ),
            (
                r"Remove-Item -Recurse -Force C:\Windows\Temp\x",
                ShellDialect::PowerShell,
                "remove-item-recurse-force",
            ),
            (
                r"rd /s /q C:\Users\u\AppData\Local\Temp\..\x",
                ShellDialect::Cmd,
                "rd-recursive",
            ),
            (
                r"rd /s /q C:\Users\u\AppData\Local\Temp\x C:\src",
                ShellDialect::Cmd,
                "rd-recursive",
            ),
            (
                r"rd /s /q C:\Windows\Temp\stale",
                ShellDialect::Cmd,
                "rd-recursive",
            ),
        ];
        for (command, dialect, expected) in destructive {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, dialect),
                WindowsFilesystemSemanticDecision::Destructive(expected),
                "{dialect:?} carve-out must stay bounded: {command}"
            );
        }
    }

    #[test]
    fn semantic_cmd_decoder_covers_every_protected_verb() {
        let checks = [
            ("d^el /s /q C:\\src", "del-recursive"),
            ("e^rase /s C:\\data", "del-recursive"),
            ("r^d /s /q C:\\src", "rd-recursive"),
            ("r^mdir /s C:\\build", "rd-recursive"),
            ("f^ormat C: /q", "format-drive"),
            ("f^ormat \"D:\" /q", "format-drive"),
        ];
        for (command, expected) in checks {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::Cmd),
                WindowsFilesystemSemanticDecision::Destructive(expected),
                "caller-proven Cmd decoding must classify {command}"
            );
            assert!(
                windows_filesystem_semantic_scan_required(command, ShellDialect::Cmd),
                "escaped executable must override keyword candidate selection: {command}"
            );
        }
    }

    #[test]
    fn semantic_powershell_decoder_covers_every_protected_verb() {
        let remove_item_aliases = [
            "Remove`-Item",
            "r`mdir",
            "r`d",
            "r`i",
            "r`m",
            "d`el",
            "e`rase",
        ];
        for executable in remove_item_aliases {
            let command = format!("{executable} -Re`curse -Fo`rce C:\\src");
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(&command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse-force"),
                "caller-proven PowerShell decoding must classify {command}"
            );
            assert!(windows_filesystem_semantic_scan_required(
                &command,
                ShellDialect::PowerShell
            ));
        }

        for (command, expected) in [
            ("Clear`-Content C:\\app\\server.log", "clear-content"),
            ("c`lc .\\notes.txt", "clear-content"),
            ("Clear`-RecycleBin -Force", "clear-recyclebin"),
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive(expected),
                "caller-proven PowerShell decoding must classify {command}"
            );
            assert!(windows_filesystem_semantic_scan_required(
                command,
                ShellDialect::PowerShell
            ));
        }

        for (command, expected) in [
            ("& \"Clear`-Content\" C:\\app\\server.log", "clear-content"),
            ("& \"Clear`-RecycleBin\" -Force", "clear-recyclebin"),
            (
                "& @('Clear-Content')[0] C:\\app\\server.log",
                "clear-content",
            ),
            (
                "Write-Output ready; & \"Remove`-Item\" -Re`curse -Fo`rce C:\\src",
                "remove-item-recurse-force",
            ),
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive(expected),
                "PowerShell's call operator must preserve executable quoted strings: {command}"
            );
            assert!(windows_filesystem_semantic_scan_required(
                command,
                ShellDialect::PowerShell,
            ));
        }
    }

    #[test]
    fn semantic_powershell_blocks_recurse_without_force_and_preserves_whatif() {
        for command in [
            "Remove-Item -Recurse C:\\src",
            "ri -R C:\\src",
            "& \"Remove-Item\" -Recurse C:\\src",
            "& 'ri' -R C:\\src",
            "Remove-Item -Recurse -- -important",
            "Remove-Item -Recurse -- C:\\src -WhatIf",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse"),
                "recursive Remove-Item is destructive without Force: {command}",
            );
            assert!(windows_filesystem_semantic_scan_required(
                command,
                ShellDialect::PowerShell,
            ));
        }

        for command in [
            "Remove-Item -Recurse C:\\src -WhatIf",
            "ri -R C:\\src -WhatIf",
            "& \"Remove-Item\" -Recurse C:\\src -WhatIf",
            "& 'ri' -R C:\\src -WhatIf",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Safe,
                "a proven WhatIf preview must remain safe: {command}",
            );
        }

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove-Item -- -Recurse C:\\src",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::NoMatch,
            "Recurse after PowerShell's end-of-parameters marker is positional data",
        );
    }

    #[test]
    fn semantic_powershell_binds_unique_remove_item_switch_prefixes() {
        assert_eq!(
            resolve_remove_item_parameter("R"),
            Some(RemoveItemParameter::Recurse)
        );
        assert_eq!(
            resolve_remove_item_parameter("Rec"),
            Some(RemoveItemParameter::Recurse)
        );
        assert_eq!(resolve_remove_item_parameter("F"), None);
        assert_eq!(
            resolve_remove_item_parameter("Fi"),
            Some(RemoveItemParameter::Value)
        );
        assert_eq!(
            resolve_remove_item_parameter("Fo"),
            Some(RemoveItemParameter::Force)
        );
        assert_eq!(resolve_remove_item_parameter("W"), None);
        assert_eq!(
            resolve_remove_item_parameter("EA"),
            Some(RemoveItemParameter::Value),
            "common-parameter aliases must bind exactly"
        );
        assert_eq!(
            resolve_remove_item_parameter("LP"),
            Some(RemoveItemParameter::Value),
            "cmdlet parameter aliases must bind exactly"
        );
        assert_eq!(
            resolve_remove_item_parameter("Wh"),
            Some(RemoveItemParameter::WhatIf)
        );
        assert_eq!(
            resolve_remove_item_parameter("wi"),
            Some(RemoveItemParameter::WhatIf),
            "WhatIf's parameter alias must bind exactly"
        );
    }

    #[test]
    fn semantic_powershell_switch_booleans_block_recursive_force_aliases() {
        for command in [
            "Remove-Item -Rec:$true -Fo:$true C:\\src",
            "Remove-Item -Recurse:$TRUE -Force:$TrUe C:\\src",
            "rm -R:$true -For:$true C:\\src",
            "ri -Recu:$true -Forc:$true C:\\src",
            "del -R: $true -Fo: $true C:\\src",
            "Remove`-Item -Re`c:$true -Fo`r:$true C:\\src",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse-force"),
                "PowerShell-bound true switches must classify {command}"
            );
            assert!(
                windows_filesystem_semantic_scan_required(command, ShellDialect::PowerShell),
                "boolean/escaped syntax must override candidate selection: {command}"
            );
        }
    }

    #[test]
    fn semantic_powershell_switch_booleans_preserve_false_and_whatif() {
        for command in [
            "Remove-Item -Rec:$false -Fo:$true C:\\src",
            "rm -R:$false -For:$false C:\\src",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::NoMatch,
                "a false Recurse switch must remain disabled: {command}"
            );
        }

        for command in [
            "Remove-Item -Rec:$true -Fo:$false C:\\src",
            "Remove-Item -R:$true -Fi:$true C:\\src",
            "Remove-Item -R:$true C:\\src -EA SilentlyContinue",
            "Remove-Item -R:$true -LP C:\\src",
            "Remove-Item -Recurse -LiteralPath -foo",
            "Remove-Item -Recurse -Path -foo",
            "Remove-Item -Filter -foo . -Recurse",
            "Remove-Item -Recurse -LiteralPath -- -foo",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse"),
                "Recurse is destructive even when Force is false, absent, or replaced by another valid parameter: {command}"
            );
        }

        for command in [
            "Remove-Item -R:$true -F:$true C:\\src",
            "Remove-Item -R:$true -NotAParameter C:\\src",
            "Remove-Item -Recurse -LiteralPath -Force",
            "Remove-Item -Recurse -LiteralPath -F",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::NoMatch,
                "a statically invalid parameter prevents PowerShell from invoking Remove-Item: {command}"
            );
        }

        for command in [
            "Remove-Item -Rec:$true -Fo:$true C:\\src -Wh:$true",
            "rm -R:$true -Fo:$true C:\\src -wi:$true",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Safe,
                "a proven true WhatIf binding must preserve preview safety: {command}"
            );
        }

        for command in [
            "Remove-Item -Rec:$true -Fo:$true C:\\src -WhatIf:$false",
            "rm -R:$true -Fo:$true C:\\src -Wh:$false",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse-force"),
                "a false WhatIf binding must not allow destruction: {command}"
            );
        }
    }

    #[test]
    fn semantic_powershell_accepts_only_binder_recognized_parameter_dashes() {
        for command in [
            "Remove-Item –Recurse –Force C:\\src",
            "Remove-Item —Recurse —Force C:\\src",
            "Remove-Item ―Recurse ―Force C:\\src",
            "rm –R –Fo C:\\src",
            "Remove-Item —Rec:$true —Fo:$true C:\\src",
            "Remove-Item ―R: $true ―For: $true C:\\src",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse-force"),
                "PowerShell-recognized parameter dashes must not bypass protection: {command}"
            );
            assert!(windows_filesystem_semantic_scan_required(
                command,
                ShellDialect::PowerShell,
            ));
        }

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove-Item –Rec:$false –Fo:$true C:\\src",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::NoMatch,
            "a false switch value stays disabled with a typographic parameter dash",
        );
        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove-Item —Rec:$true —Fo:$true C:\\src —Wh:$true",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Safe,
            "a true WhatIf switch stays safe with a typographic parameter dash",
        );
        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove-Item ―Rec:$true ―Fo:$true C:\\src ―wi:$false",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse-force"),
            "a false WhatIf switch must not allow destruction",
        );

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove-Item −Recurse −Force C:\\src",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::NoMatch,
            "U+2212 MINUS SIGN is argument data, not a PowerShell parameter dash",
        );
        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove-Item -Recurse -Force C:\\src −WhatIf",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Destructive("remove-item-recurse-force"),
            "U+2212 MINUS SIGN must not synthesize WhatIf preview safety",
        );
    }

    #[test]
    fn semantic_powershell_dynamic_switch_values_fail_closed() {
        for command in [
            "Remove-Item -Rec:$mode C:\\src",
            "Remove-Item -Rec:$mode -Fo:$true C:\\src",
            "Remove-Item -Rec:$true -Fo:$mode C:\\src",
            "Remove-Item -Rec: $mode -Fo: $true C:\\src",
            "Remove-Item -Rec:$(Get-Flag) -Fo:$true C:\\src",
            "Remove-Item -Rec:'$true' -Fo:$true C:\\src",
            "Rem$tail -Recurse C:\\src",
            "Remove-Item -Recurse -LiteralPath -$name",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Unverified,
                "runtime-dependent switch values must fail closed: {command}"
            );
            assert!(windows_filesystem_semantic_scan_required(
                command,
                ShellDialect::PowerShell,
            ));
        }
    }

    #[test]
    fn semantic_decoder_preserves_data_roles_and_whatif() {
        let harmless = [
            ("echo r^d /s C:\\src", ShellDialect::Cmd),
            ("echo d^el /s C:\\src", ShellDialect::Cmd),
            (
                "Write-Output Clear`-Content C:\\app\\server.log",
                ShellDialect::PowerShell,
            ),
            ("Write-Output Clear`-RecycleBin", ShellDialect::PowerShell),
            (
                "Remove-Item '-Re`curse' '-Fo`rce' C:\\src",
                ShellDialect::PowerShell,
            ),
            ("Remove`-Item -Fo`rce` C:\\src", ShellDialect::PowerShell),
            ("\"r^d\" /s C:\\src", ShellDialect::Cmd),
            ("d^el /s^ C:\\src", ShellDialect::Cmd),
            (
                "& 'Clear`-Content' C:\\app\\server.log",
                ShellDialect::PowerShell,
            ),
            (
                "& \"Write-Output\" Clear`-Content",
                ShellDialect::PowerShell,
            ),
            (
                "& ('Write'+'-Output') 'Clear-Content C:\\important.conf'",
                ShellDialect::PowerShell,
            ),
            (
                "& @('Write-Output')[0] 'Clear-Content C:\\important.conf'",
                ShellDialect::PowerShell,
            ),
            ("& \"@cmd\" report.txt", ShellDialect::PowerShell),
            (
                "$command = 'Clear-Content'; Write-Output $command",
                ShellDialect::PowerShell,
            ),
            (
                "${command-name} = 'Remove-Item'; ${command-name} -Recurse C:\\src",
                ShellDialect::PowerShell,
            ),
        ];
        for (command, dialect) in harmless {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, dialect),
                WindowsFilesystemSemanticDecision::NoMatch,
                "data must not be decoded into Windows filesystem syntax: {command}"
            );
            assert!(
                !windows_filesystem_semantic_scan_required(command, dialect),
                "data-only escapes must not force pack selection: {command}"
            );
        }

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Clear`-Content C:\\app\\server.log -What`If",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Safe
        );
        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Clear`-Content '-What`If'",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Destructive("clear-content")
        );
    }

    #[test]
    fn semantic_decoder_fails_closed_on_unresolved_destructive_roles() {
        for (command, dialect) in [
            ("d^el C:\\src /s^", ShellDialect::Cmd),
            ("f^ormat %DRIVE%: /q", ShellDialect::Cmd),
            ("f^ormat \"%DRIVE%:\" /q", ShellDialect::Cmd),
            ("d^el /? /s%MODE% C:\\src", ShellDialect::Cmd),
            ("Remove`-Item @parameters C:\\src", ShellDialect::PowerShell),
            ("& $command -Recurse C:\\src", ShellDialect::PowerShell),
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, dialect),
                WindowsFilesystemSemanticDecision::Unverified,
                "unresolved executable/option syntax must fail closed: {command}"
            );
            assert!(
                windows_filesystem_semantic_scan_required(command, dialect),
                "unresolved destructive syntax must override keyword candidate selection: {command}"
            );
        }

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "Remove`-Item -Re`curse C:\\src -Fo`rce`",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Unverified,
            "malformed Force syntax must fail closed instead of being assigned a concrete rule",
        );

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "& ('Clear' + '-Content') C:\\app\\server.log",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Destructive("clear-content"),
            "a bounded static call expression must resolve to its exact protected cmdlet",
        );

        for command in [
            "& @('Clear-Content')[$index] C:\\app\\server.log",
            "& @('Clear-Content')[0 + $offset] C:\\app\\server.log",
            "& ('Clear-Content')[0] C:\\app\\server.log",
        ] {
            assert_eq!(
                windows_filesystem_semantic_decision_in_dialect(command, ShellDialect::PowerShell,),
                WindowsFilesystemSemanticDecision::Unverified,
                "an index that does not preserve the decoded array executable must fail closed: {command}",
            );
            assert!(windows_filesystem_semantic_scan_required(
                command,
                ShellDialect::PowerShell,
            ));
        }

        assert_eq!(
            windows_filesystem_semantic_decision_in_dialect(
                "& @('Write-Output')[0] safe; Clear-Content C:\\important.conf",
                ShellDialect::PowerShell,
            ),
            WindowsFilesystemSemanticDecision::Destructive("clear-content"),
            "an inert call target must not hide a later destructive statement",
        );
    }
}

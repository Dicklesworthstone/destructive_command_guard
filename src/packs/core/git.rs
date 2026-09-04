//! Core git patterns - protections against destructive git commands.
//!
//! This includes patterns for:
//! - Work destruction (reset --hard, checkout --, restore)
//! - History rewriting (push --force, branch deletion/forced ref updates)
//! - Stash destruction (stash drop, stash clear)

use crate::normalize::{
    NormalizeTokenKind, ShellDialect, ShellTokenDecoder, ShellTokenRole, tokenize_for_shell_dialect,
};
use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};
use std::collections::{HashMap, HashSet};

const MAX_GIT_SEMANTIC_BYTES: usize = 64 * 1024;
const MAX_GIT_SEMANTIC_TOKENS: usize = 512;
const MAX_GIT_ALIAS_DEPTH: usize = 64;

pub(crate) const GIT_ALIAS_UNVERIFIED_RULE: &str = "git-alias-semantic-unverified";
pub(crate) const GIT_ALIAS_UNVERIFIED_REASON: &str = "The invoked Git alias depends on shell expansion, contains a cycle, or exceeds dcg's bounded semantic analysis.";
pub(crate) const BRANCH_DYNAMIC_RULE: &str = "branch-dynamic-token";
pub(crate) const BRANCH_DYNAMIC_REASON: &str = "A dynamic shell expansion in this git branch command can expand into a deletion or forced ref update. Quote the branch name or add `--` to make it a literal creation.";

/// A visible Git shell alias together with the arguments Git will append when
/// it invokes that alias. The shell body is deliberately not tokenized here:
/// shell aliases accept the complete shell grammar, which the evaluator must
/// inspect recursively in the caller-proven dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvokedGitShellAlias {
    pub(crate) shell_body: String,
    pub(crate) invoked_args: Vec<String>,
}

/// The exact Git argv produced by a non-shell alias chain. The evaluator
/// recursively checks `git <subcommand> <arguments...>` so aliases that expand
/// to destructive builtins do not disappear merely because the terminal word
/// is a known Git command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpandedGitAlias {
    pub(crate) subcommand: String,
    pub(crate) arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InvokedGitAliasDecision {
    NoMatch,
    Shell(InvokedGitShellAlias),
    Expanded(ExpandedGitAlias),
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BranchCommandDecision {
    NotBranch,
    NonDestructive,
    /// A literal deletion / force flag was proven (`-d`, `-D`, `--delete`,
    /// `-f`, `-M`, `-C`). Attributed to `branch-force-delete`.
    Destructive,
    /// The destructive verdict rests on an unresolvable dynamic word that
    /// *may* expand or field-split into a deletion / force flag (#274).
    /// Attributed to [`BRANCH_DYNAMIC_RULE`] so the denial explains the actual
    /// hazard and its safe remediations (quote the name, or add `--`).
    DestructiveDynamic,
    Unparsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchLongOptionArity {
    None,
    Required,
    OptionalAttached,
    LastArgDefault,
}

#[derive(Debug, Clone, Copy)]
struct BranchLongOptionSpec {
    name: &'static str,
    arity: BranchLongOptionArity,
    negatable: bool,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedBranchLongOption {
    name: &'static str,
    arity: BranchLongOptionArity,
    negated: bool,
    inline_value: bool,
}

const BRANCH_LONG_OPTIONS: &[BranchLongOptionSpec] = &[
    BranchLongOptionSpec {
        name: "abbrev",
        arity: BranchLongOptionArity::OptionalAttached,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "all",
        arity: BranchLongOptionArity::None,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "color",
        arity: BranchLongOptionArity::OptionalAttached,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "column",
        arity: BranchLongOptionArity::OptionalAttached,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "contains",
        arity: BranchLongOptionArity::LastArgDefault,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "no-contains",
        arity: BranchLongOptionArity::LastArgDefault,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "with",
        arity: BranchLongOptionArity::LastArgDefault,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "without",
        arity: BranchLongOptionArity::LastArgDefault,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "copy",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "create-reflog",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "delete",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "edit-description",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "force",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "format",
        arity: BranchLongOptionArity::Required,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "ignore-case",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "list",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "merged",
        arity: BranchLongOptionArity::LastArgDefault,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "no-merged",
        arity: BranchLongOptionArity::LastArgDefault,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "move",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "omit-empty",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "points-at",
        arity: BranchLongOptionArity::Required,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "quiet",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "recurse-submodules",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "remotes",
        arity: BranchLongOptionArity::None,
        negatable: false,
    },
    BranchLongOptionSpec {
        name: "set-upstream",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "set-upstream-to",
        arity: BranchLongOptionArity::Required,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "show-current",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "sort",
        arity: BranchLongOptionArity::Required,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "track",
        arity: BranchLongOptionArity::OptionalAttached,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "unset-upstream",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
    BranchLongOptionSpec {
        name: "verbose",
        arity: BranchLongOptionArity::None,
        negatable: true,
    },
];

fn resolve_branch_long_option(token: &str) -> Option<ResolvedBranchLongOption> {
    let option = token.strip_prefix("--")?;
    let (option, inline_value) = option
        .split_once('=')
        .map_or((option, false), |(name, _)| (name, true));
    if option.is_empty() || option.starts_with("no-no-") {
        return None;
    }

    let candidate = |spec: &'static BranchLongOptionSpec, negated| ResolvedBranchLongOption {
        name: spec.name,
        arity: spec.arity,
        negated,
        inline_value,
    };

    // Git gives exact long names precedence over abbreviations. This matters
    // for hidden `--set-upstream`, which is also a prefix of
    // `--set-upstream-to`.
    if let Some(spec) = BRANCH_LONG_OPTIONS.iter().find(|spec| spec.name == option) {
        return Some(candidate(spec, false));
    }
    if let Some(base) = option.strip_prefix("no-") {
        if let Some(spec) = BRANCH_LONG_OPTIONS
            .iter()
            .find(|spec| spec.negatable && spec.name == base)
        {
            return Some(candidate(spec, true));
        }
    }

    let mut matches = BRANCH_LONG_OPTIONS.iter().filter_map(|spec| {
        if spec.name.starts_with(option) {
            return Some(candidate(spec, false));
        }
        option.strip_prefix("no-").and_then(|base| {
            (spec.negatable && spec.name.starts_with(base)).then(|| candidate(spec, true))
        })
    });
    let resolved = matches.next()?;
    matches.next().is_none().then_some(resolved)
}

#[derive(Debug, Default, Clone, Copy)]
struct BranchMutationState {
    delete_bits: u8,
    force: bool,
    forced_move_or_copy: bool,
}

impl BranchMutationState {
    const fn decision(self) -> BranchCommandDecision {
        if self.delete_bits != 0 || self.force || self.forced_move_or_copy {
            BranchCommandDecision::Destructive
        } else {
            BranchCommandDecision::NonDestructive
        }
    }
}

#[inline]
pub(crate) fn contains_git_ascii_case_insensitive(command: &str) -> bool {
    command
        .as_bytes()
        .windows(3)
        .any(|window| window.eq_ignore_ascii_case(b"git"))
}

/// Return whether caller-proven shell syntax can hide a Git executable,
/// subcommand, or option from the raw keyword index.
///
/// This is a candidate-selection predicate only. It intentionally admits
/// dynamic expansions outside Git invocations; the role-aware semantic parser
/// remains authoritative about whether the command can execute Git and
/// whether a dynamic word occupies a destructive syntax role.
pub(crate) fn git_semantic_scan_required(command: &str, dialect: ShellDialect) -> bool {
    if dialect == ShellDialect::Unknown {
        return [
            ShellDialect::Posix,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
        ]
        .iter()
        .any(|dialect| git_semantic_scan_required(command, *dialect));
    }

    let dialect_obfuscation = match dialect {
        ShellDialect::Posix => command.contains("$'") || command.contains("$\""),
        ShellDialect::PowerShell => {
            command.contains('`') || powershell_dynamic_call_operator(command)
        }
        ShellDialect::Cmd => command.contains('^'),
        // The early branch currently expands Unknown across every supported
        // dialect. Keep this arm conservative as defense in depth so a future
        // control-flow refactor cannot turn untrusted input into a panic.
        ShellDialect::Unknown => true,
    };
    dialect_obfuscation
        || tokenize_for_shell_dialect(command, dialect)
            .iter()
            .filter(|token| token.kind == NormalizeTokenKind::Word)
            .filter_map(|token| token.text(command))
            .any(|raw| git_token_has_active_expansion(raw, dialect))
}

fn branch_tokens(command: &str, dialect: ShellDialect) -> Result<Vec<String>, ()> {
    if dialect == ShellDialect::Unknown {
        let normalized = crate::normalize::normalize_command(command);
        return shell_words::split(normalized.as_ref()).map_err(|_| ());
    }

    let stripped =
        (dialect == ShellDialect::Posix).then(|| crate::normalize::strip_wrapper_prefixes(command));
    let command = stripped
        .as_ref()
        .map_or(command, |result| result.normalized.as_ref());
    let raw_tokens = tokenize_for_shell_dialect(command, dialect);
    if raw_tokens
        .iter()
        .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return Err(());
    }

    raw_tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .map(|token| token.text(command).map(str::to_string).ok_or(()))
        .collect()
}

fn decode_branch_syntax(decoder: &mut ShellTokenDecoder, token: &str) -> Option<String> {
    decoder
        .decode(token, ShellTokenRole::Syntax)
        .map(std::borrow::Cow::into_owned)
}

const MAX_STATIC_SUBSTITUTION_BYTES: usize = 16 * 1024;
pub(crate) const POSIX_DYNAMIC_QUOTED: &str = "__DCG_POSIX_SUB_Q_7B8CFAE1__";
pub(crate) const POSIX_DYNAMIC_UNQUOTED: &str = "__DCG_POSIX_SUB_U_7B8CFAE1__";

/// Bounded matching-only view of POSIX command substitutions.
///
/// The evaluator consumes this read-only view only while resolving an
/// executable launcher command word; the original command remains
/// authoritative for decisions, logging, allowlists, and source spans.
pub(crate) struct PosixSubstitutionView {
    pub(crate) command: String,
    pub(crate) has_dynamic: bool,
}

/// Resolve the deliberately small, non-executing subset of POSIX command
/// substitution that can otherwise splice Git syntax across token boundaries.
///
/// Only deliberately narrow literal `printf` and `echo` invocations are
/// modeled. Shell operators, nested expansion, redirection, globbing,
/// non-literal arguments, and output that would be reinterpreted as shell
/// syntax are rejected. This is a matching view only: the original command
/// remains authoritative for logging, allowlists, and source spans.
fn resolve_literal_printf_substitutions(command: &str) -> Result<Option<String>, ()> {
    let view = posix_substitution_view(command)?;
    if view.has_dynamic {
        return Err(());
    }
    Ok((view.command != command).then_some(view.command))
}

pub(crate) fn posix_substitution_view(command: &str) -> Result<PosixSubstitutionView, ()> {
    if command.contains(POSIX_DYNAMIC_QUOTED) || command.contains(POSIX_DYNAMIC_UNQUOTED) {
        return Err(());
    }
    let bytes = command.as_bytes();
    let mut output = String::with_capacity(command.len());
    let mut index = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut changed = false;
    let mut has_dynamic = false;

    while index < bytes.len() {
        match bytes[index] {
            b'\\' if !in_single => {
                let next = index.saturating_add(2).min(bytes.len());
                output.push_str(command.get(index..next).ok_or(())?);
                index = next;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
                output.push('\'');
                index += 1;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                output.push('"');
                index += 1;
            }
            b'$' if !in_single && bytes.get(index + 1) == Some(&b'(') => {
                let close = find_posix_substitution_close(command, index + 2, b')')?;
                match render_static_producer_body(
                    command.get(index + 2..close).ok_or(())?,
                    in_double,
                ) {
                    Ok(rendered) => output.push_str(&rendered),
                    Err(()) => {
                        output.push_str(if in_double {
                            POSIX_DYNAMIC_QUOTED
                        } else {
                            POSIX_DYNAMIC_UNQUOTED
                        });
                        has_dynamic = true;
                    }
                }
                index = close + 1;
                changed = true;
            }
            b'`' if !in_single => {
                let close = find_posix_substitution_close(command, index + 1, b'`')?;
                match render_static_producer_body(
                    command.get(index + 1..close).ok_or(())?,
                    in_double,
                ) {
                    Ok(rendered) => output.push_str(&rendered),
                    Err(()) => {
                        output.push_str(if in_double {
                            POSIX_DYNAMIC_QUOTED
                        } else {
                            POSIX_DYNAMIC_UNQUOTED
                        });
                        has_dynamic = true;
                    }
                }
                index = close + 1;
                changed = true;
            }
            _ => {
                let ch = command
                    .get(index..)
                    .and_then(|tail| tail.chars().next())
                    .ok_or(())?;
                output.push(ch);
                index += ch.len_utf8();
            }
        }
        if output.len() > MAX_STATIC_SUBSTITUTION_BYTES {
            return Err(());
        }
    }

    Ok(PosixSubstitutionView {
        command: if changed { output } else { command.to_string() },
        has_dynamic,
    })
}

fn find_posix_substitution_close(command: &str, start: usize, delimiter: u8) -> Result<usize, ()> {
    let bytes = command.as_bytes();
    let mut index = start;
    let mut depth = usize::from(delimiter == b')');
    let mut in_single = false;
    let mut in_double = false;

    while index < bytes.len() {
        match bytes[index] {
            b'\\' if !in_single => index = index.saturating_add(2),
            b'\'' if !in_double => {
                in_single = !in_single;
                index += 1;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                index += 1;
            }
            b'`' if delimiter == b'`' && !in_single => return Ok(index),
            b'(' if delimiter == b')' && !in_single && !in_double => {
                depth = depth.saturating_add(1);
                index += 1;
            }
            b')' if delimiter == b')' && !in_single && !in_double => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(index);
                }
                index += 1;
            }
            _ => {
                index += command
                    .get(index..)
                    .and_then(|tail| tail.chars().next())
                    .map_or(1, char::len_utf8);
            }
        }
    }
    Err(())
}

fn render_static_producer_body(body: &str, _in_double_quotes: bool) -> Result<String, ()> {
    if body.len() > MAX_STATIC_SUBSTITUTION_BYTES
        || body.bytes().any(|byte| {
            matches!(
                byte,
                b'$' | b'`'
                    | b';'
                    | b'|'
                    | b'&'
                    | b'<'
                    | b'>'
                    | b'('
                    | b')'
                    | b'*'
                    | b'?'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
                    | b'~'
                    | b'\n'
                    | b'\r'
                    | 0
            )
        })
    {
        return Err(());
    }

    let mut words = shell_words::split(body).map_err(|_| ())?;
    if words.is_empty() {
        return Err(());
    }
    let producer = words.remove(0);
    let rendered = match producer.as_str() {
        "printf" => {
            if words.first().is_some_and(|word| word == "--") {
                words.remove(0);
            }
            crate::evaluator::render_literal_printf(&words).ok_or(())?
        }
        // `echo` varies across shells once options or backslash escapes enter
        // the picture. Model only the portable literal subset. Command
        // substitution removes trailing newlines, so joining the literal
        // operands exactly reproduces the value that can become an executable
        // word without relying on implementation-specific echo behavior.
        "echo"
            if words.first().is_none_or(|word| !word.starts_with('-'))
                && words.iter().all(|word| !word.contains('\\')) =>
        {
            words.join(" ")
        }
        _ => return Err(()),
    };
    let rendered = rendered.trim_end_matches('\n');
    if rendered.len() > MAX_STATIC_SUBSTITUTION_BYTES
        || !rendered.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte.is_ascii_whitespace()
                || matches!(
                    byte,
                    b'_' | b'.' | b'/' | b':' | b'+' | b',' | b'=' | b'@' | b'%' | b'-'
                )
        })
    {
        return Err(());
    }

    // The accepted output alphabet contains no characters that are active
    // inside POSIX double quotes, so it can be inserted verbatim there. In an
    // unquoted word, literal whitespace intentionally reproduces field
    // splitting while the restricted alphabet prevents shell re-parsing.
    Ok(rendered.to_string())
}

#[derive(Clone)]
struct SymbolicPosixWord {
    text: String,
    unquoted_dynamic: bool,
}

impl SymbolicPosixWord {
    fn exact(&self) -> Option<&str> {
        (!self.is_dynamic()).then_some(self.text.as_str())
    }

    fn is_dynamic(&self) -> bool {
        self.text.contains(POSIX_DYNAMIC_QUOTED) || self.text.contains(POSIX_DYNAMIC_UNQUOTED)
    }

    /// Whether the word carries any literal bytes at all. A word made up
    /// entirely of substitution sentinels could expand to anything, so it
    /// provides no evidence that this command involves Git (#281).
    fn has_literal_fragment(&self) -> bool {
        self.text
            .replace(POSIX_DYNAMIC_QUOTED, POSIX_DYNAMIC_UNQUOTED)
            .split(POSIX_DYNAMIC_UNQUOTED)
            .any(|fragment| !fragment.is_empty())
    }

    fn may_equal(&self, candidate: &str) -> bool {
        if !self.is_dynamic() {
            return self.text == candidate;
        }
        let normalized = self
            .text
            .replace(POSIX_DYNAMIC_QUOTED, POSIX_DYNAMIC_UNQUOTED);
        let fragments: Vec<_> = normalized.split(POSIX_DYNAMIC_UNQUOTED).collect();
        let Some(first) = fragments.first() else {
            return false;
        };
        let Some(last) = fragments.last() else {
            return false;
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
            let Some(relative) = candidate.get(offset..).and_then(|tail| tail.find(fragment))
            else {
                return false;
            };
            offset += relative + fragment.len();
        }
        offset <= candidate.len().saturating_sub(last.len())
    }
}

fn symbolic_posix_words(view: &PosixSubstitutionView) -> Result<Vec<SymbolicPosixWord>, ()> {
    shell_words::split(&view.command)
        .map_err(|_| ())
        .map(|words| {
            words
                .into_iter()
                .map(|text| SymbolicPosixWord {
                    unquoted_dynamic: text.contains(POSIX_DYNAMIC_UNQUOTED),
                    text,
                })
                .collect()
        })
}

fn symbolic_data_word_is_safe(word: &SymbolicPosixWord) -> bool {
    !word.unquoted_dynamic
}

fn symbolic_branch_option_may_mutate(word: &SymbolicPosixWord) -> bool {
    ["-d", "-D", "-f", "-M", "-C", "--delete", "--force"]
        .iter()
        .any(|candidate| word.may_equal(candidate))
}

/// Whether the literal words of a symbolic argv tail prove a branch
/// delete/force mutation. Used when unknown expansions occupy the executable
/// and subcommand slots (#281): the unknowns supply no Git evidence, but a
/// literal `-D` / `--delete` / `--force` after them still names a destructive
/// branch operation in plain sight, so it must not be discarded (#283-review).
fn literal_argv_proves_branch_mutation(words: &[SymbolicPosixWord]) -> bool {
    literal_branch_tokens_prove_mutation(words.iter().map(SymbolicPosixWord::exact))
}

/// Shared literal-evidence scan behind [`literal_argv_proves_branch_mutation`]
/// and its `GitSemanticWord` counterpart. `None` marks a dynamic word, which
/// contributes no evidence but does not stop the scan.
fn literal_branch_tokens_prove_mutation<'a>(tokens: impl Iterator<Item = Option<&'a str>>) -> bool {
    let mut mutation = BranchMutationState::default();
    for token in tokens {
        let Some(token) = token else {
            continue;
        };
        if matches!(token, "--" | "--end-of-options") {
            break;
        }
        if token.starts_with("--") {
            let Some(resolved) = resolve_branch_long_option(token) else {
                continue;
            };
            if resolved.inline_value && matches!(resolved.arity, BranchLongOptionArity::None) {
                continue;
            }
            match resolved.name {
                "delete" if resolved.negated => mutation.delete_bits &= !1,
                "delete" => mutation.delete_bits |= 1,
                "force" => mutation.force = !resolved.negated,
                _ => {}
            }
            continue;
        }
        if let Some(flags) = token.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            for flag in flags.chars() {
                match flag {
                    'd' => mutation.delete_bits |= 1,
                    'D' => mutation.delete_bits |= 2,
                    'f' => mutation.force = true,
                    'M' | 'C' => mutation.forced_move_or_copy = true,
                    // `-u<upstream>` and `-t<start>` consume their attached
                    // remainder as data, not as further short flags.
                    'u' | 't' => break,
                    _ => {}
                }
            }
        }
    }
    matches!(mutation.decision(), BranchCommandDecision::Destructive)
}

fn sole_posix_branch_name_query(command: &str) -> bool {
    let command = command.trim();
    let body = if let Some(body) = command
        .strip_prefix('`')
        .and_then(|body| body.strip_suffix('`'))
    {
        body
    } else if let Some(body) = command
        .strip_prefix("$(")
        .and_then(|body| body.strip_suffix(')'))
    {
        body
    } else {
        return false;
    };
    let Ok(words) = shell_words::split(body) else {
        return false;
    };
    matches!(
        words.as_slice(),
        [git, branch, show_current]
            if git.eq_ignore_ascii_case("git")
                && branch == "branch"
                && show_current == "--show-current"
    )
}

fn decoded_words_execute_git(words: &[String]) -> bool {
    for word in words {
        if crate::normalize::is_env_assignment(word)
            || matches!(word.as_str(), "exec" | "time" | "nohup" | "!")
        {
            continue;
        }
        let Some(mut executable) = word.rsplit(['/', '\\']).next() else {
            return false;
        };
        if executable
            .get(executable.len().saturating_sub(4)..)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
        {
            executable = executable
                .get(..executable.len().saturating_sub(4))
                .unwrap_or(executable);
        }
        return executable.eq_ignore_ascii_case("git")
            || executable.eq_ignore_ascii_case("git-branch");
    }
    false
}

fn next_posix_prefix_token(
    segment: &str,
    tokens: &[crate::normalize::NormalizeToken],
    mut index: usize,
) -> Option<usize> {
    while let Some(token) = tokens.get(index) {
        let raw = token.text(segment)?;
        if token.kind == NormalizeTokenKind::Word && matches!(raw, "\\\n" | "\\\r\n") {
            index += 1;
            continue;
        }
        return Some(index);
    }
    None
}

fn posix_compound_command_opener(
    segment: &str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
) -> bool {
    let Some(token) = tokens.get(index) else {
        return false;
    };
    let Some(raw) = token.text(segment) else {
        return false;
    };
    match token.kind {
        NormalizeTokenKind::Separator => raw == "(",
        NormalizeTokenKind::Word => matches!(
            raw,
            "{" | "if" | "while" | "until" | "for" | "select" | "case"
        ),
    }
}

fn posix_command_after_compound_opener<'a>(
    segment: &'a str,
    tokens: &[crate::normalize::NormalizeToken],
    opener_index: usize,
) -> Option<(&'a str, usize)> {
    let opener = tokens.get(opener_index)?;
    let raw = opener.text(segment)?;
    if matches!(raw, "{" | "(") {
        let body_index = next_posix_prefix_token(segment, tokens, opener_index + 1)?;
        let start = tokens.get(body_index)?.byte_range.start;
        return Some((&segment[start..], start));
    }
    let start = opener.byte_range.start;
    Some((&segment[start..], start))
}

fn first_literal_posix_git_token_offset(segment: &str) -> Option<usize> {
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::Posix);
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
    tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .find_map(|token| {
            let raw = token.text(segment)?;
            let decoded = decoder.decode(raw, ShellTokenRole::Syntax)?;
            let executable = decoded.rsplit(['/', '\\']).next()?;
            matches!(
                executable,
                "git" | "git.exe" | "git-branch" | "git-branch.exe"
            )
            .then_some(token.byte_range.start)
        })
}

fn command_after_posix_function_prefix<'a>(
    segment: &'a str,
    tokens: &[crate::normalize::NormalizeToken],
    function_index: usize,
) -> Option<(&'a str, usize)> {
    let name_index = next_posix_prefix_token(segment, tokens, function_index + 1)?;
    if tokens.get(name_index)?.kind != NormalizeTokenKind::Word {
        return None;
    }

    let mut opener_index = next_posix_prefix_token(segment, tokens, name_index + 1)?;
    if tokens.get(opener_index)?.text(segment) == Some("(") {
        let following_index = next_posix_prefix_token(segment, tokens, opener_index + 1)?;
        if tokens.get(following_index)?.text(segment) == Some(")") {
            opener_index = next_posix_prefix_token(segment, tokens, following_index + 1)?;
        }
    }
    if !posix_compound_command_opener(segment, tokens, opener_index) {
        return None;
    }
    posix_command_after_compound_opener(segment, tokens, opener_index)
}

fn command_after_posix_coproc_prefix<'a>(
    segment: &'a str,
    tokens: &[crate::normalize::NormalizeToken],
    coproc_index: usize,
) -> Option<(&'a str, usize)> {
    let candidate_index = next_posix_prefix_token(segment, tokens, coproc_index + 1)?;
    if posix_compound_command_opener(segment, tokens, candidate_index) {
        return posix_command_after_compound_opener(segment, tokens, candidate_index);
    }
    if tokens.get(candidate_index)?.kind != NormalizeTokenKind::Word {
        return None;
    }

    // Bash accepts a coprocess name only when a compound command follows it:
    // `coproc JOB { command; }` and `coproc JOB if ...; then ...; fi`.
    // Without that opener, the candidate itself is the executable, as in
    // `coproc git reset --hard`.
    if let Some(opener_index) = next_posix_prefix_token(segment, tokens, candidate_index + 1)
        && posix_compound_command_opener(segment, tokens, opener_index)
    {
        return posix_command_after_compound_opener(segment, tokens, opener_index);
    }

    let start = tokens.get(candidate_index)?.byte_range.start;
    Some((&segment[start..], start))
}

/// Return the executable portion of one separator-delimited POSIX segment.
///
/// Shell control-flow reserved words can share a segment with the command they
/// introduce (`then git ...`, `do git ...`, `{ git ...`, or `coproc git ...`).
/// Bash function declarations and named compound coprocesses also place
/// syntax before their executable body. Exact raw-token matching deliberately
/// leaves quoted words, paths, and spellings selected through
/// `command`/`env`/`sudo` untouched.
///
/// The offset is relative to `segment` and lets evaluator diagnostics map a
/// match in the returned slice back to the original command.
pub(crate) fn command_after_posix_control_prefixes(
    segment: &str,
    dialect: ShellDialect,
) -> (&str, usize) {
    command_after_posix_control_prefixes_bounded(segment, dialect, 0)
}

fn command_after_posix_control_prefixes_bounded(
    segment: &str,
    dialect: ShellDialect,
    nesting_depth: usize,
) -> (&str, usize) {
    if dialect != ShellDialect::Posix {
        return (segment, 0);
    }
    const MAX_STRUCTURAL_PREFIX_NESTING: usize = 64;
    if nesting_depth >= MAX_STRUCTURAL_PREFIX_NESTING {
        // Fail closed for the only command family this parser owns. Returning
        // another declaration prefix here would make the later executable
        // parser classify `function` rather than a deeply nested Git body.
        // The conservative textual fallback is reached only after 64 valid
        // structural layers, where avoiding an unbounded recursion is more
        // important than preserving data-only Git text.
        if let Some(git_offset) = first_literal_posix_git_token_offset(segment) {
            return (&segment[git_offset..], git_offset);
        }
        return (segment, 0);
    }

    // Direct Git invocations dominate this hot path. Avoid a second shell
    // tokenization unless the first raw word can actually be an unquoted
    // control prefix. Peel only line continuations here; the tokenizer below
    // remains authoritative for quoting and exact byte offsets.
    let mut prefix_probe = segment.trim_start();
    loop {
        if let Some(rest) = prefix_probe.strip_prefix("\\\r\n") {
            prefix_probe = rest.trim_start();
        } else if let Some(rest) = prefix_probe.strip_prefix("\\\n") {
            prefix_probe = rest.trim_start();
        } else {
            break;
        }
    }
    if !prefix_probe.split_whitespace().next().is_some_and(|word| {
        crate::context::is_shell_command_prefix_reserved_word(word) || word == "function"
    }) {
        return (segment, 0);
    }

    let tokens = tokenize_for_shell_dialect(segment, dialect);
    let mut stripped_reserved_word = false;
    let mut token_index = next_posix_prefix_token(segment, &tokens, 0);
    while let Some(index) = token_index {
        let Some(token) = tokens.get(index) else {
            return (segment, 0);
        };
        if token.kind != NormalizeTokenKind::Word {
            return (segment, 0);
        }
        let Some(raw) = token.text(segment) else {
            return (segment, 0);
        };

        if raw == "function" {
            let Some((body, offset)) = command_after_posix_function_prefix(segment, &tokens, index)
            else {
                return (segment, 0);
            };
            if body.is_empty() {
                return (body, offset);
            }
            let (command, nested_offset) = command_after_posix_control_prefixes_bounded(
                body,
                ShellDialect::Posix,
                nesting_depth + 1,
            );
            return (command, offset.saturating_add(nested_offset));
        }
        if raw == "coproc" {
            let Some((body, offset)) = command_after_posix_coproc_prefix(segment, &tokens, index)
            else {
                return (segment, 0);
            };
            if body.is_empty() {
                return (body, offset);
            }
            let (command, nested_offset) = command_after_posix_control_prefixes_bounded(
                body,
                ShellDialect::Posix,
                nesting_depth + 1,
            );
            return (command, offset.saturating_add(nested_offset));
        }

        let command_prefix = if stripped_reserved_word {
            matches!(raw, "if" | "while" | "until" | "{" | "!")
        } else {
            crate::context::is_shell_command_prefix_reserved_word(raw)
        };
        if command_prefix {
            stripped_reserved_word = true;
            token_index = next_posix_prefix_token(segment, &tokens, index + 1);
            continue;
        }
        if stripped_reserved_word && crate::context::is_shell_command_prefix_reserved_word(raw) {
            // This is not a valid nested command prefix (`then else ...`,
            // `do then ...`, and similar forms are syntax errors). Return the
            // original segment so repeated semantic layers cannot peel one
            // invalid reserved word at a time and expose inert trailing text.
            return (segment, 0);
        }
        if stripped_reserved_word {
            let start = token.byte_range.start;
            return (&segment[start..], start);
        }
        return (segment, 0);
    }

    if stripped_reserved_word {
        (&segment[segment.len()..], segment.len())
    } else {
        (segment, 0)
    }
}

fn semantic_git_executable_index(
    words: &[GitSemanticWord],
    dialect: ShellDialect,
) -> Option<usize> {
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        if crate::normalize::is_env_assignment(&word.decoded) {
            index += 1;
            continue;
        }
        if dialect == ShellDialect::Cmd {
            let executable = word.decoded.trim_start_matches('@');
            if !word.dynamic && (executable.is_empty() || executable.eq_ignore_ascii_case("call")) {
                index += 1;
                continue;
            }
        }
        if !word.dynamic && matches!(word.decoded.as_str(), "exec" | "time" | "nohup" | "!") {
            index += 1;
            continue;
        }
        return (git_semantic_executable_may_equal(word, dialect, "git")
            || git_semantic_executable_may_equal(word, dialect, "git.exe")
            || git_semantic_executable_may_equal(word, dialect, "git-branch")
            || git_semantic_executable_may_equal(word, dialect, "git-branch.exe"))
        .then_some(index);
    }
    None
}

fn symbolic_posix_may_execute_git(command: &str) -> bool {
    let stripped = crate::normalize::strip_wrapper_prefixes(command);
    let command = stripped.normalized.as_ref();
    let Ok(view) = posix_substitution_view(command) else {
        return true;
    };
    let Ok(words) = symbolic_posix_words(&view) else {
        return true;
    };
    let mut scan_all_remaining = false;
    for word in words {
        if !scan_all_remaining {
            if let Some(exact) = word.exact() {
                if crate::normalize::is_env_assignment(exact)
                    || matches!(exact, "exec" | "time" | "nohup" | "!")
                {
                    continue;
                }
            }
        }
        let basename = SymbolicPosixWord {
            text: word
                .text
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&word.text)
                .to_string(),
            unquoted_dynamic: word.unquoted_dynamic,
        };
        if basename.may_equal("git")
            || basename.may_equal("git.exe")
            || basename.may_equal("git-branch")
            || basename.may_equal("git-branch.exe")
        {
            return true;
        }
        if scan_all_remaining {
            continue;
        }
        // #260: the wrapper strip already ran above, so a first word that is
        // still a known execution frontend means the strip BAILED (dynamic
        // option value, unmodeled flag). The wrapped command still executes
        // at runtime; keep scanning the remaining words for a possible Git
        // executable so the ordinary regex rules run (deny-direction only —
        // genuinely unknown programs keep the documented argv-data default).
        if word
            .exact()
            .map(|exact| exact.rsplit(['/', '\\']).next().unwrap_or(exact))
            .is_some_and(crate::normalize::is_posix_execution_frontend_basename)
        {
            scan_all_remaining = true;
            continue;
        }
        return false;
    }
    false
}

#[derive(Debug, Clone)]
struct GitSemanticWord {
    decoded: String,
    dynamic: bool,
    may_split: bool,
}

#[derive(Debug)]
struct DecodedGitWords {
    words: Vec<GitSemanticWord>,
    over_limit: bool,
}

#[derive(Debug, Clone)]
struct EnvironmentValue {
    value: String,
    dynamic: bool,
}

#[derive(Debug, Clone)]
enum VisibleAliasValue {
    Static(String),
    Dynamic,
}

#[derive(Debug, Clone)]
struct VisibleAliasDefinition {
    /// `None` means that expansion can choose the alias name.
    name: Option<String>,
    value: VisibleAliasValue,
}

/// Whether the text following a `{` can brace-expand.
///
/// POSIX-family shells expand a brace group only when it closes in the same
/// word and contains a `,` alternative or a `..` sequence — `{}` (xargs's
/// conventional replacement token) and `{word}` are literal text.
fn posix_brace_remainder_may_expand(remainder: &str) -> bool {
    remainder.find('}').is_some_and(|close| {
        let inner = &remainder[..close];
        inner.contains(',') || inner.contains("..")
    })
}

fn git_token_has_active_expansion(raw: &str, dialect: ShellDialect) -> bool {
    match dialect {
        ShellDialect::Posix | ShellDialect::Unknown => {
            let mut chars = raw.char_indices().peekable();
            let mut single = false;
            let mut double = false;
            while let Some((index, ch)) = chars.next() {
                match ch {
                    '\\' if !single => {
                        chars.next();
                    }
                    '\'' if !double => single = !single,
                    '"' if !single => double = !double,
                    '$' if !single && !matches!(chars.peek(), Some((_, '\'' | '"'))) => {
                        return true;
                    }
                    '`' if !single => return true,
                    '*' | '?' if !single && !double => return true,
                    // A bracket or brace expression only expands when its
                    // closing delimiter appears later in the same word. A lone
                    // `[` or `[[` is the literal POSIX test builtin, and a
                    // lone `{` is the compound-command reserved word; neither
                    // can glob-expand into a different executable. Brace
                    // groups additionally need a `,`/`..` inside — `{}` and
                    // `{word}` are literal.
                    '[' if !single && !double && raw[index + ch.len_utf8()..].contains(']') => {
                        return true;
                    }
                    '{' if !single
                        && !double
                        && posix_brace_remainder_may_expand(&raw[index + ch.len_utf8()..]) =>
                    {
                        return true;
                    }
                    '<' | '>' if !single && matches!(chars.peek(), Some((_, '('))) => return true,
                    _ => {}
                }
            }
            false
        }
        ShellDialect::PowerShell => {
            let mut chars = raw.chars().peekable();
            let mut single = false;
            let mut double = false;
            while let Some(ch) = chars.next() {
                match ch {
                    '`' if !single => {
                        chars.next();
                    }
                    '\'' if !double => single = !single,
                    '"' if !single => double = !double,
                    '$' if !single => return true,
                    '@' if !single && chars.peek() == Some(&'(') => return true,
                    _ => {}
                }
            }
            false
        }
        ShellDialect::Cmd => {
            let bytes = raw.as_bytes();
            bytes
                .iter()
                .position(|byte| *byte == b'%')
                .is_some_and(|start| {
                    bytes.get(start + 1).is_some_and(|next| {
                        next.is_ascii_digit()
                            || matches!(*next, b'*' | b'~')
                            || bytes
                                .get(start + 2..)
                                .is_some_and(|tail| tail.contains(&b'%'))
                    })
                })
                || bytes
                    .iter()
                    .position(|byte| *byte == b'!')
                    .is_some_and(|start| {
                        bytes
                            .get(start + 1..)
                            .is_some_and(|tail| tail.contains(&b'!'))
                    })
        }
    }
}

fn git_token_expansion_may_split(raw: &str, dialect: ShellDialect) -> bool {
    match dialect {
        ShellDialect::Posix | ShellDialect::Unknown => {
            let mut chars = raw.char_indices().peekable();
            let mut single = false;
            let mut double = false;
            while let Some((index, ch)) = chars.next() {
                match ch {
                    '\\' if !single => {
                        chars.next();
                    }
                    '\'' if !double => single = !single,
                    '"' if !single => double = !double,
                    '$' | '`' | '*' | '?' if !single && !double => return true,
                    // See `git_token_has_active_expansion`: `[`/`{` without a
                    // later closing delimiter in the same word are literal,
                    // and brace groups additionally need a `,`/`..` inside.
                    '[' if !single && !double && raw[index + ch.len_utf8()..].contains(']') => {
                        return true;
                    }
                    '{' if !single
                        && !double
                        && posix_brace_remainder_may_expand(&raw[index + ch.len_utf8()..]) =>
                    {
                        return true;
                    }
                    '<' | '>' if !single && !double && matches!(chars.peek(), Some((_, '('))) => {
                        return true;
                    }
                    _ => {}
                }
            }
        }
        // Native-command expansion can produce more than one argv element in
        // both PowerShell (arrays) and Cmd (expanded whitespace). Expansion
        // inside double quotes is one native-command argument, however.
        ShellDialect::PowerShell | ShellDialect::Cmd => {
            let mut chars = raw.chars().peekable();
            let mut single = false;
            let mut double = false;
            while let Some(ch) = chars.next() {
                match (dialect, ch) {
                    (ShellDialect::PowerShell, '`') if !single => {
                        chars.next();
                    }
                    (_, '\'') if !double => single = !single,
                    (_, '"') if !single => double = !double,
                    (ShellDialect::PowerShell, '$') if !single && !double => return true,
                    (ShellDialect::PowerShell, '@')
                        if !single && !double && chars.peek() == Some(&'(') =>
                    {
                        return true;
                    }
                    (ShellDialect::Cmd, '%' | '!') if !double => return true,
                    _ => {}
                }
            }
        }
    }
    false
}

fn git_dynamic_fragments(decoded: &str, dialect: ShellDialect) -> Vec<String> {
    let mut fragments = vec![String::new()];
    let chars: Vec<char> = decoded.chars().collect();
    let mut index = 0usize;
    let mut dynamic = false;
    while index < chars.len() {
        let starts_dynamic = match dialect {
            ShellDialect::Posix | ShellDialect::Unknown => match chars[index] {
                '$' | '`' | '*' | '?' => true,
                // A `[`/`{` with no later closing delimiter in the word is
                // literal (the test builtin / brace reserved word) and must
                // contribute a literal fragment rather than a wildcard. Brace
                // groups additionally need a `,`/`..` inside to expand.
                '[' => chars[index + 1..].contains(&']'),
                '{' => {
                    let remainder = &chars[index + 1..];
                    remainder
                        .iter()
                        .position(|&c| c == '}')
                        .is_some_and(|close| {
                            let inner = &remainder[..close];
                            inner.contains(&',') || inner.windows(2).any(|pair| pair == ['.', '.'])
                        })
                }
                _ => false,
            },
            ShellDialect::PowerShell => {
                chars[index] == '$' || chars[index] == '@' && chars.get(index + 1) == Some(&'(')
            }
            ShellDialect::Cmd => matches!(chars[index], '%' | '!'),
        };
        if !starts_dynamic {
            fragments.last_mut().expect("seeded").push(chars[index]);
            index += 1;
            continue;
        }

        dynamic = true;
        fragments.push(String::new());
        match (dialect, chars[index]) {
            (ShellDialect::Posix | ShellDialect::Unknown, '$')
            | (ShellDialect::PowerShell, '$') => {
                index += 1;
                if matches!(chars.get(index), Some('{' | '(')) {
                    let open = chars[index];
                    let close = if open == '{' { '}' } else { ')' };
                    index += 1;
                    let mut depth = 1usize;
                    while index < chars.len() && depth > 0 {
                        if chars[index] == open {
                            depth += 1;
                        } else if chars[index] == close {
                            depth -= 1;
                        }
                        index += 1;
                    }
                } else {
                    while index < chars.len()
                        && (chars[index].is_ascii_alphanumeric()
                            || matches!(chars[index], '_' | ':' | '?' | '*' | '#' | '@' | '-'))
                    {
                        index += 1;
                    }
                }
            }
            (ShellDialect::PowerShell, '@') => {
                index += 2;
                let mut depth = 1usize;
                while index < chars.len() && depth > 0 {
                    if chars[index] == '(' {
                        depth += 1;
                    } else if chars[index] == ')' {
                        depth -= 1;
                    }
                    index += 1;
                }
            }
            (ShellDialect::Posix | ShellDialect::Unknown, '`') => {
                index += 1;
                while index < chars.len() && chars[index] != '`' {
                    index += 1;
                }
                index += usize::from(index < chars.len());
            }
            (ShellDialect::Posix | ShellDialect::Unknown, '[') => {
                index += 1;
                while index < chars.len() && chars[index] != ']' {
                    index += 1;
                }
                index += usize::from(index < chars.len());
            }
            (ShellDialect::Posix | ShellDialect::Unknown, '{') => {
                index += 1;
                while index < chars.len() && chars[index] != '}' {
                    index += 1;
                }
                index += usize::from(index < chars.len());
            }
            (ShellDialect::Posix | ShellDialect::Unknown, '*' | '?') => index += 1,
            (ShellDialect::Cmd, delimiter @ ('%' | '!')) => {
                index += 1;
                if delimiter == '%' && chars.get(index).is_some_and(char::is_ascii_digit) {
                    index += 1;
                } else {
                    while index < chars.len() && chars[index] != delimiter {
                        index += 1;
                    }
                    index += usize::from(index < chars.len());
                }
            }
            _ => index += 1,
        }
    }
    if dynamic {
        fragments
    } else {
        vec![decoded.to_string()]
    }
}

fn git_symbolic_word_may_equal(
    word: &GitSemanticWord,
    dialect: ShellDialect,
    candidate: &str,
    ascii_case_insensitive: bool,
) -> bool {
    if !word.dynamic {
        return if ascii_case_insensitive {
            word.decoded.eq_ignore_ascii_case(candidate)
        } else {
            word.decoded == candidate
        };
    }
    let decoded = if ascii_case_insensitive {
        word.decoded.to_ascii_lowercase()
    } else {
        word.decoded.clone()
    };
    let candidate = if ascii_case_insensitive {
        candidate.to_ascii_lowercase()
    } else {
        candidate.to_string()
    };
    let fragments = git_dynamic_fragments(&decoded, dialect);
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

/// Whether a dynamic word consists solely of expansions with no literal bytes.
/// Such a word could expand to anything, so it supplies no evidence that the
/// command involves Git; per the #273 precedent (`"$X" "$Y"` is an unknown
/// program), an unquoted `$X $Y` must not be attributed to a `core.git` rule
/// on its own (#281).
fn git_semantic_word_is_unbounded(word: &GitSemanticWord, dialect: ShellDialect) -> bool {
    word.dynamic
        && git_dynamic_fragments(&word.decoded, dialect)
            .iter()
            .all(String::is_empty)
}

/// Reduce an executable word to the view that actually names the program: the
/// basename after the final path separator, with `dynamic` re-derived from the
/// basename's own fragments rather than inherited from the full word.
///
/// The program name is the basename, so every question a `core.git` gate asks
/// about the executable ("could this be `git`?", "does this carry any literal
/// evidence?") must be answered against the basename alone. Carrying the whole
/// word's `dynamic` flag over gets both directions wrong (#360, #361):
/// a glob in a *directory* component (`/usr/*/git`) left a fully literal `git`
/// basename flagged dynamic, and a glob *basename* (`/*`) borrowed the literal
/// `/` separator as the evidence a pure expansion is defined not to have.
fn git_semantic_executable_basename(
    word: &GitSemanticWord,
    dialect: ShellDialect,
) -> GitSemanticWord {
    let decoded = if dialect == ShellDialect::Cmd {
        word.decoded.trim_start_matches('@')
    } else {
        &word.decoded
    };
    let basename = decoded.rsplit(['/', '\\']).next().unwrap_or(decoded);
    // A basename that splits into a single fragment is wholly literal text;
    // only an expansion *inside the basename itself* keeps the word dynamic.
    let basename_dynamic = word.dynamic && git_dynamic_fragments(basename, dialect).len() > 1;
    GitSemanticWord {
        decoded: basename.to_string(),
        dynamic: basename_dynamic,
        may_split: word.may_split,
    }
}

fn git_semantic_executable_may_equal(
    word: &GitSemanticWord,
    dialect: ShellDialect,
    candidate: &str,
) -> bool {
    let word = git_semantic_executable_basename(word, dialect);
    git_symbolic_word_may_equal(&word, dialect, candidate, true)
}

/// [`git_semantic_word_is_unbounded`], judged on the executable-name view. The
/// path separator says nothing about which program the basename resolves to,
/// so `/*` supplies exactly as little Git evidence as a bare `*` (#360).
fn git_semantic_executable_is_unbounded(word: &GitSemanticWord, dialect: ShellDialect) -> bool {
    git_semantic_word_is_unbounded(&git_semantic_executable_basename(word, dialect), dialect)
}

fn decode_git_semantic_words(command: &str, dialect: ShellDialect) -> Option<DecodedGitWords> {
    let tokens = tokenize_for_shell_dialect(command, dialect);
    if tokens
        .iter()
        .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return None;
    }
    let over_limit = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .count()
        > MAX_GIT_SEMANTIC_TOKENS;
    let mut decoder = ShellTokenDecoder::new(dialect);
    let mut powershell_literal = false;
    let words = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .take(MAX_GIT_SEMANTIC_TOKENS)
        .map(|token| {
            let raw = token.text(command)?;
            let decoded = decoder.decode(raw, ShellTokenRole::Syntax);
            let Some(decoded) = decoded else {
                powershell_literal = true;
                return Some(None);
            };
            let dynamic = !powershell_literal && git_token_has_active_expansion(raw, dialect);
            let may_split = dynamic && git_token_expansion_may_split(raw, dialect);
            Some(Some(GitSemanticWord {
                decoded: decoded.into_owned(),
                dynamic,
                may_split,
            }))
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    Some(DecodedGitWords { words, over_limit })
}

fn git_semantic_command(command: &str, dialect: ShellDialect) -> std::borrow::Cow<'_, str> {
    let command = command.trim();
    let (command, _) = command_after_posix_control_prefixes(command, dialect);
    let command = if dialect == ShellDialect::PowerShell {
        let command = crate::normalize::powershell_assignment_rhs(command).unwrap_or(command);
        command
            .strip_prefix('&')
            .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
            .map(str::trim_start)
            .unwrap_or(command)
    } else {
        command
    };
    if dialect == ShellDialect::Posix {
        crate::normalize::strip_wrapper_prefixes(command).normalized
    } else {
        std::borrow::Cow::Borrowed(command)
    }
}

fn powershell_call_expression(command: &str) -> bool {
    command
        .trim_start()
        .strip_prefix('&')
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        .map(str::trim_start)
        .is_some_and(|rest| {
            rest.starts_with('(') || rest.starts_with("$(") || rest.starts_with("@(")
        })
}

/// Return whether a caller-proven PowerShell statement is an expression
/// statement that cannot invoke its first token as a command.
///
/// PowerShell only invokes a statement whose first token is a bare word or a
/// path. When the first token is a quoted string, a variable, or an array /
/// hashtable expression (`"…"`, `'…'`, `$…`, `@…`), the statement parses as an
/// expression and a trailing bare argument is a parse error — `"$tool" build`
/// cannot execute `$tool`. Invoking a dynamic name requires the call or
/// dot-source operator (`& $tool …` / `. $tool …`), which callers detect
/// before this check. Statements containing a subexpression (`$(…)` / `@(…)`)
/// are excluded: those evaluate their embedded pipeline even inside an
/// expression statement, so they must keep the conservative treatment.
fn powershell_expression_statement_without_subexpression(statement: &str) -> bool {
    let trimmed = statement.trim_start();
    matches!(trimmed.as_bytes().first(), Some(b'"' | b'\'' | b'$' | b'@'))
        && !trimmed.contains("$(")
        && !trimmed.contains("@(")
}

fn powershell_dynamic_call_operator(command: &str) -> bool {
    command
        .trim_start()
        .strip_prefix('&')
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        .map(str::trim_start)
        .is_some_and(|rest| {
            rest.starts_with('$') || rest.starts_with("@(") || rest.starts_with('(')
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PowerShellCallTarget {
    Git,
    GitBranch,
    NonGit,
    Dynamic,
}

struct PowerShellStaticExecutableParser<'a> {
    expression: &'a str,
    index: usize,
    terms: usize,
}

impl<'a> PowerShellStaticExecutableParser<'a> {
    fn new(expression: &'a str) -> Self {
        Self {
            expression,
            index: 0,
            terms: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.expression[self.index..].chars().next() {
            if !character.is_whitespace() {
                break;
            }
            self.index += character.len_utf8();
        }
    }

    fn parse(mut self) -> Result<String, ()> {
        if self.expression.len() > MAX_GIT_SEMANTIC_BYTES {
            return Err(());
        }
        self.skip_whitespace();
        let value = self.parse_concatenation(0)?;
        self.skip_whitespace();
        (self.index == self.expression.len())
            .then_some(value)
            .ok_or(())
    }

    fn parse_concatenation(&mut self, depth: usize) -> Result<String, ()> {
        if depth > MAX_GIT_ALIAS_DEPTH {
            return Err(());
        }
        let mut value = self.parse_primary(depth)?;
        loop {
            self.skip_whitespace();
            if self.expression.as_bytes().get(self.index) != Some(&b'+') {
                return Ok(value);
            }
            self.index += 1;
            self.skip_whitespace();
            let suffix = self.parse_primary(depth)?;
            if value.len().saturating_add(suffix.len()) > MAX_GIT_SEMANTIC_BYTES {
                return Err(());
            }
            value.push_str(&suffix);
        }
    }

    fn parse_primary(&mut self, depth: usize) -> Result<String, ()> {
        self.skip_whitespace();
        self.terms = self.terms.saturating_add(1);
        if self.terms > MAX_GIT_SEMANTIC_TOKENS {
            return Err(());
        }
        match self.expression.as_bytes().get(self.index).copied() {
            Some(b'\'') => self.parse_single_quoted(),
            Some(b'"') => self.parse_double_quoted(),
            Some(b'(') => {
                self.index += 1;
                let value = self.parse_concatenation(depth + 1)?;
                self.skip_whitespace();
                if self.expression.as_bytes().get(self.index) != Some(&b')') {
                    return Err(());
                }
                self.index += 1;
                Ok(value)
            }
            _ => Err(()),
        }
    }

    fn parse_single_quoted(&mut self) -> Result<String, ()> {
        self.index += 1;
        let mut value = String::new();
        while self.index < self.expression.len() {
            let character = self.expression[self.index..].chars().next().ok_or(())?;
            if character == '\'' {
                if self.expression.as_bytes().get(self.index + 1) == Some(&b'\'') {
                    value.push('\'');
                    self.index += 2;
                    continue;
                }
                self.index += 1;
                return Ok(value);
            }
            value.push(character);
            self.index += character.len_utf8();
        }
        Err(())
    }

    fn parse_double_quoted(&mut self) -> Result<String, ()> {
        self.index += 1;
        let mut value = String::new();
        while self.index < self.expression.len() {
            let character = self.expression[self.index..].chars().next().ok_or(())?;
            match character {
                '"' => {
                    self.index += 1;
                    return Ok(value);
                }
                '$' => return Err(()),
                '`' => {
                    self.index += 1;
                    let escaped = self.expression[self.index..].chars().next().ok_or(())?;
                    self.index += escaped.len_utf8();
                    match escaped {
                        '0' => value.push('\0'),
                        'a' => value.push('\u{0007}'),
                        'b' => value.push('\u{0008}'),
                        'e' => value.push('\u{001b}'),
                        'f' => value.push('\u{000c}'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        't' => value.push('\t'),
                        'v' => value.push('\u{000b}'),
                        '\n' => {}
                        '\r' if self.expression.as_bytes().get(self.index) == Some(&b'\n') => {
                            self.index += 1;
                        }
                        other => value.push(other),
                    }
                }
                other => {
                    value.push(other);
                    self.index += other.len_utf8();
                }
            }
        }
        Err(())
    }
}

fn powershell_call_expression_parts(command: &str) -> Option<(&str, &str)> {
    let rest = command
        .trim_start()
        .strip_prefix('&')
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))?
        .trim_start();
    let open = if rest.starts_with("$(") || rest.starts_with("@(") {
        1
    } else if rest.starts_with('(') {
        0
    } else {
        return None;
    };
    let mut depth = 0usize;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (index, character) in rest.char_indices().skip(open) {
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
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let expression_end = index + character.len_utf8();
                    let tail = powershell_postfix_expression_tail(
                        rest.get(expression_end..)?.trim_start(),
                    )?;
                    return Some((rest.get(..expression_end)?, tail));
                }
            }
            _ => {}
        }
    }
    None
}

fn powershell_call_target(command: &str) -> PowerShellCallTarget {
    let Some((executable, _)) = powershell_static_call_executable(command) else {
        return PowerShellCallTarget::Dynamic;
    };
    let Some(executable) = executable else {
        return PowerShellCallTarget::Dynamic;
    };
    let basename = executable
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&executable)
        .to_ascii_lowercase();
    match basename.as_str() {
        "git" | "git.exe" => PowerShellCallTarget::Git,
        "git-branch" | "git-branch.exe" => PowerShellCallTarget::GitBranch,
        _ => PowerShellCallTarget::NonGit,
    }
}

/// Decode a statement-leading PowerShell call-operator expression when its
/// executable is assembled entirely from bounded string literals.
///
/// `None` means the command is not a structurally complete expression-form
/// call. `Some((None, tail))` means it is a call but the target depends on
/// runtime state. The generic result is shared with other semantic packs so a
/// statically known non-target command is not mistaken for a protected tool
/// merely because its data arguments contain protected text.
pub(crate) fn powershell_static_call_executable(command: &str) -> Option<(Option<String>, &str)> {
    let (expression, tail) = powershell_call_expression_parts(command)?;
    let expression = expression
        .strip_prefix('$')
        .or_else(|| expression.strip_prefix('@'))
        .unwrap_or(expression);
    let executable = PowerShellStaticExecutableParser::new(expression)
        .parse()
        .ok();
    Some((executable, tail))
}

fn powershell_call_expression_tail(command: &str) -> Option<&str> {
    powershell_call_expression_parts(command).map(|(_, tail)| tail)
}

fn powershell_postfix_expression_tail(mut tail: &str) -> Option<&str> {
    while tail.starts_with('[') {
        let mut depth = 0usize;
        let mut single = false;
        let mut double = false;
        let mut escaped = false;
        let mut end = None;
        for (index, ch) in tail.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '`' && !single {
                escaped = true;
                continue;
            }
            if ch == '\'' && !double {
                single = !single;
                continue;
            }
            if ch == '"' && !single {
                double = !double;
                continue;
            }
            if single || double {
                continue;
            }
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        end = Some(index + ch.len_utf8());
                        break;
                    }
                }
                _ => {}
            }
        }
        tail = tail.get(end?..)?.trim_start();
    }
    Some(tail)
}

fn alias_name_from_key(key: &str) -> Option<&str> {
    let prefix = key.get(..6)?;
    prefix.eq_ignore_ascii_case("alias.").then_some(&key[6..])
}

fn push_visible_alias_definition(
    definitions: &mut Vec<VisibleAliasDefinition>,
    config: &str,
    dynamic: bool,
    dialect: ShellDialect,
) {
    let Some((key, value)) = config.split_once('=') else {
        if dynamic {
            definitions.push(VisibleAliasDefinition {
                name: None,
                value: VisibleAliasValue::Dynamic,
            });
        }
        return;
    };
    let Some(name) = alias_name_from_key(key) else {
        if dynamic {
            definitions.push(VisibleAliasDefinition {
                name: None,
                value: VisibleAliasValue::Dynamic,
            });
        }
        return;
    };
    if name.is_empty() {
        return;
    }
    let key_dynamic = dynamic && git_dynamic_fragments(key, dialect).len() > 1;
    let value_dynamic = dynamic && git_dynamic_fragments(value, dialect).len() > 1;
    definitions.push(VisibleAliasDefinition {
        name: (!key_dynamic).then(|| name.to_string()),
        value: if value_dynamic {
            VisibleAliasValue::Dynamic
        } else {
            VisibleAliasValue::Static(value.to_string())
        },
    });
}

fn environment_get<'a>(
    environment: &'a HashMap<String, EnvironmentValue>,
    name: &str,
    dialect: ShellDialect,
) -> Option<&'a EnvironmentValue> {
    environment.get(name).or_else(|| {
        matches!(dialect, ShellDialect::PowerShell | ShellDialect::Cmd)
            .then(|| {
                environment
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value)
            })
            .flatten()
    })
}

fn visible_environment_alias_definitions(
    environment: &HashMap<String, EnvironmentValue>,
    dialect: ShellDialect,
) -> Vec<VisibleAliasDefinition> {
    let Some(count) = environment_get(environment, "GIT_CONFIG_COUNT", dialect) else {
        return Vec::new();
    };
    if count.dynamic {
        return vec![VisibleAliasDefinition {
            name: None,
            value: VisibleAliasValue::Dynamic,
        }];
    }
    let Ok(count) = count.value.parse::<usize>() else {
        // Git rejects a malformed count before invoking an alias.
        return Vec::new();
    };

    let mut indexed = Vec::new();
    for (variable, key) in environment {
        let Some(index) = variable
            .strip_prefix("GIT_CONFIG_KEY_")
            .and_then(|suffix| suffix.parse::<usize>().ok())
        else {
            continue;
        };
        if index >= count {
            continue;
        }
        let value_name = format!("GIT_CONFIG_VALUE_{index}");
        let Some(value) = environment_get(environment, &value_name, dialect) else {
            continue;
        };
        indexed.push((index, key, value));
    }
    indexed.sort_unstable_by_key(|(index, _, _)| *index);

    let mut definitions = Vec::new();
    for (_, key, value) in indexed {
        let dynamic = key.dynamic || value.dynamic;
        push_visible_alias_definition(
            &mut definitions,
            &format!("{}={}", key.value, value.value),
            dynamic,
            dialect,
        );
    }
    definitions
}

fn push_config_env_alias_definition(
    definitions: &mut Vec<VisibleAliasDefinition>,
    environment: &HashMap<String, EnvironmentValue>,
    config_env: &GitSemanticWord,
    dialect: ShellDialect,
) -> bool {
    let Some((key, variable)) = config_env.decoded.split_once('=') else {
        if config_env.dynamic {
            definitions.push(VisibleAliasDefinition {
                name: None,
                value: VisibleAliasValue::Dynamic,
            });
            return true;
        }
        return false;
    };
    let Some(value) = environment_get(environment, variable, dialect) else {
        // Git exits before dispatch when --config-env names a missing value.
        return false;
    };
    push_visible_alias_definition(
        definitions,
        &format!("{key}={}", value.value),
        config_env.dynamic || value.dynamic,
        dialect,
    );
    true
}

fn lookup_visible_alias<'a>(
    definitions: &'a [VisibleAliasDefinition],
    name: &str,
) -> Option<&'a VisibleAliasValue> {
    definitions.iter().rev().find_map(|definition| {
        definition
            .name
            .as_deref()
            .is_none_or(|candidate| candidate.eq_ignore_ascii_case(name))
            .then_some(&definition.value)
    })
}

/// Return whether a shell-alias body combines a POSIX function definition
/// with positional-parameter expansion.
///
/// Git appends alias arguments to a shell alias's final command.  The nested
/// evaluator can reason about direct uses such as `!git branch "$@"`, but it
/// deliberately does not execute shell function definitions.  Consequently,
/// a wrapper such as `!f() { git branch "$@"; }; f` crosses that evaluator's
/// data-flow boundary: the arguments appended to `f` are invisible while its
/// body is inspected.  Treat that uncommon, fully general shell construct as
/// unverified rather than silently dropping the argument flow.
fn shell_alias_args_cross_function_scope(shell_body: &str) -> bool {
    let bytes = shell_body.as_bytes();
    let mut index = 0usize;
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut escaped = false;
    let mut has_positional_expansion = false;
    let mut has_function_definition = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if byte == b'\\' && !single_quoted {
            escaped = true;
            index += 1;
            continue;
        }
        if byte == b'\'' && !double_quoted {
            single_quoted = !single_quoted;
            index += 1;
            continue;
        }
        if byte == b'"' && !single_quoted {
            double_quoted = !double_quoted;
            index += 1;
            continue;
        }
        if single_quoted {
            index += 1;
            continue;
        }

        if byte == b'$' {
            let tail = &bytes[index + 1..];
            has_positional_expansion |= matches!(tail.first(), Some(b'@' | b'*' | b'0'..=b'9'))
                || tail.first() == Some(&b'{')
                    && matches!(tail.get(1), Some(b'@' | b'*' | b'0'..=b'9'));
        }

        if !double_quoted && byte == b'(' && bytes.get(index + 1) == Some(&b')') {
            let mut name_end = index;
            while name_end > 0 && bytes[name_end - 1].is_ascii_whitespace() {
                name_end -= 1;
            }
            let mut name_start = name_end;
            while name_start > 0
                && (bytes[name_start - 1].is_ascii_alphanumeric() || bytes[name_start - 1] == b'_')
            {
                name_start -= 1;
            }
            let mut body_start = index + 2;
            while bytes.get(body_start).is_some_and(u8::is_ascii_whitespace) {
                body_start += 1;
            }
            has_function_definition |=
                name_start < name_end && bytes.get(body_start) == Some(&b'{');
        }

        index += 1;
    }

    has_positional_expansion && has_function_definition
}

fn resolve_visible_alias_invocation(
    definitions: &[VisibleAliasDefinition],
    mut command: String,
    mut arguments: Vec<String>,
) -> InvokedGitAliasDecision {
    let mut visited = HashSet::new();
    for _ in 0..MAX_GIT_ALIAS_DEPTH {
        if is_known_git_command(&command) {
            return InvokedGitAliasDecision::Expanded(ExpandedGitAlias {
                subcommand: command,
                arguments,
            });
        }
        if !visited.insert(command.clone()) {
            return InvokedGitAliasDecision::Unverified;
        }
        let Some(alias) = lookup_visible_alias(definitions, &command) else {
            // Git next consults repository/global aliases and external
            // `git-<command>` helpers. A pure parser cannot prove either
            // runtime namespace safe, so unknown *name-shaped* subcommands
            // are the explicit zero-false-negative boundary. A token Git's
            // dispatch could never accept (shell punctuation glued on by a
            // cross-dialect tokenizer view, e.g. the Cmd reading of POSIX
            // `git pull; done`) is a Git usage error, not a possible alias
            // (issue #250).
            if !git_subcommand_token_is_dispatchable(&command) {
                return InvokedGitAliasDecision::NoMatch;
            }
            return InvokedGitAliasDecision::Unverified;
        };
        let VisibleAliasValue::Static(alias) = alias else {
            return InvokedGitAliasDecision::Unverified;
        };
        if let Some(shell_body) = alias.strip_prefix('!') {
            if !arguments.is_empty() && shell_alias_args_cross_function_scope(shell_body) {
                return InvokedGitAliasDecision::Unverified;
            }
            return InvokedGitAliasDecision::Shell(InvokedGitShellAlias {
                shell_body: shell_body.to_string(),
                invoked_args: arguments,
            });
        }
        let Ok(mut replacement) = shell_words::split(alias) else {
            // Malformed non-shell aliases are rejected by Git itself.
            return InvokedGitAliasDecision::NoMatch;
        };
        if replacement.is_empty() {
            return InvokedGitAliasDecision::NoMatch;
        }
        command = replacement.remove(0);
        replacement.extend(arguments);
        arguments = replacement;
    }
    InvokedGitAliasDecision::Unverified
}

/// Whether a token could ever reach Git's subcommand dispatch (a builtin, an
/// `alias.<name>` config key, or an external `git-<name>` helper).
///
/// Git config key names only allow ASCII alphanumerics and `-`, and helper
/// names are ordinary executable filenames; a token carrying shell
/// punctuation such as `;`, quotes, or redirection glyphs is a cross-dialect
/// tokenizer artifact (e.g. the Cmd view of POSIX `git pull; done`, where
/// `;` is not a separator), not a candidate alias — Git itself would reject
/// it as a usage error. Treating such tokens as "possibly aliased" turned
/// every `git <sub>; …` compound into a false `git-alias-semantic-unverified`
/// deny under `ShellDialect::Unknown` (issue #250).
fn git_subcommand_token_is_dispatchable(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

fn is_known_git_command(command: &str) -> bool {
    matches!(
        command,
        "add"
            | "am"
            | "annotate"
            | "apply"
            | "archive"
            | "archimport"
            | "backfill"
            | "bisect"
            | "blame"
            | "branch"
            | "bugreport"
            | "bundle"
            | "cat-file"
            | "check-attr"
            | "check-ignore"
            | "check-mailmap"
            | "check-ref-format"
            | "checkout"
            | "checkout-index"
            | "cherry"
            | "cherry-pick"
            | "citool"
            | "clean"
            | "clone"
            | "column"
            | "commit"
            | "commit-graph"
            | "commit-tree"
            | "config"
            | "count-objects"
            | "credential"
            | "credential-cache"
            | "credential-store"
            | "cvsimport"
            | "cvsexportcommit"
            | "cvsserver"
            | "daemon"
            | "describe"
            | "diagnose"
            | "diff"
            | "diff-files"
            | "diff-index"
            | "diff-pairs"
            | "diff-tree"
            | "difftool"
            | "fast-export"
            | "fast-import"
            | "fetch"
            | "fetch-pack"
            | "filter-branch"
            | "fmt-merge-msg"
            | "for-each-ref"
            | "for-each-repo"
            | "format-patch"
            | "fsck"
            | "gc"
            | "get-tar-commit-id"
            | "gitk"
            | "gitweb"
            | "grep"
            | "gui"
            | "hash-object"
            | "help"
            | "history"
            | "hook"
            | "http-backend"
            | "imap-send"
            | "index-pack"
            | "init"
            | "instaweb"
            | "interpret-trailers"
            | "last-modified"
            // `git lfs` is not a builtin but is the canonical spelling of the
            // Git LFS helper (`git-lfs` on PATH), so Git dispatches it without
            // consulting `alias.lfs`. Treating it as an unverifiable alias
            // denied every read-only `git lfs ls-files` / `status` / `fetch`
            // (Refs PR #383). Its own destructive verbs — `migrate`, `prune`,
            // `uninstall` — carry dedicated rules below, so recognising the
            // subcommand here is not a coverage loss.
            | "lfs"
            | "log"
            | "ls-files"
            | "ls-remote"
            | "ls-tree"
            | "mailinfo"
            | "mailsplit"
            | "maintenance"
            | "merge"
            | "merge-base"
            | "merge-file"
            | "merge-index"
            | "merge-one-file"
            | "merge-tree"
            | "mergetool"
            | "mktag"
            | "mktree"
            | "multi-pack-index"
            | "mv"
            | "name-rev"
            | "notes"
            | "p4"
            | "pack-objects"
            | "pack-redundant"
            | "pack-refs"
            | "patch-id"
            | "prune"
            | "prune-packed"
            | "pull"
            | "push"
            | "quiltimport"
            | "range-diff"
            | "read-tree"
            | "rebase"
            | "reflog"
            | "refs"
            | "remote"
            | "repack"
            | "replace"
            | "replay"
            | "repo"
            | "request-pull"
            | "rerere"
            | "reset"
            | "restore"
            | "rev-list"
            | "rev-parse"
            | "revert"
            | "rm"
            | "scalar"
            | "send-email"
            | "send-pack"
            | "sh-i18n"
            | "sh-setup"
            | "shortlog"
            | "show"
            | "show-branch"
            | "show-index"
            | "show-ref"
            | "sparse-checkout"
            | "stash"
            | "status"
            | "stripspace"
            | "submodule"
            | "svn"
            | "switch"
            | "symbolic-ref"
            | "tag"
            | "unpack-file"
            | "unpack-objects"
            | "update-index"
            | "update-ref"
            | "update-server-info"
            | "var"
            | "verify-commit"
            | "verify-pack"
            | "verify-tag"
            | "version"
            | "whatchanged"
            | "worktree"
            | "write-tree"
    )
}

fn invoked_git_alias_segment_in_dialect(
    command: &str,
    dialect: ShellDialect,
) -> InvokedGitAliasDecision {
    let powershell_expression =
        dialect == ShellDialect::PowerShell && powershell_call_expression(command);
    if powershell_expression
        && powershell_call_target(command) != PowerShellCallTarget::NonGit
        && (command.to_ascii_lowercase().contains("alias.")
            || command.to_ascii_uppercase().contains("GIT_CONFIG_"))
    {
        return InvokedGitAliasDecision::Unverified;
    }
    let command = git_semantic_command(command, dialect);
    let Some(decoded) = decode_git_semantic_words(&command, dialect) else {
        return InvokedGitAliasDecision::NoMatch;
    };
    if decoded.over_limit {
        return InvokedGitAliasDecision::Unverified;
    }
    let words = decoded.words;
    let mut environment = HashMap::new();
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        if !word.dynamic && crate::normalize::is_env_assignment(&word.decoded) {
            if let Some((name, value)) = word.decoded.split_once('=') {
                environment.insert(
                    name.to_string(),
                    EnvironmentValue {
                        value: value.to_string(),
                        dynamic: false,
                    },
                );
            }
            index += 1;
            continue;
        }
        if word.dynamic && word.decoded.contains('=') && !word.decoded.starts_with('=') {
            if let Some((name, value)) = word.decoded.split_once('=') {
                environment.insert(
                    name.to_string(),
                    EnvironmentValue {
                        value: value.to_string(),
                        dynamic: true,
                    },
                );
                index += 1;
                continue;
            }
        }
        if dialect == ShellDialect::Cmd {
            let executable = word.decoded.trim_start_matches('@');
            if executable.eq_ignore_ascii_case("call") {
                index += 1;
                continue;
            }
        }
        if !word.dynamic && matches!(word.decoded.as_str(), "exec" | "time" | "nohup" | "!") {
            index += 1;
            continue;
        }
        break;
    }

    let Some(executable) = words.get(index) else {
        return InvokedGitAliasDecision::NoMatch;
    };
    if executable.dynamic {
        let visible_alias_syntax = command.to_ascii_lowercase().contains("alias.")
            || command.to_ascii_uppercase().contains("GIT_CONFIG_")
            || command.contains("--config-env");
        return if visible_alias_syntax
            && (git_semantic_executable_may_equal(executable, dialect, "git")
                || git_semantic_executable_may_equal(executable, dialect, "git.exe"))
        {
            InvokedGitAliasDecision::Unverified
        } else {
            InvokedGitAliasDecision::NoMatch
        };
    }
    if !git_semantic_executable_may_equal(executable, dialect, "git")
        && !git_semantic_executable_may_equal(executable, dialect, "git.exe")
    {
        return InvokedGitAliasDecision::NoMatch;
    }

    let mut definitions = visible_environment_alias_definitions(&environment, dialect);
    index += 1;
    loop {
        let Some(word) = words.get(index) else {
            return InvokedGitAliasDecision::NoMatch;
        };
        if word.dynamic {
            return InvokedGitAliasDecision::Unverified;
        }
        let token = word.decoded.as_str();
        if matches!(
            token,
            "-v" | "--version"
                | "-h"
                | "--help"
                | "--exec-path"
                | "--html-path"
                | "--man-path"
                | "--info-path"
                | "help"
        ) || token.starts_with("--list-cmds=")
        {
            return InvokedGitAliasDecision::NoMatch;
        }
        if matches!(
            token,
            "-p" | "--paginate"
                | "-P"
                | "--no-pager"
                | "--bare"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--no-literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
                | "--no-advice"
        ) {
            index += 1;
            continue;
        }
        if token == "-c" {
            let Some(config) = words.get(index + 1) else {
                return InvokedGitAliasDecision::NoMatch;
            };
            push_visible_alias_definition(
                &mut definitions,
                &config.decoded,
                config.dynamic,
                dialect,
            );
            index += 2;
            continue;
        }
        if token == "--config-env" {
            let Some(config_env) = words.get(index + 1) else {
                return InvokedGitAliasDecision::NoMatch;
            };
            if !push_config_env_alias_definition(
                &mut definitions,
                &environment,
                config_env,
                dialect,
            ) {
                return InvokedGitAliasDecision::NoMatch;
            }
            index += 2;
            continue;
        }
        if matches!(
            token,
            "-C" | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--shallow-file"
                | "--attr-source"
        ) {
            let Some(value) = words.get(index + 1) else {
                return InvokedGitAliasDecision::NoMatch;
            };
            if value.dynamic && value.may_split {
                return InvokedGitAliasDecision::Unverified;
            }
            index += 2;
            continue;
        }
        if let Some(config) = token.strip_prefix("-c").filter(|value| !value.is_empty()) {
            push_visible_alias_definition(&mut definitions, config, false, dialect);
            index += 1;
            continue;
        }
        if let Some(config_env) = token.strip_prefix("--config-env=") {
            if !push_config_env_alias_definition(
                &mut definitions,
                &environment,
                &GitSemanticWord {
                    decoded: config_env.to_string(),
                    dynamic: false,
                    may_split: false,
                },
                dialect,
            ) {
                return InvokedGitAliasDecision::NoMatch;
            }
            index += 1;
            continue;
        }
        if token.starts_with("-C")
            || [
                "--exec-path=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--attr-source=",
            ]
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            index += 1;
            continue;
        }
        if token == "--" {
            index += 1;
            break;
        }
        if token.starts_with('-') {
            // Git rejects unknown global options before alias dispatch.
            return InvokedGitAliasDecision::NoMatch;
        }
        break;
    }

    let Some(invoked) = words.get(index) else {
        return InvokedGitAliasDecision::NoMatch;
    };
    if invoked.dynamic {
        return InvokedGitAliasDecision::Unverified;
    }
    if is_known_git_command(&invoked.decoded) {
        return InvokedGitAliasDecision::NoMatch;
    }
    let command = invoked.decoded.clone();
    let mut arguments = Vec::new();
    for argument in words.iter().skip(index + 1) {
        if argument.dynamic {
            return InvokedGitAliasDecision::Unverified;
        }
        arguments.push(argument.decoded.clone());
    }
    resolve_visible_alias_invocation(&definitions, command, arguments)
}

fn static_git_executable_index(words: &[GitSemanticWord], dialect: ShellDialect) -> Option<usize> {
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return None;
        }
        if crate::normalize::is_env_assignment(&word.decoded)
            || matches!(word.decoded.as_str(), "exec" | "time" | "nohup" | "!")
        {
            index += 1;
            continue;
        }
        if dialect == ShellDialect::Cmd
            && (word.decoded.trim_start_matches('@').is_empty()
                || word
                    .decoded
                    .trim_start_matches('@')
                    .eq_ignore_ascii_case("call"))
        {
            index += 1;
            continue;
        }
        return (git_semantic_executable_may_equal(word, dialect, "git")
            || git_semantic_executable_may_equal(word, dialect, "git.exe"))
        .then_some(index);
    }
    None
}

fn static_git_subcommand_index(words: &[GitSemanticWord], mut index: usize) -> Option<usize> {
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return None;
        }
        let token = word.decoded.as_str();
        if matches!(
            token,
            "-v" | "--version"
                | "-h"
                | "--help"
                | "--exec-path"
                | "--html-path"
                | "--man-path"
                | "--info-path"
                | "help"
        ) || token.starts_with("--list-cmds=")
        {
            return None;
        }
        if matches!(
            token,
            "-p" | "--paginate"
                | "-P"
                | "--no-pager"
                | "--bare"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--no-literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
                | "--no-advice"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            token,
            "-c" | "--config-env"
                | "-C"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--shallow-file"
                | "--attr-source"
        ) {
            if words.get(index + 1).is_none_or(|value| value.dynamic) {
                return None;
            }
            index += 2;
            continue;
        }
        if token.starts_with("-c")
            || token.starts_with("-C")
            || [
                "--exec-path=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--config-env=",
                "--attr-source=",
            ]
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            index += 1;
            continue;
        }
        if token == "--" {
            index += 1;
            continue;
        }
        return (!token.starts_with('-')).then_some(index);
    }
    None
}

fn record_cross_segment_environment(
    words: &[GitSemanticWord],
    dialect: ShellDialect,
    environment: &mut HashMap<String, EnvironmentValue>,
    exported: &mut HashSet<String>,
    unverified: &mut bool,
) -> bool {
    let powershell_environment_assignment = words
        .first()
        .and_then(|word| word.decoded.get(..5))
        .is_some_and(|prefix| {
            dialect == ShellDialect::PowerShell && prefix.eq_ignore_ascii_case("$env:")
        });
    if powershell_environment_assignment {
        let assignment = words[0].decoded.get(5..).unwrap_or_default();
        let (name, value, dynamic) = if let Some((name, value)) = assignment.split_once('=') {
            (
                name,
                value.to_string(),
                git_dynamic_fragments(value, dialect).len() > 1,
            )
        } else if words.get(1).map(|word| word.decoded.as_str()) == Some("=") {
            let Some(value) = words.get(2) else {
                if assignment.to_ascii_uppercase().starts_with("GIT_CONFIG_") {
                    *unverified = true;
                }
                return true;
            };
            (
                assignment,
                value.decoded.clone(),
                value.dynamic || words.len() > 3,
            )
        } else {
            if assignment.to_ascii_uppercase().starts_with("GIT_CONFIG_") {
                *unverified = true;
            }
            return true;
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            if name.to_ascii_uppercase().starts_with("GIT_CONFIG_") {
                *unverified = true;
            }
            return true;
        }
        environment.insert(name.to_string(), EnvironmentValue { value, dynamic });
        return true;
    }

    // POSIX preserves the export attribute across later assignments.
    if dialect == ShellDialect::Posix
        && !words.is_empty()
        && words
            .iter()
            .all(|word| !word.dynamic && crate::normalize::is_env_assignment(&word.decoded))
    {
        for assignment in words {
            let Some((name, value)) = assignment.decoded.split_once('=') else {
                continue;
            };
            if exported.contains(name) {
                environment.insert(
                    name.to_string(),
                    EnvironmentValue {
                        value: value.to_string(),
                        dynamic: false,
                    },
                );
            }
        }
        return true;
    }

    let assignments: &[GitSemanticWord] = match dialect {
        ShellDialect::Posix
            if words.first().is_some_and(|word| {
                !word.dynamic && word.decoded.eq_ignore_ascii_case("export")
            }) =>
        {
            &words[1..]
        }
        ShellDialect::Cmd
            if words.first().is_some_and(|word| {
                !word.dynamic
                    && word
                        .decoded
                        .trim_start_matches('@')
                        .eq_ignore_ascii_case("set")
            }) =>
        {
            &words[1..]
        }
        _ => return false,
    };
    if assignments.is_empty() {
        return true;
    }
    for assignment in assignments {
        let decoded = assignment.decoded.trim_matches('"');
        let Some((name, value)) = decoded.split_once('=') else {
            if dialect == ShellDialect::Posix
                && !decoded.is_empty()
                && decoded
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                exported.insert(decoded.to_string());
                if decoded.to_ascii_uppercase().starts_with("GIT_CONFIG_")
                    && !environment.contains_key(decoded)
                {
                    environment.insert(
                        decoded.to_string(),
                        EnvironmentValue {
                            value: String::new(),
                            dynamic: true,
                        },
                    );
                }
            } else if decoded.to_ascii_uppercase().contains("GIT_CONFIG_") {
                *unverified = true;
            }
            continue;
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            if name.to_ascii_uppercase().starts_with("GIT_CONFIG_") {
                *unverified = true;
            }
            continue;
        }
        let dynamic = assignment.dynamic;
        if dialect == ShellDialect::Posix {
            exported.insert(name.to_string());
        }
        environment.insert(
            name.to_string(),
            EnvironmentValue {
                value: value.to_string(),
                dynamic,
            },
        );
    }
    true
}

fn update_persistent_alias_definitions(
    words: &[GitSemanticWord],
    subcommand_index: usize,
    definitions: &mut Vec<VisibleAliasDefinition>,
    dialect: ShellDialect,
) -> bool {
    if words
        .get(subcommand_index)
        .map(|word| word.decoded.as_str())
        != Some("config")
    {
        return false;
    }
    let mut index = subcommand_index + 1;
    let mut unset = false;
    if let Some(operation) = words.get(index).filter(|word| !word.dynamic) {
        match operation.decoded.as_str() {
            "set" => index += 1,
            "unset" | "remove-section" => {
                unset = true;
                index += 1;
            }
            "get" | "get-all" | "get-regexp" | "list" | "show-origin" | "show-scope" => {
                return true;
            }
            _ => {}
        }
    }
    while let Some(option) = words.get(index) {
        if option.dynamic {
            definitions.push(VisibleAliasDefinition {
                name: None,
                value: VisibleAliasValue::Dynamic,
            });
            return true;
        }
        if matches!(
            option.decoded.as_str(),
            "--global"
                | "--system"
                | "--local"
                | "--worktree"
                | "--replace-all"
                | "--add"
                | "--fixed-value"
                | "--includes"
                | "--no-includes"
        ) {
            index += 1;
            continue;
        }
        if matches!(option.decoded.as_str(), "--unset" | "--unset-all") {
            unset = true;
            index += 1;
            continue;
        }
        if matches!(
            option.decoded.as_str(),
            "--file" | "-f" | "--blob" | "--type" | "--default"
        ) {
            index += 2;
            continue;
        }
        if option.decoded.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    let Some(key) = words.get(index) else {
        return true;
    };
    let Some(name) = alias_name_from_key(&key.decoded) else {
        return true;
    };
    if unset {
        definitions.retain(|definition| {
            definition
                .name
                .as_deref()
                .is_none_or(|candidate| !candidate.eq_ignore_ascii_case(name))
        });
        return true;
    }
    let Some(value) = words.get(index + 1) else {
        // `git config alias.x` is a read-only query.
        return true;
    };
    push_visible_alias_definition(
        definitions,
        &format!("{}={}", key.decoded, value.decoded),
        key.dynamic || value.dynamic,
        dialect,
    );
    true
}

fn token_has_nested_shell_context(raw: &str, dialect: ShellDialect) -> bool {
    match dialect {
        ShellDialect::Posix | ShellDialect::Unknown => {
            let mut chars = raw.chars().peekable();
            let mut single = false;
            let mut double = false;
            while let Some(ch) = chars.next() {
                match ch {
                    '\\' if !single => {
                        chars.next();
                    }
                    '\'' if !double => single = !single,
                    '"' if !single => double = !double,
                    '`' if !single => return true,
                    '$' if !single && chars.peek() == Some(&'(') => return true,
                    _ => {}
                }
            }
            false
        }
        ShellDialect::PowerShell => {
            let mut chars = raw.chars().peekable();
            let mut single = false;
            let mut double = false;
            while let Some(ch) = chars.next() {
                match ch {
                    '`' if !single => {
                        chars.next();
                    }
                    '\'' if !double => single = !single,
                    '"' if !single => double = !double,
                    '$' | '@' if !single && chars.peek() == Some(&'(') => return true,
                    _ => {}
                }
            }
            false
        }
        ShellDialect::Cmd => false,
    }
}

fn shell_control_keyword(raw: &str, dialect: ShellDialect) -> bool {
    match dialect {
        ShellDialect::Posix => matches!(
            raw,
            "if" | "then"
                | "elif"
                | "else"
                | "fi"
                | "for"
                | "while"
                | "until"
                | "do"
                | "done"
                | "case"
                | "esac"
                | "select"
                | "coproc"
                | "function"
                | "{"
                | "}"
        ),
        ShellDialect::PowerShell => matches!(
            raw.to_ascii_lowercase().as_str(),
            "if" | "elseif"
                | "else"
                | "switch"
                | "foreach"
                | "for"
                | "while"
                | "do"
                | "until"
                | "try"
                | "catch"
                | "finally"
                | "trap"
                | "function"
                | "filter"
                | "begin"
                | "process"
                | "end"
                | "{"
                | "}"
        ),
        ShellDialect::Cmd => matches!(raw.to_ascii_lowercase().as_str(), "if" | "else" | "for"),
        ShellDialect::Unknown => {
            shell_control_keyword(raw, ShellDialect::Posix)
                || shell_control_keyword(raw, ShellDialect::PowerShell)
                || shell_control_keyword(raw, ShellDialect::Cmd)
        }
    }
}

/// The cross-segment alias-state interpreter is deliberately straight-line.
/// Any relevant mutation in a conditional, loop, function, subshell,
/// pipeline, background job, or command substitution must therefore make a
/// later unresolved Git invocation unverified rather than flattening a path
/// that the executing shell may skip or isolate.
fn command_has_conditional_control_flow(command: &str, dialect: ShellDialect) -> bool {
    let tokens = tokenize_for_shell_dialect(command, dialect);
    let mut command_word = true;
    for token in &tokens {
        let Some(raw) = token.text(command) else {
            continue;
        };
        match token.kind {
            NormalizeTokenKind::Separator => {
                let straight_line_separator = matches!(raw, ";" | "\n" | "\r" | "\r\n")
                    || dialect == ShellDialect::Cmd && raw == "&";
                if !straight_line_separator {
                    return true;
                }
                command_word = true;
            }
            NormalizeTokenKind::Word => {
                if token_has_nested_shell_context(raw, dialect)
                    || (command_word && shell_control_keyword(raw, dialect))
                {
                    return true;
                }
                command_word = false;
            }
        }
    }
    false
}

fn git_config_segment_mutates_alias(words: &[GitSemanticWord], subcommand_index: usize) -> bool {
    if words
        .get(subcommand_index)
        .map(|word| word.decoded.as_str())
        != Some("config")
    {
        return false;
    }
    let alias_index = words
        .iter()
        .enumerate()
        .skip(subcommand_index + 1)
        .find_map(|(index, word)| alias_name_from_key(&word.decoded).map(|_| index));
    let Some(alias_index) = alias_index else {
        return false;
    };
    words.get(alias_index + 1).is_some()
        || words.iter().skip(subcommand_index + 1).any(|word| {
            matches!(
                word.decoded.as_str(),
                "set" | "unset" | "--unset" | "--unset-all" | "--add" | "--replace-all"
            )
        })
}

fn cross_segment_git_alias_decision(
    command: &str,
    dialect: ShellDialect,
) -> InvokedGitAliasDecision {
    let segments = crate::packs::split_command_segments_in_dialect(command, dialect);
    if segments.len() < 2 {
        return InvokedGitAliasDecision::NoMatch;
    }
    let mut environment = HashMap::new();
    let mut exported = HashSet::new();
    let mut environment_unverified = false;
    let mut persistent = Vec::new();
    let conditional_control_flow = command_has_conditional_control_flow(command, dialect);
    let mut conditional_alias_state = false;
    for segment in segments {
        // Preserve PowerShell environment assignments long enough for
        // `record_cross_segment_environment` to consume them. Other variable
        // assignments use their executable RHS so `$result = git ...` is
        // analyzed as a Git invocation rather than as a dynamic lvalue.
        let segment = if dialect == ShellDialect::PowerShell
            && segment
                .trim_start()
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("$env:"))
        {
            std::borrow::Cow::Borrowed(segment.trim())
        } else {
            git_semantic_command(segment, dialect)
        };
        let Some(decoded) = decode_git_semantic_words(&segment, dialect) else {
            continue;
        };
        if decoded.over_limit {
            return InvokedGitAliasDecision::Unverified;
        }
        let words = decoded.words;
        if record_cross_segment_environment(
            &words,
            dialect,
            &mut environment,
            &mut exported,
            &mut environment_unverified,
        ) {
            if conditional_control_flow
                && words
                    .iter()
                    .any(|word| word.decoded.to_ascii_uppercase().contains("GIT_CONFIG_"))
            {
                conditional_alias_state = true;
            }
            continue;
        }
        let Some(executable_index) = static_git_executable_index(&words, dialect) else {
            continue;
        };
        let Some(subcommand_index) = static_git_subcommand_index(&words, executable_index + 1)
        else {
            continue;
        };
        let mutates_alias = git_config_segment_mutates_alias(&words, subcommand_index);
        if update_persistent_alias_definitions(&words, subcommand_index, &mut persistent, dialect) {
            if conditional_control_flow && mutates_alias {
                conditional_alias_state = true;
            }
            continue;
        }

        if conditional_alias_state
            && !is_known_git_command(&words[subcommand_index].decoded)
            && git_subcommand_token_is_dispatchable(&words[subcommand_index].decoded)
        {
            return InvokedGitAliasDecision::Unverified;
        }

        let mut definitions = persistent.clone();
        definitions.extend(visible_environment_alias_definitions(&environment, dialect));
        if definitions.is_empty() && !environment_unverified {
            continue;
        }
        if environment_unverified
            || words
                .iter()
                .skip(executable_index + 1)
                .any(|word| word.dynamic)
            || definitions.iter().any(|definition| {
                definition.name.is_none() || matches!(definition.value, VisibleAliasValue::Dynamic)
            })
        {
            if !is_known_git_command(&words[subcommand_index].decoded)
                && git_subcommand_token_is_dispatchable(&words[subcommand_index].decoded)
            {
                return InvokedGitAliasDecision::Unverified;
            }
            continue;
        }

        let mut synthetic = String::new();
        for (name, value) in &environment {
            if value.dynamic
                || name.is_empty()
                || !name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                continue;
            }
            synthetic.push_str(name);
            synthetic.push('=');
            synthetic.push_str(&shell_words::quote(&value.value));
            synthetic.push(' ');
        }
        synthetic.push_str("git");
        for definition in definitions {
            let (Some(name), VisibleAliasValue::Static(value)) =
                (definition.name, definition.value)
            else {
                continue;
            };
            synthetic.push_str(" -c ");
            synthetic.push_str(&shell_words::quote(&format!("alias.{name}={value}")));
        }
        for word in words.iter().skip(executable_index + 1) {
            synthetic.push(' ');
            synthetic.push_str(&shell_words::quote(&word.decoded));
        }
        match invoked_git_alias_segment_in_dialect(&synthetic, ShellDialect::Posix) {
            InvokedGitAliasDecision::NoMatch => {}
            decision => return decision,
        }
    }
    InvokedGitAliasDecision::NoMatch
}

/// Resolve aliases visible in this command: invocation-local `-c` /
/// `--config-env` / `GIT_CONFIG_*` definitions plus earlier `git config` and
/// exported environment mutations in the same compound shell command.
/// Pre-existing repository/user aliases remain outside this pure parser and
/// are covered by the unresolved-subcommand mutation guard.
#[must_use]
pub(crate) fn invoked_visible_git_alias_in_dialect(
    command: &str,
    dialect: ShellDialect,
) -> InvokedGitAliasDecision {
    if dialect == ShellDialect::Unknown {
        let decisions = [
            invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
            invoked_visible_git_alias_in_dialect(command, ShellDialect::PowerShell),
            invoked_visible_git_alias_in_dialect(command, ShellDialect::Cmd),
        ];
        if decisions
            .iter()
            .any(|decision| matches!(decision, InvokedGitAliasDecision::Unverified))
        {
            return InvokedGitAliasDecision::Unverified;
        }
        let mut actionable = decisions.iter().filter(|decision| {
            matches!(
                decision,
                InvokedGitAliasDecision::Shell(_) | InvokedGitAliasDecision::Expanded(_)
            )
        });
        if let Some(first) = actionable.next() {
            if actionable.all(|decision| decision == first) {
                return first.clone();
            }
            return InvokedGitAliasDecision::Unverified;
        }
        return InvokedGitAliasDecision::NoMatch;
    }
    if dialect == ShellDialect::PowerShell
        && powershell_call_expression(command)
        && powershell_call_target(command) != PowerShellCallTarget::NonGit
        && (command.to_ascii_lowercase().contains("alias.")
            || command.to_ascii_uppercase().contains("GIT_CONFIG_")
            || command.contains("--config-env"))
    {
        return InvokedGitAliasDecision::Unverified;
    }
    if command.len() > MAX_GIT_SEMANTIC_BYTES {
        return if contains_git_ascii_case_insensitive(command)
            || command.to_ascii_lowercase().contains("alias.")
        {
            InvokedGitAliasDecision::Unverified
        } else {
            InvokedGitAliasDecision::NoMatch
        };
    }
    match cross_segment_git_alias_decision(command, dialect) {
        InvokedGitAliasDecision::NoMatch => {}
        decision => return decision,
    }
    let segments = crate::packs::split_command_segments_in_dialect(command, dialect);
    let mut actionable = None;
    for segment in segments {
        match invoked_git_alias_segment_in_dialect(segment, dialect) {
            InvokedGitAliasDecision::Unverified => return InvokedGitAliasDecision::Unverified,
            found @ (InvokedGitAliasDecision::Shell(_) | InvokedGitAliasDecision::Expanded(_)) => {
                if actionable.replace(found).is_some() {
                    // Multiple visible aliases require recursive segment
                    // evaluation rather than collapsing them into one argv.
                    return InvokedGitAliasDecision::Unverified;
                }
            }
            InvokedGitAliasDecision::NoMatch => {}
        }
    }
    actionable.unwrap_or(InvokedGitAliasDecision::NoMatch)
}

fn branch_dynamic_word_may_mutate(word: &GitSemanticWord, dialect: ShellDialect) -> bool {
    word.may_split
        || [
            "-d", "-D", "-f", "-M", "-C", "--d", "--de", "--del", "--dele", "--delet", "--delete",
            "--forc", "--force",
        ]
        .iter()
        .any(|candidate| git_symbolic_word_may_equal(word, dialect, candidate, false))
}

fn semantic_branch_argv_may_mutate(words: &[GitSemanticWord], dialect: ShellDialect) -> bool {
    let mut mutation = BranchMutationState::default();
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        if !word.dynamic && matches!(word.decoded.as_str(), "--" | "--end-of-options") {
            return mutation.decision() == BranchCommandDecision::Destructive;
        }
        if word.dynamic {
            if branch_dynamic_word_may_mutate(word, dialect) {
                return true;
            }
            index += 1;
            continue;
        }
        let token = word.decoded.as_str();
        if token.starts_with("--") {
            if matches!(token, "--help" | "--help-all") {
                return false;
            }
            let Some(resolved) = resolve_branch_long_option(token) else {
                return false;
            };
            if resolved.inline_value && matches!(resolved.arity, BranchLongOptionArity::None) {
                return false;
            }
            match resolved.name {
                "delete" if resolved.negated => mutation.delete_bits &= !1,
                "delete" => mutation.delete_bits |= 1,
                "force" => mutation.force = !resolved.negated,
                _ => {}
            }
            let arity = if resolved.negated {
                BranchLongOptionArity::None
            } else {
                resolved.arity
            };
            match arity {
                BranchLongOptionArity::None | BranchLongOptionArity::OptionalAttached => index += 1,
                BranchLongOptionArity::Required if resolved.inline_value => index += 1,
                BranchLongOptionArity::Required => {
                    let Some(value) = words.get(index + 1) else {
                        return false;
                    };
                    if value.dynamic && value.may_split {
                        return true;
                    }
                    index += 2;
                }
                BranchLongOptionArity::LastArgDefault if resolved.inline_value => index += 1,
                BranchLongOptionArity::LastArgDefault => {
                    let Some(value) = words.get(index + 1) else {
                        index += 1;
                        continue;
                    };
                    if value.dynamic && value.may_split {
                        return true;
                    }
                    index += 2;
                }
            }
            continue;
        }
        if let Some(flags) = token.strip_prefix('-') {
            if flags.is_empty() {
                index += 1;
                continue;
            }
            let mut chars = flags.chars();
            while let Some(flag) = chars.next() {
                if flag == 'h' {
                    return false;
                }
                match flag {
                    'd' => mutation.delete_bits |= 1,
                    'D' => mutation.delete_bits |= 2,
                    'f' => mutation.force = true,
                    'M' | 'C' => mutation.forced_move_or_copy = true,
                    'v' | 'q' | 'r' | 'a' | 'm' | 'c' | 'l' | 'i' | 'u' | 't' => {}
                    _ => return false,
                }
                if flag == 'u' {
                    if chars.as_str().is_empty() {
                        let Some(value) = words.get(index + 1) else {
                            return false;
                        };
                        if value.dynamic && value.may_split {
                            return true;
                        }
                        index += 1;
                    }
                    break;
                }
                if flag == 't' && !chars.as_str().is_empty() {
                    break;
                }
            }
        }
        index += 1;
    }
    mutation.decision() == BranchCommandDecision::Destructive
}

/// Fail closed only when active shell expansion can occupy Git's executable,
/// subcommand, or a branch-mutation option role. Expansion consumed as quoted
/// option data or after `--` remains data and is not reinterpreted.
fn dynamic_git_branch_may_mutate(command: &str, dialect: ShellDialect) -> bool {
    if dialect == ShellDialect::Unknown {
        return [
            ShellDialect::Posix,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
        ]
        .iter()
        .any(|dialect| dynamic_git_branch_may_mutate(command, *dialect));
    }

    // Never flatten several shell statements into one synthetic argv. A
    // dynamic word at the start of one PowerShell assignment must not combine
    // with an option-looking token from a later statement and become a
    // fictional `git branch -D` invocation. Each executable segment is already
    // checked independently by the evaluator, so leave the original compound
    // form to `branch_command_decision_in_dialect`, which returns `Unparsed`.
    let powershell_expression =
        dialect == ShellDialect::PowerShell && powershell_call_expression(command);
    if !powershell_expression {
        let trimmed = command.trim();
        let segments = crate::packs::split_command_segments_in_dialect(trimmed, dialect);
        if segments.last().is_some_and(|segment| *segment != trimmed) {
            return false;
        }
    }

    let command = if powershell_expression {
        let Some(tail) = powershell_call_expression_tail(command) else {
            return true;
        };
        match powershell_call_target(command) {
            PowerShellCallTarget::NonGit => return false,
            PowerShellCallTarget::GitBranch => {
                std::borrow::Cow::Owned(format!("git branch {tail}"))
            }
            PowerShellCallTarget::Git | PowerShellCallTarget::Dynamic => {
                std::borrow::Cow::Owned(format!("git {tail}"))
            }
        }
    } else {
        if dialect == ShellDialect::PowerShell {
            let statement = command.trim();
            let (statement, _) = command_after_posix_control_prefixes(statement, dialect);
            let statement =
                crate::normalize::powershell_assignment_rhs(statement).unwrap_or(statement);
            if powershell_expression_statement_without_subexpression(statement) {
                // An expression statement never invokes its first token, so a
                // dynamic word there cannot become `git branch` (#273). The
                // call-operator forms keep their existing handling above.
                return false;
            }
        }
        git_semantic_command(command, dialect)
    };
    let Some(decoded) = decode_git_semantic_words(&command, dialect) else {
        return false;
    };
    if decoded.over_limit {
        return contains_git_ascii_case_insensitive(&command);
    }
    let words = decoded.words;
    if !powershell_expression && !words.iter().any(|word| word.dynamic) {
        return false;
    }

    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        if !word.dynamic && crate::normalize::is_env_assignment(&word.decoded) {
            index += 1;
            continue;
        }
        if dialect == ShellDialect::Cmd {
            let executable = word.decoded.trim_start_matches('@');
            if executable.eq_ignore_ascii_case("call") {
                index += 1;
                continue;
            }
        }
        if !word.dynamic && matches!(word.decoded.as_str(), "exec" | "time" | "nohup" | "!") {
            index += 1;
            continue;
        }
        break;
    }
    let Some(executable) = words.get(index) else {
        return false;
    };
    // #281: an executable word with no literal bytes (`$cmd`) supplies no
    // evidence of Git. It must not become `git-branch` on its own, and later
    // dynamic words must not stand in for the literal `branch` subcommand —
    // two unknowns are not evidence. Literal branch syntax after it (e.g.
    // `$(producer) branch -d feature`) still fails closed below.
    let executable_unbounded =
        !powershell_expression && git_semantic_executable_is_unbounded(executable, dialect);
    let dashed_branch = !powershell_expression
        && !executable_unbounded
        && (git_semantic_executable_may_equal(executable, dialect, "git-branch")
            || git_semantic_executable_may_equal(executable, dialect, "git-branch.exe"));
    let may_execute_git = powershell_expression
        || executable_unbounded
        || git_semantic_executable_may_equal(executable, dialect, "git")
        || git_semantic_executable_may_equal(executable, dialect, "git.exe")
        || dashed_branch;
    if !may_execute_git {
        return false;
    }
    index += 1;
    if dashed_branch {
        return semantic_branch_argv_may_mutate(&words[index..], dialect);
    }

    // When the executable name proved nothing (#360, #361: a pure-wildcard
    // basename, or a bare expansion), no later word may stand in for the
    // literal `branch` subcommand — but literal deletion/force flags anywhere
    // in the remaining argv are still evidence in plain sight. Scanning the
    // whole tail here (not just the words after a dynamic token) keeps
    // `/* -D main` denied even though its flag sits in the very first argv
    // slot, where no dynamic word precedes it.
    if executable_unbounded
        && literal_branch_tokens_prove_mutation(
            words[index..]
                .iter()
                .map(|word| (!word.dynamic).then_some(word.decoded.as_str())),
        )
    {
        return true;
    }

    loop {
        let Some(word) = words.get(index) else {
            return false;
        };
        if word.dynamic {
            if !executable_unbounded
                && git_symbolic_word_may_equal(word, dialect, "branch", false)
                && semantic_branch_argv_may_mutate(&words[index + 1..], dialect)
            {
                return true;
            }
            if executable_unbounded
                && literal_branch_tokens_prove_mutation(
                    words[index + 1..]
                        .iter()
                        .map(|word| (!word.dynamic).then_some(word.decoded.as_str())),
                )
            {
                // #281 keeps two unknowns from standing in for `git branch`,
                // but literal argv after them is still evidence: `$g $sub -D
                // main` shows a proven branch deletion in plain sight, and the
                // short-flag spelling must not fare better than `--delete`.
                return true;
            }
            // A dynamic global prefix can disappear or expand to a valid Git
            // option. Continue looking for a literal branch subcommand.
            index += 1;
            continue;
        }
        let token = word.decoded.as_str();
        if token == "branch" {
            return semantic_branch_argv_may_mutate(&words[index + 1..], dialect);
        }
        if is_known_git_command(token) {
            return false;
        }
        if matches!(
            token,
            "-v" | "--version"
                | "-h"
                | "--help"
                | "--exec-path"
                | "--html-path"
                | "--man-path"
                | "--info-path"
                | "help"
        ) || token.starts_with("--list-cmds=")
        {
            return false;
        }
        if matches!(
            token,
            "-p" | "--paginate"
                | "-P"
                | "--no-pager"
                | "--bare"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--no-literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
                | "--no-advice"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            token,
            "-c" | "--config-env"
                | "-C"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--shallow-file"
                | "--attr-source"
        ) {
            let Some(value) = words.get(index + 1) else {
                return false;
            };
            if value.dynamic && value.may_split {
                return semantic_branch_argv_may_mutate(&words[index + 2..], dialect);
            }
            index += 2;
            continue;
        }
        if token.starts_with("-c")
            || token.starts_with("-C")
            || [
                "--exec-path=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--config-env=",
                "--attr-source=",
            ]
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            index += 1;
            continue;
        }
        if token == "--" {
            index += 1;
            continue;
        }
        // An unresolved command may be a persistent alias for `branch` — but
        // only when the executable itself gave some evidence of being Git.
        // With an unbounded executable this token is a second unknown, and
        // two unknowns are not evidence (#360, per the #281 precedent). Any
        // literal deletion flag in the tail was already caught by the
        // whole-argv scan above, so returning false here hides nothing.
        if executable_unbounded {
            return false;
        }
        return semantic_branch_argv_may_mutate(&words[index + 1..], dialect);
    }
}

const MAX_VISIBLE_GIT_ALIASES: usize = 64;

fn insert_visible_alias(aliases: &mut HashMap<String, String>, config: &str) {
    let Some((key, value)) = config.split_once('=') else {
        return;
    };
    let Some(prefix) = key.get(..6) else {
        return;
    };
    if !prefix.eq_ignore_ascii_case("alias.") {
        return;
    }
    let name = &key[6..];
    if name.is_empty() || (aliases.len() >= MAX_VISIBLE_GIT_ALIASES && !aliases.contains_key(name))
    {
        return;
    }
    aliases.insert(name.to_string(), value.to_string());
}

fn insert_visible_config_env_alias(
    aliases: &mut HashMap<String, String>,
    environment: &HashMap<String, String>,
    config_env: &str,
) {
    let Some((key, variable)) = config_env.split_once('=') else {
        return;
    };
    let Some(value) = environment.get(variable) else {
        return;
    };
    insert_visible_alias(aliases, &format!("{key}={value}"));
}

fn visible_environment_aliases(environment: &HashMap<String, String>) -> HashMap<String, String> {
    let mut aliases = HashMap::new();
    let count = environment
        .get("GIT_CONFIG_COUNT")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_VISIBLE_GIT_ALIASES);
    for index in 0..count {
        let Some(key) = environment.get(&format!("GIT_CONFIG_KEY_{index}")) else {
            continue;
        };
        let Some(value) = environment.get(&format!("GIT_CONFIG_VALUE_{index}")) else {
            continue;
        };
        insert_visible_alias(&mut aliases, &format!("{key}={value}"));
    }
    aliases
}

fn resolve_visible_branch_alias(
    invoked: &str,
    aliases: &HashMap<String, String>,
) -> Option<Vec<String>> {
    let mut words = vec![invoked.to_string()];
    let mut visited = HashSet::new();

    for _ in 0..MAX_VISIBLE_GIT_ALIASES {
        let command = words.first()?.clone();
        if command == "branch" {
            return Some(words);
        }
        if command.eq_ignore_ascii_case("git-branch") {
            words[0] = "branch".to_string();
            return Some(words);
        }
        if !visited.insert(command.clone()) {
            return None;
        }
        let alias = aliases.get(&command)?;
        let mut replacement = if let Some(shell_alias) = alias.strip_prefix('!') {
            if shell_alias.contains([';', '|', '&', '(', ')', '\n', '\r']) {
                return None;
            }
            let mut shell_words = shell_words::split(shell_alias).ok()?;
            let executable = shell_words
                .first()?
                .rsplit(['/', '\\'])
                .next()?
                .trim_end_matches(".exe");
            if !executable.eq_ignore_ascii_case("git") {
                return None;
            }
            shell_words.remove(0);
            shell_words
        } else {
            shell_words::split(alias).ok()?
        };
        if replacement.is_empty() {
            return None;
        }
        replacement.extend(words.into_iter().skip(1));
        words = replacement;
    }
    None
}

/// Conservatively execute the branch grammar over unresolved POSIX command
/// substitutions. Quoted dynamic data consumed by a known option stays data;
/// an unquoted substitution may field-split into additional options and is
/// therefore unsafe whenever it occupies a Git syntax position.
fn symbolic_posix_branch_decision(command: &str) -> Option<BranchCommandDecision> {
    // The splitter evaluates this inner Git query independently. Its outer
    // substitution yields at most one branch-name argv word, so it cannot
    // synthesize a `git branch -d/-f/-M/-C` invocation by field splitting.
    if sole_posix_branch_name_query(command) {
        return Some(BranchCommandDecision::NotBranch);
    }
    let stripped = crate::normalize::strip_wrapper_prefixes(command);
    let command = stripped.normalized.as_ref();
    let view = posix_substitution_view(command).ok()?;
    if !view.has_dynamic {
        return None;
    }
    let mut words = symbolic_posix_words(&view).ok()?;
    let mut environment = HashMap::new();
    let mut executable_index = 0usize;
    let mut executable_unbounded = false;
    let dashed_branch;

    loop {
        let word = words.get(executable_index)?;
        if let Some(exact) = word.exact() {
            if crate::normalize::is_env_assignment(exact) {
                if let Some((name, value)) = exact.split_once('=') {
                    environment.insert(name.to_string(), value.to_string());
                }
                executable_index += 1;
                continue;
            }
            if matches!(exact, "exec" | "time" | "nohup" | "!") {
                executable_index += 1;
                continue;
            }
        }
        let basename = SymbolicPosixWord {
            text: word
                .text
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&word.text)
                .to_string(),
            unquoted_dynamic: word.unquoted_dynamic,
        };
        if basename.may_equal("git") || basename.may_equal("git.exe") {
            if basename.unquoted_dynamic {
                // #281: a substitution with no literal bytes could expand to
                // anything and supplies no Git evidence; keep parsing so only
                // literal branch syntax after it (e.g. `$(producer) branch -d
                // feature`) can fail closed. A partially literal word such as
                // `gi$(x)` retains the conservative treatment.
                if basename.has_literal_fragment() {
                    return Some(BranchCommandDecision::DestructiveDynamic);
                }
                executable_unbounded = true;
            }
            dashed_branch = false;
            break;
        }
        if basename.may_equal("git-branch") || basename.may_equal("git-branch.exe") {
            if basename.unquoted_dynamic {
                return Some(BranchCommandDecision::DestructiveDynamic);
            }
            dashed_branch = true;
            break;
        }
        return Some(BranchCommandDecision::NotBranch);
    }

    let mut aliases = visible_environment_aliases(&environment);
    let mut index = executable_index + 1;
    let found_branch = dashed_branch;
    if !found_branch {
        loop {
            let Some(word) = words.get(index) else {
                return Some(BranchCommandDecision::NotBranch);
            };
            if word.is_dynamic() {
                if executable_unbounded {
                    // #281: two unknowns are not evidence — a dynamic word
                    // cannot stand in for `branch` when the executable is
                    // itself an unbounded expansion. Literal argv after the
                    // unknowns is evidence, though: `$g $sub -D main` still
                    // carries a proven branch deletion in plain sight, so the
                    // scan continues past the dynamic word rather than
                    // discarding what follows it.
                    return Some(
                        if literal_argv_proves_branch_mutation(&words[index + 1..]) {
                            BranchCommandDecision::DestructiveDynamic
                        } else {
                            BranchCommandDecision::NotBranch
                        },
                    );
                }
                if word.may_equal("branch") {
                    if word.unquoted_dynamic {
                        return Some(BranchCommandDecision::DestructiveDynamic);
                    }
                    index += 1;
                    break;
                }
                return Some(BranchCommandDecision::NotBranch);
            }
            let token = word.exact()?;
            if token == "branch" {
                index += 1;
                break;
            }
            if matches!(
                token,
                "-v" | "--version"
                    | "-h"
                    | "--help"
                    | "--exec-path"
                    | "--html-path"
                    | "--man-path"
                    | "--info-path"
                    | "help"
            ) || token.starts_with("--list-cmds=")
            {
                return Some(BranchCommandDecision::NonDestructive);
            }
            if matches!(
                token,
                "-p" | "--paginate"
                    | "-P"
                    | "--no-pager"
                    | "--bare"
                    | "--no-replace-objects"
                    | "--literal-pathspecs"
                    | "--no-literal-pathspecs"
                    | "--glob-pathspecs"
                    | "--noglob-pathspecs"
                    | "--icase-pathspecs"
                    | "--no-optional-locks"
                    | "--no-lazy-fetch"
                    | "--no-advice"
            ) {
                index += 1;
                continue;
            }
            if token == "-c" || token == "--config-env" {
                let Some(data) = words.get(index + 1) else {
                    return Some(BranchCommandDecision::Unparsed);
                };
                if !symbolic_data_word_is_safe(data) {
                    return Some(BranchCommandDecision::DestructiveDynamic);
                }
                if let Some(exact) = data.exact() {
                    if token == "-c" {
                        insert_visible_alias(&mut aliases, exact);
                    } else {
                        insert_visible_config_env_alias(&mut aliases, &environment, exact);
                    }
                }
                index += 2;
                continue;
            }
            if matches!(
                token,
                "-C" | "--git-dir"
                    | "--work-tree"
                    | "--namespace"
                    | "--super-prefix"
                    | "--shallow-file"
                    | "--attr-source"
            ) {
                let Some(data) = words.get(index + 1) else {
                    return Some(BranchCommandDecision::Unparsed);
                };
                if !symbolic_data_word_is_safe(data) {
                    return Some(BranchCommandDecision::DestructiveDynamic);
                }
                index += 2;
                continue;
            }
            if let Some(config) = token.strip_prefix("-c").filter(|value| !value.is_empty()) {
                insert_visible_alias(&mut aliases, config);
                index += 1;
                continue;
            }
            if let Some(config_env) = token.strip_prefix("--config-env=") {
                insert_visible_config_env_alias(&mut aliases, &environment, config_env);
                index += 1;
                continue;
            }
            if token.starts_with("-C")
                || [
                    "--exec-path=",
                    "--git-dir=",
                    "--work-tree=",
                    "--namespace=",
                    "--super-prefix=",
                    "--config-env=",
                    "--attr-source=",
                ]
                .iter()
                .any(|prefix| token.starts_with(prefix))
            {
                index += 1;
                continue;
            }
            if !token.starts_with('-') {
                let Some(expansion) = resolve_visible_branch_alias(token, &aliases) else {
                    return Some(BranchCommandDecision::NotBranch);
                };
                let mut expanded: Vec<_> = expansion
                    .into_iter()
                    .map(|text| SymbolicPosixWord {
                        text,
                        unquoted_dynamic: false,
                    })
                    .collect();
                expanded.extend(words.into_iter().skip(index + 1));
                words = expanded;
                index = 1;
                break;
            }
            return Some(BranchCommandDecision::Unparsed);
        }
    }

    let mut mutation = BranchMutationState::default();
    while let Some(word) = words.get(index) {
        if word.is_dynamic() {
            if word.unquoted_dynamic || symbolic_branch_option_may_mutate(word) {
                return Some(BranchCommandDecision::DestructiveDynamic);
            }
            index += 1;
            continue;
        }
        let token = word.exact()?;
        if matches!(token, "--" | "--end-of-options") {
            return Some(symbolic_scan_decision(mutation, executable_unbounded));
        }
        if token.starts_with("--") {
            if matches!(token, "--help" | "--help-all") {
                return Some(BranchCommandDecision::NonDestructive);
            }
            let Some(resolved) = resolve_branch_long_option(token) else {
                return Some(BranchCommandDecision::NonDestructive);
            };
            if resolved.inline_value && matches!(resolved.arity, BranchLongOptionArity::None) {
                return Some(BranchCommandDecision::NonDestructive);
            }
            match resolved.name {
                "delete" if resolved.negated => mutation.delete_bits &= !1,
                "delete" => mutation.delete_bits |= 1,
                "force" => mutation.force = !resolved.negated,
                _ => {}
            }
            let arity = if resolved.negated {
                BranchLongOptionArity::None
            } else {
                resolved.arity
            };
            match arity {
                BranchLongOptionArity::None | BranchLongOptionArity::OptionalAttached => index += 1,
                BranchLongOptionArity::Required if resolved.inline_value => index += 1,
                BranchLongOptionArity::Required => {
                    let Some(data) = words.get(index + 1) else {
                        return Some(BranchCommandDecision::NonDestructive);
                    };
                    if !symbolic_data_word_is_safe(data) {
                        return Some(BranchCommandDecision::DestructiveDynamic);
                    }
                    index += 2;
                }
                BranchLongOptionArity::LastArgDefault if resolved.inline_value => index += 1,
                BranchLongOptionArity::LastArgDefault => {
                    if let Some(data) = words.get(index + 1) {
                        if !symbolic_data_word_is_safe(data) {
                            return Some(BranchCommandDecision::DestructiveDynamic);
                        }
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
            }
            continue;
        }
        if let Some(flags) = token.strip_prefix('-') {
            let mut chars = flags.chars();
            while let Some(flag) = chars.next() {
                if flag == 'h' {
                    return Some(BranchCommandDecision::NonDestructive);
                }
                match flag {
                    'd' => mutation.delete_bits |= 1,
                    'D' => mutation.delete_bits |= 2,
                    'f' => mutation.force = true,
                    'M' | 'C' => mutation.forced_move_or_copy = true,
                    'v' | 'q' | 'r' | 'a' | 'm' | 'c' | 'l' | 'i' | 'u' | 't' => {}
                    _ => return Some(BranchCommandDecision::NonDestructive),
                }
                if flag == 'u' {
                    if chars.as_str().is_empty() {
                        let Some(data) = words.get(index + 1) else {
                            return Some(BranchCommandDecision::NonDestructive);
                        };
                        if !symbolic_data_word_is_safe(data) {
                            return Some(BranchCommandDecision::DestructiveDynamic);
                        }
                        index += 1;
                    }
                    // `-u<upstream>` consumes the entire attached remainder as
                    // data; letters such as d/f/M/C are not more short flags.
                    break;
                }
                if flag == 't' && !chars.as_str().is_empty() {
                    break;
                }
            }
        }
        index += 1;
    }

    Some(symbolic_scan_decision(mutation, executable_unbounded))
}

/// Map a completed symbolic branch-argv scan to a decision. When the
/// executable word was an unbounded expansion (#281), a proven mutation is
/// attributed to the dynamic-token rule (the unresolved word is part of the
/// proof) and anything weaker stays unattributed to Git entirely.
const fn symbolic_scan_decision(
    mutation: BranchMutationState,
    executable_unbounded: bool,
) -> BranchCommandDecision {
    let decision = mutation.decision();
    if !executable_unbounded {
        return decision;
    }
    match decision {
        BranchCommandDecision::Destructive => BranchCommandDecision::DestructiveDynamic,
        _ => BranchCommandDecision::NotBranch,
    }
}

/// Return whether this command segment invokes Git as its executable in a
/// caller-proven shell dialect. This prevents quoted documentation or command
/// substitution output from being reinterpreted as executable shell source by
/// regex-backed rules. Unknown callers retain the historical conservative
/// behavior.
pub(crate) fn command_executes_git_in_dialect(command: &str, dialect: ShellDialect) -> bool {
    if dialect == ShellDialect::Unknown {
        return true;
    }

    let resolved;
    let command = if dialect == ShellDialect::Posix {
        match resolve_literal_printf_substitutions(command) {
            Ok(Some(view)) => {
                resolved = view;
                resolved.as_str()
            }
            Ok(None) => command,
            Err(()) => return symbolic_posix_may_execute_git(command),
        }
    } else {
        command
    };
    let command = command.trim();
    let (command, _) = command_after_posix_control_prefixes(command, dialect);
    let command = if dialect == ShellDialect::PowerShell {
        crate::normalize::powershell_assignment_rhs(command).unwrap_or(command)
    } else {
        command
    };
    if dialect == ShellDialect::PowerShell
        && powershell_expression_statement_without_subexpression(command)
    {
        // `"$X" …` / `$X …` is an expression statement; PowerShell refuses to
        // invoke it without the call operator, so it cannot execute Git (#273).
        return false;
    }
    let command = command
        .strip_prefix('&')
        .filter(|rest| rest.chars().next().is_some_and(char::is_whitespace))
        .map(str::trim_start)
        .unwrap_or(command);
    let stripped =
        (dialect == ShellDialect::Posix).then(|| crate::normalize::strip_wrapper_prefixes(command));
    let command = stripped
        .as_ref()
        .map_or(command, |result| result.normalized.as_ref());
    let tokens = tokenize_for_shell_dialect(command, dialect);
    if tokens
        .iter()
        .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return true;
    }
    let Some(decoded) = decode_git_semantic_words(command, dialect) else {
        return false;
    };
    if decoded.over_limit {
        return contains_git_ascii_case_insensitive(command)
            || git_semantic_scan_required(command, dialect);
    }
    if semantic_git_executable_index(&decoded.words, dialect).is_some() {
        return true;
    }
    dialect == ShellDialect::Posix && frontend_bail_may_execute_git(&decoded.words, dialect)
}

/// #260 deny-direction backstop: a command whose executable is a *known*
/// execution frontend, but whose wrapper strip bailed (dynamic option value,
/// unmodeled flag), still executes its wrapped command at runtime. Report
/// scan-required when any later word may resolve to a Git executable so the
/// ordinary regex rules evaluate the command text. Genuinely unknown
/// programs (`foo exec git …`) keep the documented argv-data default.
fn frontend_bail_may_execute_git(words: &[GitSemanticWord], dialect: ShellDialect) -> bool {
    let mut index = 0usize;
    while let Some(word) = words.get(index) {
        if !word.dynamic
            && (crate::normalize::is_env_assignment(&word.decoded)
                || matches!(word.decoded.as_str(), "exec" | "time" | "nohup" | "!"))
        {
            index += 1;
            continue;
        }
        break;
    }
    let Some(first) = words.get(index) else {
        return false;
    };
    if first.dynamic {
        return false;
    }
    let basename = first
        .decoded
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&first.decoded);
    if !crate::normalize::is_posix_execution_frontend_basename(basename) {
        return false;
    }
    words[index + 1..].iter().any(|word| {
        git_semantic_executable_may_equal(word, dialect, "git")
            || git_semantic_executable_may_equal(word, dialect, "git.exe")
            || git_semantic_executable_may_equal(word, dialect, "git-branch")
            || git_semantic_executable_may_equal(word, dialect, "git-branch.exe")
    })
}

/// Build a matching-only view of a Git invocation in a caller-proven shell.
///
/// Raw command bytes remain authoritative for history, allowlists, and output.
/// This view exists only so Windows escape syntax and Bash ANSI-C/locale
/// quoting cannot hide existing regex-backed `core.git` rules. Callers must not
/// synthesize source spans from the decoded string.
pub(crate) fn syntax_view_in_dialect(command: &str, dialect: ShellDialect) -> Option<String> {
    let resolved_substitutions = matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
        .then(|| resolve_literal_printf_substitutions(command))
        .transpose()
        .ok()
        .flatten()
        .flatten();
    let command = resolved_substitutions.as_deref().unwrap_or(command);
    let dialect = if resolved_substitutions.is_some() && dialect == ShellDialect::Unknown {
        ShellDialect::Posix
    } else {
        dialect
    };

    if dialect == ShellDialect::Unknown {
        return Some(command.to_string());
    }

    let command = command.trim();
    let (command, _) = command_after_posix_control_prefixes(command, dialect);
    if dialect == ShellDialect::PowerShell && powershell_call_expression(command) {
        let tail = powershell_call_expression_tail(command)?;
        let synthetic = match powershell_call_target(command) {
            PowerShellCallTarget::NonGit => "__dcg_non_git_command__".to_string(),
            PowerShellCallTarget::GitBranch => format!("git branch {tail}"),
            PowerShellCallTarget::Git | PowerShellCallTarget::Dynamic => format!("git {tail}"),
        };
        return Some(crate::normalize::normalize_command(&synthetic).into_owned());
    }
    let command = command
        .strip_prefix('&')
        .map(str::trim_start)
        .filter(|remainder| !remainder.is_empty())
        .unwrap_or(command);
    let stripped =
        (dialect == ShellDialect::Posix).then(|| crate::normalize::strip_wrapper_prefixes(command));
    let command = stripped
        .as_ref()
        .map_or(command, |result| result.normalized.as_ref());
    let tokens = tokenize_for_shell_dialect(command, dialect);
    if tokens
        .iter()
        .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return None;
    }

    let mut decoder = ShellTokenDecoder::new(dialect);
    let mut words = Vec::with_capacity(tokens.len());
    for token in tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
    {
        let raw = token.text(command)?;
        if let Some(decoded) = decoder.decode(raw, ShellTokenRole::Syntax) {
            words.push(decoded.into_owned());
        }
    }
    if words.is_empty() {
        return None;
    }
    if resolved_substitutions.is_some() && !decoded_words_execute_git(&words) {
        // Command-substitution output is argv data; it is not parsed again as
        // shell source. Do not let an `echo "$(printf 'git reset --hard')"`
        // data argument become a synthetic Git invocation in the regex view.
        return Some("__dcg_non_git_command__".to_string());
    }

    if let Some(semantic) = decode_git_semantic_words(command, dialect)
        && !semantic.over_limit
        && let Some(executable_index) = semantic_git_executable_index(&semantic.words, dialect)
        && semantic.words[executable_index].dynamic
    {
        let mut words: Vec<_> = semantic
            .words
            .iter()
            .map(|word| word.decoded.clone())
            .collect();
        words[executable_index] = "git".to_string();
        return Some(crate::normalize::normalize_command(&words.join(" ")).into_owned());
    }

    let decoded = words.join(" ");
    Some(crate::normalize::normalize_command(&decoded).into_owned())
}

/// Build the decoded Git regex view without reintroducing inert argv data.
///
/// `command` is the exact caller-proven shell source used by the semantic
/// executable parser. `sanitized_command` is the length-preserving view whose
/// known data-only arguments have already been masked. Most invocations can be
/// decoded directly from the sanitized view. If masking obscured an obfuscated
/// executable expression, reconstruct a canonical POSIX argv from the raw
/// semantic words, quote each word to preserve its boundary, and sanitize that
/// reconstruction before regex matching.
pub(crate) fn syntax_view_for_pattern_matching(
    command: &str,
    sanitized_command: &str,
    dialect: ShellDialect,
) -> Option<String> {
    let sanitized_view = syntax_view_in_dialect(sanitized_command, dialect);
    if dialect == ShellDialect::Unknown {
        return sanitized_view;
    }

    if dialect == ShellDialect::PowerShell && powershell_call_expression(command) {
        let tail = powershell_call_expression_tail(command)?;
        let synthetic = match powershell_call_target(command) {
            PowerShellCallTarget::NonGit => return sanitized_view,
            PowerShellCallTarget::GitBranch => format!("git branch {tail}"),
            PowerShellCallTarget::Git | PowerShellCallTarget::Dynamic => format!("git {tail}"),
        };
        let sanitized = crate::context::sanitize_for_pattern_matching(&synthetic);
        return syntax_view_in_dialect(sanitized.as_ref(), ShellDialect::PowerShell);
    }

    let semantic_command = git_semantic_command(command, dialect);
    let Some(decoded) = decode_git_semantic_words(semantic_command.as_ref(), dialect) else {
        return sanitized_view;
    };
    if decoded.over_limit {
        return sanitized_view;
    }
    let Some(executable_index) = semantic_git_executable_index(&decoded.words, dialect) else {
        return sanitized_view;
    };

    // A dynamic argv word may become a destructive option at execution time.
    // Keep the established conservative sanitized view in that case. Only the
    // executable itself may be symbolic here because the semantic parser has
    // already proven that it can resolve to Git.
    if decoded
        .words
        .iter()
        .skip(executable_index + 1)
        .any(|word| word.dynamic)
    {
        return sanitized_view;
    }

    let executable = &decoded.words[executable_index];
    let mut synthetic = if git_semantic_executable_may_equal(executable, dialect, "git-branch")
        || git_semantic_executable_may_equal(executable, dialect, "git-branch.exe")
    {
        String::from("git branch")
    } else {
        String::from("git")
    };
    for word in decoded.words.iter().skip(executable_index + 1) {
        synthetic.push(' ');
        synthetic.push_str(&shell_words::quote(&word.decoded));
    }
    let sanitized = crate::context::sanitize_for_pattern_matching(&synthetic);
    syntax_view_in_dialect(sanitized.as_ref(), ShellDialect::Posix)
}

/// Parse a direct `git branch` invocation with option arity awareness.
///
/// Regex alone cannot distinguish `git branch --format -d` (where `-d` is a
/// format string) from `git branch -d name` (where it deletes a ref). This
/// parser is deliberately narrow: it handles wrappers through the shared
/// command normalizer, recognizes Git's global options, honors `--`, and
/// consumes branch options whose following token is data. Unknown syntax
/// returns [`BranchCommandDecision::Unparsed`] so the existing regex remains a
/// conservative fallback.
pub(crate) fn branch_command_decision(command: &str) -> BranchCommandDecision {
    branch_command_decision_in_dialect(command, ShellDialect::Unknown)
}

pub(crate) fn branch_command_decision_in_dialect(
    command: &str,
    dialect: ShellDialect,
) -> BranchCommandDecision {
    if matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        match resolve_literal_printf_substitutions(command) {
            Ok(Some(resolved)) => {
                return branch_command_decision_in_dialect(&resolved, ShellDialect::Posix);
            }
            Err(()) => {
                if let Some(decision) = symbolic_posix_branch_decision(command) {
                    return decision;
                }
            }
            Ok(None) => {}
        }
    }

    if dialect == ShellDialect::Unknown {
        let trimmed = command.trim_start();
        if trimmed
            .strip_prefix('&')
            .as_ref()
            .is_some_and(|remainder| remainder.chars().next().is_some_and(char::is_whitespace))
        {
            // A leading call operator is unambiguously PowerShell syntax; in
            // POSIX shells `&` terminates the preceding command instead of
            // introducing an executable. Preserve quoted Windows paths and
            // their embedded spaces by parsing this direct Pack API call with
            // the same dialect used by hook-mode PowerShell invocations.
            return branch_command_decision_in_dialect(trimmed, ShellDialect::PowerShell);
        }
    }

    // `Pack::check` evaluates split segments first and then the original whole
    // command. Refuse the whole compound form here so an option-looking token
    // in a later command cannot be attributed to the earlier `git branch`.
    let command = command.trim();
    let (command, _) = command_after_posix_control_prefixes(command, dialect);
    let command = if dialect == ShellDialect::PowerShell {
        crate::normalize::powershell_assignment_rhs(command).unwrap_or(command)
    } else {
        command
    };
    let semantic_command = command;
    let command = command
        .strip_prefix('&')
        .map(str::trim_start)
        .filter(|remainder| !remainder.is_empty())
        .unwrap_or(command);
    if dialect == ShellDialect::PowerShell
        && powershell_call_expression(semantic_command)
        && dynamic_git_branch_may_mutate(semantic_command, dialect)
    {
        return BranchCommandDecision::Destructive;
    }
    let segments = crate::packs::split_command_segments_in_dialect(command, dialect);
    if segments.last().is_some_and(|segment| *segment != command) {
        return BranchCommandDecision::Unparsed;
    }
    if dynamic_git_branch_may_mutate(semantic_command, dialect) {
        // This path fires only when a dynamic word can occupy a mutating
        // syntax role (the all-literal case returns false), so attribute it
        // to the dynamic-token rule rather than a proven deletion (#274).
        return BranchCommandDecision::DestructiveDynamic;
    }
    let Ok(mut tokens) = branch_tokens(command, dialect) else {
        return BranchCommandDecision::Unparsed;
    };
    let mut decoder = ShellTokenDecoder::new(dialect);
    let mut environment = HashMap::new();
    let mut executable_index = 0usize;
    let executable = loop {
        let Some(raw_token) = tokens.get(executable_index) else {
            return BranchCommandDecision::NotBranch;
        };
        let Some(token) = decode_branch_syntax(&mut decoder, raw_token) else {
            executable_index += 1;
            continue;
        };
        let token = if dialect == ShellDialect::Cmd {
            token.trim_start_matches('@')
        } else {
            token.as_str()
        };
        if crate::normalize::is_env_assignment(token) {
            if let Some((name, value)) = token.split_once('=') {
                environment.insert(name.to_string(), value.to_string());
            }
            executable_index += 1;
            continue;
        }
        if dialect == ShellDialect::Cmd && token.eq_ignore_ascii_case("call") {
            executable_index += 1;
            continue;
        }
        if matches!(token, "exec" | "time" | "nohup" | "!") {
            executable_index += 1;
            continue;
        }
        let Some(executable) = token.rsplit(['/', '\\']).next() else {
            return BranchCommandDecision::NotBranch;
        };
        break executable.to_string();
    };
    let executable = executable.as_str();
    let executable = executable
        .len()
        .checked_sub(4)
        .and_then(|suffix_start| {
            executable
                .get(suffix_start..)
                .filter(|suffix| suffix.eq_ignore_ascii_case(".exe"))
                .and_then(|_| executable.get(..suffix_start))
        })
        .unwrap_or(executable);
    let dashed_branch = executable.eq_ignore_ascii_case("git-branch");
    if !executable.eq_ignore_ascii_case("git") && !dashed_branch {
        return BranchCommandDecision::NotBranch;
    }

    let mut aliases = visible_environment_aliases(&environment);
    let mut index = executable_index + 1;
    let mut found_branch = dashed_branch;
    while !found_branch {
        let Some(raw_token) = tokens.get(index) else {
            break;
        };
        let Some(token) = decode_branch_syntax(&mut decoder, raw_token) else {
            index += 1;
            continue;
        };
        let token = token.as_str();
        if token == "branch" {
            index += 1;
            found_branch = true;
            break;
        }
        if matches!(
            token,
            "-v" | "--version"
                | "-h"
                | "--help"
                | "--exec-path"
                | "--html-path"
                | "--man-path"
                | "--info-path"
        ) || token.starts_with("--list-cmds=")
        {
            return BranchCommandDecision::NonDestructive;
        }
        if token == "help" {
            return BranchCommandDecision::NonDestructive;
        }
        if matches!(
            token,
            "-p" | "--paginate"
                | "-P"
                | "--no-pager"
                | "--bare"
                | "--no-replace-objects"
                | "--literal-pathspecs"
                | "--no-literal-pathspecs"
                | "--glob-pathspecs"
                | "--noglob-pathspecs"
                | "--icase-pathspecs"
                | "--no-optional-locks"
                | "--no-lazy-fetch"
                | "--no-advice"
        ) {
            index += 1;
            continue;
        }
        if token == "-c" {
            let Some(raw_config) = tokens.get(index + 1) else {
                return BranchCommandDecision::Unparsed;
            };
            let Some(config) = decode_branch_syntax(&mut decoder, raw_config) else {
                return BranchCommandDecision::Unparsed;
            };
            insert_visible_alias(&mut aliases, &config);
            index += 2;
            continue;
        }
        if token == "--config-env" {
            let Some(raw_config_env) = tokens.get(index + 1) else {
                return BranchCommandDecision::Unparsed;
            };
            let Some(config_env) = decode_branch_syntax(&mut decoder, raw_config_env) else {
                return BranchCommandDecision::Unparsed;
            };
            insert_visible_config_env_alias(&mut aliases, &environment, &config_env);
            index += 2;
            continue;
        }
        if matches!(
            token,
            "-C" | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--shallow-file"
                | "--attr-source"
        ) {
            if tokens.get(index + 1).is_none() {
                return BranchCommandDecision::Unparsed;
            }
            index += 2;
            continue;
        }
        if let Some(config) = token.strip_prefix("-c").filter(|config| !config.is_empty()) {
            insert_visible_alias(&mut aliases, config);
            index += 1;
            continue;
        }
        if let Some(config_env) = token.strip_prefix("--config-env=") {
            insert_visible_config_env_alias(&mut aliases, &environment, config_env);
            index += 1;
            continue;
        }
        if token.starts_with("-C")
            || [
                "--exec-path=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--config-env=",
                "--attr-source=",
            ]
            .iter()
            .any(|prefix| token.starts_with(prefix))
        {
            index += 1;
            continue;
        }
        if !token.starts_with('-') {
            let Some(mut expansion) = resolve_visible_branch_alias(token, &aliases) else {
                if !aliases.contains_key(token) && !is_known_git_command(token) {
                    let remaining: Vec<_> = tokens
                        .iter()
                        .skip(index + 1)
                        .filter_map(|raw| decode_branch_syntax(&mut decoder, raw))
                        .map(|decoded| GitSemanticWord {
                            decoded,
                            dynamic: false,
                            may_split: false,
                        })
                        .collect();
                    if semantic_branch_argv_may_mutate(&remaining, dialect) {
                        return BranchCommandDecision::Destructive;
                    }
                }
                return BranchCommandDecision::NotBranch;
            };
            for raw_argument in tokens.iter().skip(index + 1) {
                if let Some(argument) = decode_branch_syntax(&mut decoder, raw_argument) {
                    expansion.push(argument);
                }
            }
            tokens = expansion;
            decoder = ShellTokenDecoder::new(ShellDialect::Unknown);
            index = 1;
            found_branch = true;
            break;
        }
        return if token.starts_with('-') {
            BranchCommandDecision::Unparsed
        } else {
            BranchCommandDecision::NotBranch
        };
    }

    if !found_branch {
        return BranchCommandDecision::NotBranch;
    }

    let mut mutation = BranchMutationState::default();
    while let Some(raw_token) = tokens.get(index) {
        let Some(token) = decode_branch_syntax(&mut decoder, raw_token) else {
            index += 1;
            continue;
        };
        let token = token.as_str();
        if matches!(token, "--" | "--end-of-options") {
            return mutation.decision();
        }
        if token.starts_with("--") {
            if matches!(token, "--help" | "--help-all") {
                return BranchCommandDecision::NonDestructive;
            }
            let Some(resolved) = resolve_branch_long_option(token) else {
                // A confirmed direct `git branch` invocation with an unknown
                // or ambiguous option exits during parse-options and cannot
                // mutate refs.
                return BranchCommandDecision::NonDestructive;
            };
            if resolved.inline_value && matches!(resolved.arity, BranchLongOptionArity::None) {
                return BranchCommandDecision::NonDestructive;
            }
            match resolved.name {
                "delete" => {
                    if resolved.negated {
                        mutation.delete_bits &= !1;
                    } else {
                        mutation.delete_bits |= 1;
                    }
                }
                "force" => mutation.force = !resolved.negated,
                _ => {}
            }
            let effective_arity = if resolved.negated {
                BranchLongOptionArity::None
            } else {
                resolved.arity
            };
            match effective_arity {
                BranchLongOptionArity::None | BranchLongOptionArity::OptionalAttached => {
                    index += 1;
                }
                BranchLongOptionArity::Required if resolved.inline_value => index += 1,
                BranchLongOptionArity::Required => {
                    if tokens.get(index + 1).is_none() {
                        return BranchCommandDecision::NonDestructive;
                    }
                    index += 2;
                }
                BranchLongOptionArity::LastArgDefault if resolved.inline_value => index += 1,
                BranchLongOptionArity::LastArgDefault => {
                    index += 1 + usize::from(tokens.get(index + 1).is_some());
                }
            }
            continue;
        }
        if let Some(flags) = token.strip_prefix('-') {
            if flags.is_empty() {
                index += 1;
                continue;
            }
            let mut chars = flags.chars();
            while let Some(flag) = chars.next() {
                if flag == 'h' {
                    return BranchCommandDecision::NonDestructive;
                }
                match flag {
                    'd' => mutation.delete_bits |= 1,
                    'D' => mutation.delete_bits |= 2,
                    'f' => mutation.force = true,
                    'M' | 'C' => mutation.forced_move_or_copy = true,
                    'v' | 'q' | 'r' | 'a' | 'm' | 'c' | 'l' | 'i' => {}
                    'u' | 't' => {}
                    _ => return BranchCommandDecision::NonDestructive,
                }
                // `-u <upstream>` consumes the following token; in a combined
                // form such as `-vuorigin/main`, the remainder is its value.
                if flag == 'u' {
                    if chars.as_str().is_empty() {
                        if tokens.get(index + 1).is_none() {
                            return BranchCommandDecision::NonDestructive;
                        }
                        index += 1;
                    }
                    break;
                }
                // `-t`/`--track` has an optional argument that Git accepts
                // only when attached (`-tdirect`, `-tinherit`). The remainder
                // is data, so letters such as the `d` in `direct` are not
                // additional short flags. A bare `-t` does not consume the
                // following token, which may therefore still be `-d`.
                if flag == 't' && !chars.as_str().is_empty() {
                    break;
                }
            }
        }
        index += 1;
    }

    mutation.decision()
}

/// Create the core git pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.git".to_string(),
        name: "Core Git",
        description: "Protects against destructive git commands that can lose uncommitted work, \
                      rewrite history, or destroy stashes",
        keywords: &["git"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Branch creation is safe
        safe_pattern!(
            "checkout-new-branch",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+-b\s+"
        ),
        safe_pattern!(
            "checkout-orphan",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+--orphan\s+"
        ),
        // restore --staged only affects the index, not the working tree, so it
        // is safe. `--staged`/`-S` is a flag that may appear in ANY position
        // (e.g. `git restore . --staged` is identical to `git restore --staged .`),
        // so match it anywhere after `restore` rather than only immediately
        // after it (see issue #156). Still exclude `--worktree`/`-W`, which make
        // the restore touch the working tree (handled by `restore-worktree-explicit`).
        safe_pattern!(
            "restore-staged-long",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\b(?=\s)(?=.*\s--staged\b)(?!.*\s(?:--worktree|-W)\b)"
        ),
        safe_pattern!(
            "restore-staged-short",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\b(?=\s)(?=.*\s-S\b)(?!.*\s(?:--worktree|-W)\b)"
        ),
        // clean dry-run just previews, doesn't delete
        safe_pattern!(
            "clean-dry-run-short",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*clean\s+-[a-z]*n[a-z]*"
        ),
        safe_pattern!(
            "clean-dry-run-long",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*clean\s+--dry-run"
        ),
        // `git lfs prune --dry-run` reports what it would delete and deletes
        // nothing (Refs PR #383). The flag must be a whole token — `--dry-runx`
        // is not it — and quoted argument text cannot supply it, because the
        // walk stops at a quote or a redirection glyph.
        safe_pattern!(
            "lfs-prune-dry-run",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*lfs\s+prune(?:\s+[^\s;&|<>\x22']+)*\s+--dry-run(?:\s|$)"
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // Evaluated explicitly by the bounded visible-alias semantic pass.
        // The regex is intentionally unsatisfiable so ordinary text matching
        // cannot manufacture an unverified finding.
        DestructivePattern {
            regex: crate::packs::regex_engine::LazyCompiledRegex::new(r"(?!)"),
            reason: GIT_ALIAS_UNVERIFIED_REASON,
            name: Some(GIT_ALIAS_UNVERIFIED_RULE),
            severity: crate::packs::Severity::High,
            explanation: Some(
                "Review the fully expanded Git executable, alias chain, shell-alias body, and appended arguments before allowing execution. Dynamic shell values, cycles, and commands beyond the semantic parser's bounds can hide destructive operations.",
            ),
            suggestions: &[],
            executables: None,
        },
        // Evaluated explicitly by the branch semantic parser when a dynamic
        // word may expand or field-split into a deletion / force flag (#274).
        // The regex is intentionally unsatisfiable so ordinary text matching
        // cannot manufacture this finding.
        DestructivePattern {
            regex: crate::packs::regex_engine::LazyCompiledRegex::new(r"(?!)"),
            reason: BRANCH_DYNAMIC_REASON,
            name: Some(BRANCH_DYNAMIC_RULE),
            severity: crate::packs::Severity::High,
            explanation: Some(
                "An unquoted command substitution or variable in a git branch invocation is \
                 expanded and field-split by the shell before git parses it, so its output can \
                 inject `-D`, `-f`, `-M`, or `-C` and turn a branch creation into a deletion or \
                 forced ref update. dcg cannot statically bound the expansion's output.\n\n\
                 The reliable fix is to resolve the dynamic value first and rerun the command \
                 with the literal branch name.\n\n\
                 For a branch *creation*, these spellings are safe without any exception:\n\
                 - Quote the name so it stays one word: git branch \"backup-$(date +%s)\"\n\
                 - End option parsing first: git branch -- backup-$(date +%s)\n\n\
                 Both guarantee the expansion cannot become a flag. They do not unlock a command \
                 that already carries a literal deletion/force flag (`-D`, `-d`, `-f`, `-M`, \
                 `-C`) — branch deletion stays gated on its own merits.",
            ),
            suggestions: &const {
                [
                    PatternSuggestion::new(
                        "Resolve the dynamic value first, then rerun with the literal branch name",
                        "The expansion is the problem; a literal name is evaluated on its own merits",
                    ),
                    PatternSuggestion::new(
                        "git branch \"{name}\"",
                        "For a creation: quote the branch name so the expansion stays a single non-flag word",
                    ),
                    PatternSuggestion::new(
                        "git branch -- {name}",
                        "For a creation: `--` ends option parsing, so expanded output cannot become a flag",
                    ),
                ]
            },
            executables: None,
        },
        // checkout -- discards uncommitted changes
        destructive_pattern!(
            "checkout-discard",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+--\s+",
            "git checkout -- discards uncommitted changes permanently. Use 'git stash' first.",
            High,
            "git checkout -- <path> discards all uncommitted changes to the specified files \
             in your working directory. These changes are permanently lost - they cannot be \
             recovered because they were never committed.\n\n\
             Safer alternatives:\n\
             - git stash: Save changes temporarily, restore later with 'git stash pop'\n\
             - git diff <path>: Review what would be lost before discarding\n\n\
             Preview changes first:\n  git diff -- <path>\n\n\
             Recovering from a failed `git pull --rebase`?\n\
             Run `dcg rebase-recover` in this repo, then retry the command on its own line \
             (a leading `cd <repo> &&` is fine; nothing else may share the line). This \
             issues a short-lived, single-shot permit that unblocks this rule only. A rebase already \
             in progress (`.git/rebase-merge/` or `.git/rebase-apply/` present) auto-allows \
             the same rule without a permit.",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash",
                        "Save changes temporarily, restore later with 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git diff -- {path}",
                        "Review what would be lost before discarding",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "checkout-ref-discard",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
            "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first.",
            High,
            "git checkout <ref> -- <path> replaces your working tree files with versions from \
             another commit or branch. Any uncommitted changes to those files are permanently \
             lost - they cannot be recovered.\n\n\
             Safer alternatives:\n\
             - git stash: Save changes first, then checkout, then restore with 'git stash pop'\n\
             - git show <ref>:<path>: View the file content without overwriting. View only — \
             redirecting the output back onto <path> (`git show <ref>:<path> > <path>`) reaches \
             the exact overwrite this rule denies. To capture the content, redirect to a NEW \
             file: `git show <ref>:<path> > <path>.from-ref`\n\n\
             Preview what would change:\n  git diff HEAD <ref> -- <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash",
                        "Save changes first, then checkout, then restore with 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git show {ref}:{path}",
                        "View the file content without overwriting (view only — do not redirect back onto the same path)",
                    ),
                    PatternSuggestion::new(
                        "git diff HEAD {ref} -- {path}",
                        "Preview what would change before overwriting",
                    ),
                ]
            }
        ),
        // `git show <ref>:<path>` is safe on its own (stdout only), and the
        // checkout-ref-discard remediation above recommends it. But redirected
        // back onto the SAME path it reaches the identical end state that rule
        // denies: the working-tree file is overwritten with another commit's
        // content and uncommitted changes to it are lost (#373). Deny only the
        // same-path shape (a backreference pins redirect target == shown
        // path), so `git show HEAD:f > f.from-ref` and every other capture to
        // a new file stays allowed. Covers `>`, `>>`, and `>|`; the piped
        // `| tee <path>` spelling cannot be a core.git pattern (this pack is
        // matched per pipeline segment by design), so the prose warns about
        // it instead.
        destructive_pattern!(
            "show-redirect-overwrite-source",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*show\s+[^\s:]+:(\S+)\s*(?:>>|>\|?)\s*(?:\./)?\1(?:[\s;&|)]|$)",
            "git show <ref>:<path> redirected onto the same <path> overwrites the working tree file, exactly like the denied 'git checkout <ref> -- <path>'.",
            High,
            "Redirecting `git show <ref>:<path>` back onto `<path>` replaces the working-tree \
             file with the version from another commit or branch. Any uncommitted changes to \
             that file are permanently lost — the same hazard `checkout-ref-discard` exists to \
             prevent, reached through a redirect instead of a checkout.\n\n\
             The piped spelling `git show <ref>:<path> | tee <path>` reaches the same \
             overwrite and is just as unsafe.\n\n\
             Safer alternatives:\n\
             - Redirect to a NEW file, then inspect: `git show <ref>:<path> > <path>.from-ref`\n\
             - git stash: Save changes first, then take the other version, then \
             'git stash pop'\n\
             - Bare `git show <ref>:<path>` (no redirect) only prints and is always allowed.\n\n\
             Preview what would change:\n  git diff HEAD <ref> -- <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git show {ref}:{path} > {path}.from-ref",
                        "Capture the other version into a NEW file instead of overwriting the working copy",
                    ),
                    PatternSuggestion::new(
                        "git stash",
                        "Save changes first, then take the other version, then 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git diff HEAD {ref} -- {path}",
                        "Preview what would change before overwriting",
                    ),
                ]
            }
        ),
        // restore without --staged/-S affects the working tree. Detect the
        // staged flag in ANY position (not just immediately after `restore`),
        // so `git restore . --staged` is correctly recognized as safe and is
        // NOT blocked here (issue #156). `--worktree`/`-W` cases are caught by
        // `restore-worktree-explicit` below regardless of `--staged`.
        destructive_pattern!(
            "restore-worktree",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\b(?=\s)(?!.*\s(?:--staged|-S)\b)",
            "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first.",
            High,
            "git restore <path> discards uncommitted changes in your working directory, \
             reverting files to their last committed state. Changes that were never \
             committed are permanently lost.\n\n\
             Safer alternatives:\n\
             - git restore --staged <path>: Only unstage, keeps working directory changes\n\
             - git stash: Save all changes temporarily\n\
             - git diff <path>: Review what would be lost\n\n\
             Preview changes first:\n  git diff <path>\n\n\
             Recovering from a failed `git pull --rebase`?\n\
             Run `dcg rebase-recover` in this repo, then retry the command on its own line \
             (a leading `cd <repo> &&` is fine; nothing else may share the line). This \
             issues a short-lived, single-shot permit that unblocks this rule only. A rebase already \
             in progress (`.git/rebase-merge/` or `.git/rebase-apply/` present) auto-allows \
             the same rule without a permit.",
            &const {
                [
                    PatternSuggestion::new(
                        "git restore --staged {path}",
                        "Only unstage, keeps working directory changes intact",
                    ),
                    PatternSuggestion::new(
                        "git stash",
                        "Save all changes temporarily, restore later with 'git stash pop'",
                    ),
                    PatternSuggestion::new(
                        "git diff {path}",
                        "Review what would be lost before discarding",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "restore-worktree-explicit",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*restore\s+.*(?:--worktree|-W\b)",
            "git restore --worktree/-W discards uncommitted changes permanently.",
            High,
            "git restore --worktree (or -W) explicitly targets your working directory, \
             discarding uncommitted changes. Even when combined with --staged, the worktree \
             changes are permanently lost.\n\n\
             Safer alternatives:\n\
             - git restore --staged <path>: Only unstage, keeps working directory\n\
             - git stash: Save changes first\n\n\
             Preview changes first:\n  git diff <path>",
            &const {
                [
                    PatternSuggestion::new(
                        "git restore --staged {path}",
                        "Only unstage, keeps working directory changes intact",
                    ),
                    PatternSuggestion::new(
                        "git stash",
                        "Save all changes temporarily before discarding",
                    ),
                    PatternSuggestion::new(
                        "git diff {path}",
                        "Review what would be lost before discarding",
                    ),
                ]
            }
        ),
        // reset --hard destroys uncommitted work (CRITICAL - extremely common mistake)
        destructive_pattern!(
            "reset-hard",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*reset\s+--hard",
            "git reset --hard destroys uncommitted changes. Use 'git stash' first.",
            Critical,
            "git reset --hard discards ALL uncommitted changes in your working directory \
             AND staging area. This is one of the most dangerous git commands because \
             changes that were never committed cannot be recovered by any means.\n\n\
             What gets destroyed:\n\
             - All modified files revert to the target commit\n\
             - All staged changes are lost\n\
             - Untracked files remain (use git clean to remove those)\n\n\
             Safer alternatives:\n\
             - git reset --soft <ref>: Move HEAD but keep all changes staged\n\
             - git reset --mixed <ref>: Move HEAD, unstage changes, keep working dir (default)\n\
             - git stash: Save changes before resetting\n\n\
             Preview what would be lost:\n  git status && git diff",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash",
                        "Save all uncommitted changes before reset",
                    ),
                    PatternSuggestion::new(
                        "git reset --soft HEAD~1",
                        "Undo commit but keep all changes staged",
                    ),
                    PatternSuggestion::new(
                        "git reset --mixed HEAD~1",
                        "Undo commit, unstage changes, but keep working directory",
                    ),
                    PatternSuggestion::gated(
                        "git checkout -- {file}",
                        "Discards changes in one file only — still destructive, so dcg gates it too",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "reset-merge",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*reset\s+--merge",
            "git reset --merge can lose uncommitted changes.",
            High,
            "git reset --merge resets the index and updates files in the working tree that \
             differ between the target commit and HEAD, but keeps changes that are not staged. \
             However, if there are uncommitted changes in files that need to be updated, \
             those changes will be lost.\n\n\
             Safer alternatives:\n\
             - git stash: Save uncommitted changes before reset\n\
             - git merge --abort: If in the middle of a merge, abort safely\n\n\
             Preview what would change:\n  git status && git diff",
            &const {
                [
                    PatternSuggestion::new("git stash", "Save uncommitted changes before reset"),
                    PatternSuggestion::new(
                        "git merge --abort",
                        "Abort the current merge safely without losing changes",
                    ),
                    PatternSuggestion::new(
                        "git status && git diff",
                        "Preview what would change before resetting",
                    ),
                ]
            }
        ),
        // clean -f deletes untracked files (CRITICAL - permanently removes files)
        destructive_pattern!(
            "clean-force",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*clean\s+(?:-[a-z]*f|--force\b)",
            "git clean -f/--force removes untracked files permanently. Review with 'git clean -n' first.",
            Critical,
            "git clean -f permanently deletes untracked files from your working directory. \
             These are files that have never been committed to git, so they cannot be \
             recovered from git history. If you haven't backed them up elsewhere, they \
             are gone forever.\n\n\
             Common dangerous combinations:\n\
             - git clean -fd: Also removes untracked directories\n\
             - git clean -xf: Also removes ignored files (build artifacts, .env, etc.)\n\n\
             Safer alternatives:\n\
             - git clean -n: Dry-run, shows what would be deleted\n\
             - git clean -i: Interactive mode, choose what to delete\n\n\
             ALWAYS preview first:\n  git clean -n -d",
            &const {
                [
                    PatternSuggestion::new(
                        "git clean -n",
                        "Dry run first (shows what would be deleted)",
                    ),
                    PatternSuggestion::new("git clean -nd", "Dry run including directories"),
                    PatternSuggestion::new(
                        "git clean -i",
                        "Interactive mode, choose what to delete",
                    ),
                    PatternSuggestion::new(
                        "git stash --include-untracked",
                        "Stash instead of delete (recoverable)",
                    ),
                ]
            }
        ),
        // force push can destroy remote history (CRITICAL - affects shared history)
        // `push-force-long` — `.*--force` would match `--force` embedded in a
        // branch name like `feature--force` (false positive). Use the
        // `(?:\S+\s+)*` token walker so we only reach a fresh arg token.
        destructive_pattern!(
            "push-force-long",
            // Bounded walker between `git`/`push` and the force flag — `(?:\S+\s+)*`
            // would walk past shell metacharacters (`&;|`()<>` + backticks),
            // false-positiving on cases where a chained shell command itself
            // happens to contain `git push --force` text. Excluding those
            // chars forces the walker to stay within a single command segment.
            // Matches the fix already applied to `branch-force-delete` (#121).
            //
            // The evaluator applies this regex only to its role-aware,
            // string-data-sanitized command view. That boundary is essential:
            // the regex alone cannot distinguish a real force push from the
            // same words inside `git commit -m "..."`.
            r"(?:^|[^[:alnum:]_-])git\s+(?:[^\s&;|`()<>]+\s+)*push\s+(?:[^\s&;|`()<>]+\s+)*--force(?![-a-z])",
            "Force push can destroy remote history. Use --force-with-lease if necessary.",
            Critical,
            "git push --force overwrites remote history with your local history. This can \
             permanently destroy commits that others have already pulled, causing data loss \
             for your entire team. Collaborators may lose work, and recovering requires \
             manual intervention from everyone affected.\n\n\
             What can go wrong:\n\
             - Commits others pushed are deleted from remote\n\
             - Team members get diverged histories\n\
             - CI/CD pipelines may reference deleted commits\n\n\
             Safer alternative:\n\
             - git push --force-with-lease: Only forces if remote matches your last fetch\n\n\
             Check remote state first:\n  git fetch && git log origin/<branch>..HEAD",
            &const {
                [
                    PatternSuggestion::new(
                        "git push --force-with-lease",
                        "Fails if remote has new commits you haven't fetched",
                    ),
                    PatternSuggestion::new(
                        "git push --force-with-lease --force-if-includes",
                        "Even safer: also checks that your local ref includes the remote ref",
                    ),
                    PatternSuggestion::new(
                        "git fetch && git log origin/{branch}..HEAD",
                        "Preview what you're about to overwrite on the remote",
                    ),
                ]
            }
        ),
        // `push-force-short` — catch combined forms (`-uf`, `-fv`, `-vf`,
        // `-fuvq`) that evaluate to `-f` at parse time. The token-walker
        // `(?:\S+\s+)*` skips unrelated args (branches/remotes) WITHOUT
        // descending into hyphens inside a single token — so a branch name
        // like `feature-f` or `hotfix-f` no longer false-matches a flag
        // containing `f`. `--force-with-lease` is safer and is already
        // excluded by the `push-force-long` rule (which takes precedence).
        destructive_pattern!(
            "push-force-short",
            // Bounded walker — see `push-force-long` for rationale and the
            // evaluator-owned role-aware data masking. (#124)
            r"(?:^|[^[:alnum:]_-])git\s+(?:[^\s&;|`()<>]+\s+)*push\s+(?:[^\s&;|`()<>]+\s+)*-[a-zA-Z]*f[a-zA-Z]*\b",
            "Force push (-f) can destroy remote history. Use --force-with-lease if necessary.",
            Critical,
            "git push -f (short for --force) overwrites remote history with your local history. \
             This can permanently destroy commits that others have already pulled, causing data \
             loss for your entire team.\n\n\
             What can go wrong:\n\
             - Commits others pushed are deleted from remote\n\
             - Team members get diverged histories\n\
             - CI/CD pipelines may reference deleted commits\n\n\
             Safer alternative:\n\
             - git push --force-with-lease: Only forces if remote matches your last fetch\n\n\
             Check remote state first:\n  git fetch && git log origin/<branch>..HEAD",
            &const {
                [
                    PatternSuggestion::new(
                        "git push --force-with-lease",
                        "Fails if remote has new commits you haven't fetched",
                    ),
                    PatternSuggestion::new(
                        "git push --force-with-lease --force-if-includes",
                        "Even safer: also checks that your local ref includes the remote ref",
                    ),
                    PatternSuggestion::new(
                        "git fetch && git log origin/{branch}..HEAD",
                        "Preview what you're about to overwrite on the remote",
                    ),
                ]
            }
        ),
        // Branch deletion and forced ref updates cross a user-intent boundary.
        // Lowercase `-d` checks merge state, but still removes the branch name,
        // tracking configuration, and convenient reflog anchor. Agents must
        // therefore ask before every delete form, not only force deletion (#209).
        //
        // Intermediate tokens between `git` and `branch`, and between
        // `branch` and the force-flag, are constrained to NOT contain
        // shell metacharacters (`&;|`()<>` plus backticks). That keeps
        // the match within a single command: forms like
        //   branch=$(git branch --show-current) && git push --force-with-lease ...
        // can no longer span the `)` and `&&` boundary back into a
        // `--force` flag belonging to a different command (#121).
        //
        // The force-flag tail uses `(?:\s|$)` instead of `\b` because
        // `\b` treats hyphens as word boundaries, so `--force\b` falsely
        // matched the `--force` prefix of `--force-with-lease` and
        // `--force-if-includes` (#121).
        //
        // Token separators use `[ \t]+` rather than `\s+` so the walkers
        // cannot bridge a newline — a POSIX command separator — from a benign
        // `git branch --list` line into an unrelated later line whose first
        // token starts with `-` (for example a `[ -d "$p/.git" ]` test) (#246).
        destructive_pattern!(
            "branch-force-delete",
            r"(?:^|[^[:alnum:]_-])(?i:(?:git(?:\.exe)?[ \t]+(?:[^\s&;|`()<>]+[ \t]+)*branch|git-branch(?:\.exe)?))[ \t]+(?:[^\s&;|`()<>]+[ \t]+)*(?:-[a-zA-Z]*[dDfMC][a-zA-Z]*(?:\s|$)|--(?:d(?:e(?:l(?:e(?:t(?:e)?)?)?)?)?|forc(?:e)?)(?:\s|$))",
            "git branch deletion or forced ref updates require explicit user approval.",
            High,
            "git branch -d, -D, or --delete removes a branch reference. Lowercase -d \
             checks that Git considers the branch merged, but it still discards the branch \
             name, tracking configuration, and convenient reflog reference. The user may \
             intentionally need any of those. The -f/--force forms can also move an existing \
             branch reference away from commits. Agents must not cross either user-intent \
             boundary without explicit approval. The -M and -C shorthands force-overwrite an \
             existing rename/copy target and require the same approval.\n\n\
             Review without changing refs:\n\
             - git branch -vv: Show branch tips and upstream tracking state\n\
             - git branch --merged / --no-merged: Review Git's merge classification\n\
             - git log --oneline --decorate <branch>: Inspect the branch history\n\n\
             Recovery if deletion already happened:\n\
               git reflog  # Find the commit hash while it is still retained\n\
               git branch <branch> <commit-hash>",
            &const {
                [
                    PatternSuggestion::new(
                        "git branch -vv",
                        "Review branch tips and upstream tracking state without changing refs",
                    ),
                    PatternSuggestion::new(
                        "git branch --merged && git branch --no-merged",
                        "Review Git's merged and unmerged classifications before asking approval",
                    ),
                    PatternSuggestion::new(
                        "git log {branch} --oneline -10",
                        "Review branch commits without deleting or moving the ref",
                    ),
                ]
            }
        ),
        // stash destruction (Medium: single stash, recoverable via fsck/unreachable objects)
        destructive_pattern!(
            "stash-drop",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*stash\s+drop",
            "git stash drop deletes a single stash. Recoverable via `git fsck` (unreachable objects).",
            Medium,
            "git stash drop removes a specific stash entry from your stash list. The stashed \
             changes become unreferenced but remain in git's object database temporarily. \
             They can often be recovered using git fsck, but this is not guaranteed and \
             becomes harder over time as git garbage collects.\n\n\
             Safer alternatives:\n\
             - git stash pop: Apply and drop in one step (only drops if apply succeeds)\n\
             - git stash apply: Apply without dropping, verify first\n\n\
             Recovery if needed:\n\
               git fsck --unreachable | grep commit\n\
               git show <commit-hash>  # Inspect each to find your stash",
            &const {
                [
                    PatternSuggestion::new(
                        "git stash pop",
                        "Apply and drop atomically (only drops if apply succeeds)",
                    ),
                    PatternSuggestion::new(
                        "git stash apply",
                        "Apply without dropping, verify changes first",
                    ),
                    PatternSuggestion::new(
                        "git stash show stash@{0}",
                        "Preview stash contents before dropping",
                    ),
                    PatternSuggestion::new(
                        "git stash list",
                        "Review all stashes before dropping any",
                    ),
                ]
            }
        ),
        // stash clear destroys ALL stashes (CRITICAL)
        destructive_pattern!(
            "stash-clear",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*stash\s+clear",
            "git stash clear permanently deletes ALL stashed changes.",
            Critical,
            "git stash clear removes ALL stash entries at once. Unlike git stash drop, \
             which removes one at a time, this command wipes your entire stash list. \
             All stashed changes become unreferenced and are very difficult to recover.\n\n\
             What gets destroyed:\n\
             - All entries in 'git stash list' are removed\n\
             - Multiple sets of saved work-in-progress may be lost\n\n\
             Safer alternatives:\n\
             - git stash drop stash@{n}: Remove one specific stash at a time\n\
             - git stash list: Review what would be lost first\n\
             - git stash show stash@{n}: Inspect each stash before deciding\n\n\
             Recovery (difficult, not guaranteed):\n\
               git fsck --unreachable | grep commit",
            &const {
                [
                    PatternSuggestion::gated(
                        "git stash drop stash@{n}",
                        "Drops one stash at a time instead of all — still deletes stashed work, so dcg gates it too",
                    ),
                    PatternSuggestion::new("git stash list", "Review all stashes before clearing"),
                    PatternSuggestion::new(
                        "git stash show stash@{n}",
                        "Inspect each stash before deciding to delete",
                    ),
                ]
            }
        ),
        // ---- Git LFS (Refs PR #383) -----------------------------------------
        //
        // `git lfs` is dispatched to the `git-lfs` helper, so it is a known
        // subcommand rather than an unverifiable alias. Its read-only verbs
        // (`ls-files`, `status`, `env`, `fetch`, `pull`, `track`, `locks`,
        // `migrate info`) carry no rule; the three verbs that destroy data or
        // rewrite history do.
        destructive_pattern!(
            "lfs-migrate-rewrite",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*lfs\s+migrate\s+(?:import|export)(?![\w-])",
            "git lfs migrate import/export rewrites history — every commit in the range gets a new SHA.",
            High,
            "git lfs migrate import/export rewrites the commits it touches:\n\n\
             - Every rewritten commit gets a NEW SHA, so the branch diverges from\n  \
             every clone and a force-push is required to publish it\n\
             - Collaborators' branches, open PRs and CI pins all break\n\
             - `--everything` rewrites every local ref, not just the current branch\n\
             - The original objects survive only until the next `git gc` prunes\n  \
             the unreachable ones\n\n\
             Preview without rewriting anything:\n\
             - git lfs migrate info: report what WOULD be converted\n\
             - git lfs migrate info --everything --above=1MB\n\n\
             Back the refs up first: git branch backup/pre-lfs-migrate",
            &const {
                [
                    PatternSuggestion::new(
                        "git lfs migrate info",
                        "Reports what would be converted without rewriting any commit",
                    ),
                    PatternSuggestion::new(
                        "git branch backup/pre-lfs-migrate",
                        "Keep a ref to the pre-rewrite history before migrating",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "lfs-prune",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*lfs\s+prune(?![\w-])",
            "git lfs prune deletes local LFS objects; with --force it deletes objects the remote does not have.",
            Medium,
            "git lfs prune deletes local Git LFS objects from .git/lfs/objects:\n\n\
             - Objects older than the fetch/push retention window are removed\n\
             - Anything the remote also has is re-downloadable, so the usual\n  \
             case is recoverable — at the cost of a re-fetch\n\
             - `--force` / `-f` prunes objects even when the remote is NOT known\n  \
             to have them, which can destroy the only copy of unpushed content\n\
             - `--recent` widens what is kept; it does not make the delete safer\n\n\
             Check what would go first:\n\
             - git lfs prune --dry-run --verbose\n\
             - git lfs prune --verify-remote: only prune what the remote confirms",
            &const {
                [
                    PatternSuggestion::new(
                        "git lfs prune --dry-run --verbose",
                        "Lists the objects that would be deleted without deleting them",
                    ),
                    PatternSuggestion::gated(
                        "git lfs prune --verify-remote",
                        "Only prunes objects the remote confirms it has — still a delete, so dcg gates it too",
                    ),
                ]
            }
        ),
        destructive_pattern!(
            "lfs-uninstall",
            r"(?:^|[^[:alnum:]_-])git\s+(?:\S+\s+)*lfs\s+uninstall(?![\w-])",
            "git lfs uninstall removes the LFS filters and hooks, so LFS files check out as pointer text.",
            Medium,
            "git lfs uninstall removes Git LFS from the git configuration:\n\n\
             - The clean/smudge filters go, so tracked binaries check out as\n  \
             one-line pointer files — and a later `git add`/commit can write\n  \
             those pointers back over real content\n\
             - The pre-push hook goes, so LFS objects stop being uploaded and a\n  \
             push can publish pointers with no objects behind them\n\
             - `--system` and `--global` affect EVERY repository on the machine,\n  \
             not just this one\n\n\
             Check the current configuration first: git lfs env\n\
             Re-enable with: git lfs install",
            &const {
                [
                    PatternSuggestion::new(
                        "git lfs env",
                        "Shows the filters and hooks that would be removed",
                    ),
                    PatternSuggestion::new(
                        "git lfs install",
                        "Restores the LFS filters and hooks if they were removed",
                    ),
                ]
            }
        ),
    ]
}

#[cfg(test)]
mod tests {
    //! Unit tests for core.git pack using the `test_helpers` framework.
    //!
    //! This module serves as an example of how to use the pack testing
    //! infrastructure. See `docs/pack-testing-guide.md` for details.

    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;
    use std::fmt::Write as _;

    // =========================================================================
    // Git LFS (Refs PR #383): `git lfs` is a known subcommand, and its three
    // destructive verbs carry their own rules.
    // =========================================================================

    #[test]
    fn git_lfs_destructive_verbs_are_covered() {
        let pack = create_pack();

        for (command, pattern, severity) in [
            (
                "git lfs migrate import --everything --above=1MB",
                "lfs-migrate-rewrite",
                Severity::High,
            ),
            (
                "git lfs migrate export --include='*.psd'",
                "lfs-migrate-rewrite",
                Severity::High,
            ),
            ("git lfs prune", "lfs-prune", Severity::Medium),
            ("git lfs prune --force", "lfs-prune", Severity::Medium),
            ("git lfs uninstall", "lfs-uninstall", Severity::Medium),
            (
                "git lfs uninstall --system",
                "lfs-uninstall",
                Severity::Medium,
            ),
            // Global git flags between `git` and `lfs`.
            (
                "git -C /srv/repo lfs prune --force",
                "lfs-prune",
                Severity::Medium,
            ),
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks_with_pattern(&pack, command, pattern);
            assert_blocks_with_severity(&pack, command, severity);
        }

        // Read-only and routine LFS verbs stay allowed — `migrate info` in
        // particular is the recommended preview for `migrate import`.
        for command in [
            "git lfs ls-files",
            "git lfs ls-files --long",
            "git lfs status",
            "git lfs env",
            "git lfs version",
            "git lfs fetch origin main",
            "git lfs pull",
            "git lfs checkout",
            "git lfs track '*.psd'",
            "git lfs install",
            "git lfs locks",
            "git lfs migrate info --everything --above=1MB",
            "git lfs prune --dry-run --verbose",
        ] {
            assert_allows(&pack, command);
        }
    }

    // =========================================================================
    // PowerShell expression statements are not command invocations (#273)
    // =========================================================================

    /// A PS statement whose first token is a quoted string or variable is an
    /// expression statement; PowerShell refuses to invoke it without `&`, so
    /// the git semantic layer must not treat it as a possible Git executable.
    #[test]
    fn powershell_expression_statement_is_not_a_git_invocation() {
        for command in [
            "\"$X\" \"$Y\"",
            "\"$BIN\" run \"$ARG\"",
            "\"$X\" y",
            "$X $Y",
            "\"$X\" -D",
            "\"$env:TOOL\" \"$env:ARG\"",
            "$x = \"$Y\" \"$Z\"",
        ] {
            assert!(
                !command_executes_git_in_dialect(command, ShellDialect::PowerShell),
                "expression statement must not execute git: {command}"
            );
            assert!(
                !dynamic_git_branch_may_mutate(command, ShellDialect::PowerShell),
                "expression statement must not reach branch mutation: {command}"
            );
            assert_ne!(
                branch_command_decision_in_dialect(command, ShellDialect::PowerShell),
                BranchCommandDecision::Destructive,
                "expression statement must not be a destructive branch command: {command}"
            );
        }
    }

    /// Real invocation shapes must keep their conservative treatment: an
    /// assignment executes its right-hand side, and `$(…)` / `@(…)`
    /// subexpressions evaluate their embedded pipeline even inside an
    /// expression statement.
    #[test]
    fn powershell_expression_shortcut_excludes_invoking_shapes() {
        assert_eq!(
            branch_command_decision_in_dialect("$x = git branch -D main", ShellDialect::PowerShell),
            BranchCommandDecision::Destructive,
            "assignment RHS is a real invocation and must stay destructive"
        );
        for command in [
            "$(git branch -D main)",
            "\"$(git branch -D main)\"",
            "@(git branch -D main)",
        ] {
            assert!(
                command_executes_git_in_dialect(command, ShellDialect::PowerShell),
                "subexpression statements keep the conservative treatment: {command}"
            );
        }
    }

    /// The reported #273 shapes must not be denied on the all-dialect route
    /// either: the quoted dynamic executable is an unknown program in every
    /// dialect. Since #281, the unquoted `$X $Y` form agrees with the quoted
    /// one — an executable with no literal bytes supplies no Git evidence, so
    /// quoted and unquoted spellings must not disagree.
    #[test]
    fn quoted_dynamic_executable_with_dynamic_argument_is_unknown_program() {
        for command in ["\"$X\" \"$Y\"", "\"$BIN\" run \"$ARG\"", "$X $Y"] {
            for dialect in [
                ShellDialect::Posix,
                ShellDialect::PowerShell,
                ShellDialect::Cmd,
                ShellDialect::Unknown,
            ] {
                let decision = branch_command_decision_in_dialect(command, dialect);
                assert!(
                    !matches!(
                        decision,
                        BranchCommandDecision::Destructive
                            | BranchCommandDecision::DestructiveDynamic
                    ),
                    "dynamic executable without git evidence must not be branch-destructive: {command} ({dialect:?}) -> {decision:?}"
                );
            }
        }
    }

    // =========================================================================
    // Unbounded dynamic executables carry no git evidence (#281)
    // =========================================================================

    /// A command whose executable resolves to an unbounded expansion — a
    /// backtick pair surfaced by Unknown-dialect quote stripping, or a bare
    /// `$cmd` — must not be attributed to `core.git:branch-dynamic-token`
    /// when nothing literal ties the command to Git (#281).
    #[test]
    fn unbounded_dynamic_executable_without_git_evidence_is_not_branch() {
        for command in [
            // Reported shape 1: backticks inside a single-quoted string in an
            // assignment value; Unknown-dialect normalization strips the
            // quotes and the substitution lands in the executable slot.
            "s=s.replace('a `x` b', 'c')",
            // The exact normalized slice the evaluator scans for it.
            "s=s.replace(a `x` b, c)",
            // Reported shape 2: dynamic executable plus dynamic argument.
            "$cmd $arg",
            // Reporter-verified boundary facts that already allow.
            "s=s.replace('a $(x) b', 'c')",
            "s=`echo hi`",
            "print('a `x` b', 'c')",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                let decision = branch_command_decision_in_dialect(command, dialect);
                assert!(
                    !matches!(
                        decision,
                        BranchCommandDecision::Destructive
                            | BranchCommandDecision::DestructiveDynamic
                    ),
                    "no git evidence, must not deny as git branch: {command} ({dialect:?}) -> {decision:?}"
                );
            }
        }
    }

    /// Planted negatives for #281: literal branch evidence keeps every one of
    /// these fail-closed under the dynamic-token attribution.
    #[test]
    fn literal_branch_evidence_stays_fail_closed_281() {
        for command in [
            "git branch $(cat f)",
            "git branch -D $BR",
            // An unbounded executable followed by literal branch syntax keeps
            // the conservative treatment: the literal words are the evidence.
            "$(producer) branch -d feature",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                assert_eq!(
                    branch_command_decision_in_dialect(command, dialect),
                    BranchCommandDecision::DestructiveDynamic,
                    "literal branch evidence must stay denied: {command} ({dialect:?})"
                );
            }
        }
    }

    /// #281 must not discard literal argv that follows the unknowns. A short
    /// delete/force flag proves the mutation exactly like the long spelling
    /// that already fails closed, so both must deny.
    #[test]
    fn literal_short_flags_after_unbounded_dynamics_stay_fail_closed_281() {
        for command in [
            "$g $sub -D main",
            "$g $sub -d feature",
            "$g ${sub} -D main",
            "$g $sub -M old new",
            "$g $sub -f main origin/main",
            "$g $sub --delete --force main",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                assert_eq!(
                    branch_command_decision_in_dialect(command, dialect),
                    BranchCommandDecision::DestructiveDynamic,
                    "literal mutation evidence must stay denied: {command} ({dialect:?})"
                );
            }
        }

        // Literal evidence that is not a branch mutation keeps the #281 allow.
        for command in [
            "$cmd $arg",
            "\"$cmd\" \"$arg\"",
            "$cmd literal",
            "$g $sub main",
            "$g $sub -v",
            "$g $sub --list",
            "ls $arg",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                let decision = branch_command_decision_in_dialect(command, dialect);
                assert!(
                    !matches!(
                        decision,
                        BranchCommandDecision::Destructive
                            | BranchCommandDecision::DestructiveDynamic
                    ),
                    "no branch mutation evidence, must not deny: {command} ({dialect:?}) -> {decision:?}"
                );
            }
        }
    }

    // =========================================================================
    // Executable evidence is judged on the basename (#360, #361)
    // =========================================================================

    /// A word whose basename is nothing but glob metacharacters names no
    /// program at all — the leading `/` is a directory separator, not literal
    /// Git evidence — so it must supply exactly as little evidence as the bare
    /// `*`/`$cmd` that #281 already discounts. The reported symptom: a C/JSDoc
    /// block comment (`/* ... */`) reaching a shell was denied as a
    /// destructive dynamic git-branch invocation (#360).
    #[test]
    fn wildcard_basename_executable_supplies_no_git_evidence_360() {
        for command in [
            // Minimal reproducer and the block-comment pair.
            "/* *",
            "/* */",
            "/** Default language for new articles */",
            // Other pure-metacharacter basenames.
            "/? *",
            "./* *",
            "lib/* *",
            "/[ab]* *",
            // A second wildcard cannot stand in for the `branch` subcommand.
            "/* b*",
            // An expansion basename behind a literal directory is just as
            // unbounded as the bare expansion.
            "dir/$X $sub",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                let decision = branch_command_decision_in_dialect(command, dialect);
                assert!(
                    !matches!(
                        decision,
                        BranchCommandDecision::Destructive
                            | BranchCommandDecision::DestructiveDynamic
                    ),
                    "wildcard basename is no git evidence: {command} ({dialect:?}) -> {decision:?}"
                );
            }
        }
    }

    /// The full reported command: a `python3` heredoc rewriting source files
    /// whose body contains a JSDoc comment. Neither `git` nor `branch` appears
    /// anywhere; the `/**` line manufactured the old match (#360).
    #[test]
    fn python_heredoc_with_jsdoc_body_is_not_a_branch_command_360() {
        let command = concat!(
            "cd /tmp/proj && python3 - <<'PY'\n",
            "pairs = [\n",
            "    ('src/settings.ts', '/** Default language for new articles */', '/** Default locale */'),\n",
            "]\n",
            "for path, old, new in pairs:\n",
            "    text = open(path).read()\n",
            "    open(path, 'w').write(text.replace(old, new))\n",
            "PY",
        );
        for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
            let decision = branch_command_decision_in_dialect(command, dialect);
            assert!(
                !matches!(
                    decision,
                    BranchCommandDecision::Destructive | BranchCommandDecision::DestructiveDynamic
                ),
                "python heredoc body is not a git branch command: ({dialect:?}) -> {decision:?}"
            );
        }
    }

    /// The mirror defect (#361): a glob in a *directory* component leaves a
    /// fully literal `git` basename, which names Git unambiguously. Treating
    /// the whole word's dynamism as the basename's let
    /// `/usr/*/git branch -D main` slip past the entire `core.git` pack while
    /// the literal-path spelling was denied.
    #[test]
    fn glob_directory_with_literal_git_basename_stays_denied_361() {
        for command in [
            "/usr/*/git branch -D main",
            "/usr/*/git branch $name",
            "/*/bin/git branch -D main",
            "/opt/?/git branch $name",
            "$PREFIX/*/git branch -D main",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                let decision = branch_command_decision_in_dialect(command, dialect);
                assert!(
                    matches!(
                        decision,
                        BranchCommandDecision::Destructive
                            | BranchCommandDecision::DestructiveDynamic
                    ),
                    "literal git basename must stay fail-closed: {command} ({dialect:?}) -> {decision:?}"
                );
            }
        }
    }

    /// The #360 allow must not open a bypass: literal branch-mutation flags
    /// anywhere in the argv after an unbounded executable are evidence in
    /// plain sight, wherever they sit — including the first argv slot, which
    /// no dynamic word precedes.
    #[test]
    fn literal_mutation_flags_after_wildcard_executable_stay_denied_360() {
        for command in [
            "/* -D main",
            "/* -d feature",
            "/* --delete feature",
            "/* --force --delete feature",
            "/* -M old new",
            "lib/* -D main",
            "/* $sub -D main",
            "$cmd $sub -D main",
        ] {
            for dialect in [ShellDialect::Unknown, ShellDialect::Posix] {
                assert_eq!(
                    branch_command_decision_in_dialect(command, dialect),
                    BranchCommandDecision::DestructiveDynamic,
                    "literal mutation flags stay denied: {command} ({dialect:?})"
                );
            }
        }
    }

    // =========================================================================
    // Execution-frontend strip failures stay scan-required (#260)
    // =========================================================================

    /// When a known execution frontend's wrapper strip bails (dynamic option
    /// value, unmodeled flag), the wrapped `git` word must stay scan-required
    /// under the Posix dialect so the regex rules run — the live hook path
    /// must not be weaker than `dcg test`.
    #[test]
    fn frontend_strip_failure_keeps_git_scan_required() {
        for command in [
            "nice -n $(x) git reset --hard",
            "timeout $(x) git reset --hard",
            "mise exec --cd $(pwd) git reset --hard",
            "mise exec --no-such-flag git reset --hard",
            "sudo nice -n $(x) git reset --hard",
            "nice -n $(x) git branch -D main",
        ] {
            assert!(
                command_executes_git_in_dialect(command, ShellDialect::Posix),
                "frontend bail must keep the wrapped git command scan-required: {command}"
            );
        }
        // Genuinely unknown programs keep the documented argv-data default,
        // and a frontend with no possible git word downstream stays skipped.
        for command in ["foo exec git reset --hard", "timeout 5 sleep 1"] {
            assert!(
                !command_executes_git_in_dialect(command, ShellDialect::Posix),
                "unknown program argv keeps the documented default: {command}"
            );
        }
    }

    // =========================================================================
    // Branch creation with dynamic tokens (#274)
    // =========================================================================

    /// An unquoted, unresolvable expansion in `git branch` argv stays
    /// fail-closed — its output can field-split into `-D main` — but the
    /// verdict is attributed to the dynamic-token rule so the denial explains
    /// the real hazard and its safe spellings, not a fictional deletion.
    #[test]
    fn branch_creation_with_unresolvable_expansion_uses_dynamic_rule() {
        for command in [
            "git branch backup-$(date +%s)",
            "git branch backup/pre-$(git rev-parse --short HEAD)",
            "git branch $FLAGS",
        ] {
            for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
                assert_eq!(
                    branch_command_decision_in_dialect(command, dialect),
                    BranchCommandDecision::DestructiveDynamic,
                    "unquoted dynamic branch argv fails closed under the dynamic rule: {command} ({dialect:?})"
                );
            }
        }
    }

    /// The safe spellings need no allowlist entry: quoting pins the expansion
    /// to a single non-flag word, `--` ends option parsing, and a
    /// statically-resolvable substitution folds to a literal name.
    #[test]
    fn branch_creation_safe_spellings_stay_allowed() {
        for command in [
            "git branch mybackup",
            "git branch foo-$(echo x)",
            "git branch \"backup-$(date +%s)\"",
            "git branch \"backup/pre-$(git rev-parse --short HEAD)\"",
            "git branch -- backup-$(date +%s)",
        ] {
            for dialect in [ShellDialect::Posix, ShellDialect::Unknown] {
                let decision = branch_command_decision_in_dialect(command, dialect);
                assert!(
                    !matches!(
                        decision,
                        BranchCommandDecision::Destructive
                            | BranchCommandDecision::DestructiveDynamic
                    ),
                    "safe branch creation spelling must not fail closed: {command} ({dialect:?}) -> {decision:?}"
                );
            }
        }
        // Literal deletion / force flags keep the original attribution.
        for command in [
            "git branch -D main",
            "git branch -d merged",
            "git branch -f main HEAD~1",
        ] {
            assert_eq!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::Destructive,
                "literal mutation flags stay on branch-force-delete: {command}"
            );
        }
    }

    // =========================================================================
    // Pack Creation Tests
    // =========================================================================

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();

        assert_eq!(pack.id, "core.git");
        assert_eq!(pack.name, "Core Git");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"git"));

        // Validate patterns
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    fn assert_shell_alias(
        command: &str,
        dialect: ShellDialect,
        expected_body: &str,
        expected_args: &[&str],
    ) {
        let InvokedGitAliasDecision::Shell(alias) =
            invoked_visible_git_alias_in_dialect(command, dialect)
        else {
            panic!("expected visible shell alias: {command}");
        };
        assert_eq!(alias.shell_body, expected_body, "command: {command}");
        assert_eq!(
            alias.invoked_args, expected_args,
            "appended arguments for: {command}"
        );
    }

    fn assert_expanded_alias(
        command: &str,
        dialect: ShellDialect,
        expected_subcommand: &str,
        expected_args: &[&str],
    ) {
        let InvokedGitAliasDecision::Expanded(alias) =
            invoked_visible_git_alias_in_dialect(command, dialect)
        else {
            panic!("expected expanded Git alias: {command}");
        };
        assert_eq!(alias.subcommand, expected_subcommand, "command: {command}");
        assert_eq!(alias.arguments, expected_args, "arguments for: {command}");
    }

    #[test]
    fn visible_git_shell_aliases_preserve_body_and_arguments() {
        for command in [
            "git -c 'alias.x=!rm -r ./tree' x",
            "git -calias.x='!rm -r ./tree' x",
            "ALIAS_BODY='!rm -r ./tree' git --config-env=alias.x=ALIAS_BODY x",
            "ALIAS_BODY='!rm -r ./tree' git --config-env alias.x=ALIAS_BODY x",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.x GIT_CONFIG_VALUE_0='!rm -r ./tree' git x",
        ] {
            assert_shell_alias(command, ShellDialect::Posix, "rm -r ./tree", &[]);
        }
        assert_shell_alias(
            "git -c 'alias.x=!rm -r' x ./tree",
            ShellDialect::Posix,
            "rm -r",
            &["./tree"],
        );
        assert_shell_alias(
            "git -c 'alias.x=!rm' x -r ./tree",
            ShellDialect::Posix,
            "rm",
            &["-r", "./tree"],
        );
        assert_shell_alias(
            "git -c alias.x=y -c 'alias.y=!rm -r ./tree' x",
            ShellDialect::Posix,
            "rm -r ./tree",
            &[],
        );
        assert_shell_alias(
            "git -c 'alias.x=!f(){ rm -r ./tree; }; f' x",
            ShellDialect::Posix,
            "f(){ rm -r ./tree; }; f",
            &[],
        );
        assert_shell_alias(
            "git -c \"alias.x=!sh -c 'rm -r ./tree | tee /tmp/log'\" x",
            ShellDialect::Posix,
            "sh -c 'rm -r ./tree | tee /tmp/log'",
            &[],
        );
    }

    #[test]
    fn visible_git_alias_resolution_is_bounded_and_last_definition_wins() {
        for command in [
            "git -c alias.x=x x",
            "git -c alias.x=y -c alias.y=x x",
            "git -c 'alias.x=!rm -r ./tree' $alias",
            "git -c \"alias.$name=!rm -r ./tree\" x",
            "git -c \"alias.x=!rm $target\" x",
            "git -c 'alias.x=!f() { git branch \"$@\"; }; f' x -d victim",
            "git -c 'alias.x=!f () { git branch \"${1}\" \"${2}\"; }; f' x -d victim",
        ] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
                InvokedGitAliasDecision::Unverified,
                "must fail closed: {command}"
            );
        }
        for command in [
            "git -c alias.x=status -c 'alias.x=!rm -r ./tree' status",
            "git -c 'alias.x=!rm -r ./tree' status",
            "MISSING= git --config-env=alias.x=ABSENT x",
        ] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
                InvokedGitAliasDecision::NoMatch,
                "configured-but-inert alias must not match: {command}"
            );
        }
        assert_expanded_alias(
            "git -c 'alias.x=!rm -r ./tree' -c alias.x=status x",
            ShellDialect::Posix,
            "status",
            &[],
        );
        assert_shell_alias(
            "git -c alias.x=status -c 'alias.x=!rm -r ./tree' x",
            ShellDialect::Posix,
            "rm -r ./tree",
            &[],
        );

        let mut command = String::from("git");
        for index in 0..65 {
            let _ = write!(command, " -c alias.dummy{index}=status");
        }
        command.push_str(" -c 'alias.x=!rm -r ./tree' x");
        assert_shell_alias(&command, ShellDialect::Posix, "rm -r ./tree", &[]);
    }

    #[test]
    fn shell_alias_function_scope_detection_is_quote_aware() {
        assert!(shell_alias_args_cross_function_scope(
            "f() { git branch \"$@\"; }; f"
        ));
        assert!(shell_alias_args_cross_function_scope(
            "f () { git branch \"${1}\"; }; f"
        ));
        assert!(!shell_alias_args_cross_function_scope(
            "f() { printf '%s' '$@'; }; f"
        ));
        assert!(!shell_alias_args_cross_function_scope("git branch \"$@\""));
    }

    #[test]
    fn non_shell_aliases_expose_exact_expanded_git_argv() {
        for (command, subcommand, arguments) in [
            (
                "git -c 'alias.x=branch -d' x victim",
                "branch",
                &["-d", "victim"][..],
            ),
            ("git -c 'alias.x=reset --hard' x", "reset", &["--hard"][..]),
            ("git -c 'alias.x=clean -fd' x", "clean", &["-fd"][..]),
            (
                "git -c alias.x=y -c 'alias.y=branch -d' x victim",
                "branch",
                &["-d", "victim"][..],
            ),
            (
                "git config alias.x 'branch -d'; git x victim",
                "branch",
                &["-d", "victim"][..],
            ),
            (
                "git config alias.x 'reset --hard'; git x",
                "reset",
                &["--hard"][..],
            ),
            (
                "git config alias.x 'clean -fd'; git x",
                "clean",
                &["-fd"][..],
            ),
        ] {
            assert_expanded_alias(command, ShellDialect::Posix, subcommand, arguments);
        }
        for command in ["git nuke", "git custom-helper", "git -C /tmp/repo nuke"] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
                InvokedGitAliasDecision::Unverified,
                "runtime aliases/helpers make unknown Git commands unverified: {command}"
            );
        }
        for command in ["git status", "git log", "git branch"] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
                InvokedGitAliasDecision::NoMatch,
                "known Git builtins remain directly inspectable: {command}"
            );
        }
    }

    #[test]
    fn active_expansion_is_role_aware_for_git_branch_mutation() {
        for (command, dialect) in [
            ("then git branch -d victim", ShellDialect::Posix),
            ("do ! git branch --delete victim", ShellDialect::Posix),
            ("else { sudo git branch -D victim", ShellDialect::Posix),
            ("g${part}t branch -d victim", ShellDialect::Posix),
            ("git br${part}anch -d victim", ShellDialect::Posix),
            ("git branch -${flag} victim", ShellDialect::Posix),
            ("$cmd branch -d victim", ShellDialect::Posix),
            ("$result = git branch -d victim", ShellDialect::PowerShell),
            ("git br${part}anch -d victim", ShellDialect::PowerShell),
            ("git branch -${flag} victim", ShellDialect::PowerShell),
            ("%G% branch -d victim", ShellDialect::Cmd),
            ("!G! branch --delete victim", ShellDialect::Cmd),
            ("git br%PART%anch -d victim", ShellDialect::Cmd),
            ("git branch -%FLAG% victim", ShellDialect::Cmd),
            ("call g^it branch -^d victim", ShellDialect::Cmd),
            ("@g^it branch -^d victim", ShellDialect::Cmd),
            ("& ('g'+'it') branch -d victim", ShellDialect::PowerShell),
            ("& $('git') branch -d victim", ShellDialect::PowerShell),
        ] {
            let decision = branch_command_decision_in_dialect(command, dialect);
            assert!(
                matches!(
                    decision,
                    BranchCommandDecision::Destructive | BranchCommandDecision::DestructiveDynamic
                ),
                "active syntax can select destructive Git branch semantics: {command} -> {decision:?}"
            );
        }

        for (command, dialect) in [
            ("command then git branch -d victim", ShellDialect::Posix),
            ("'then' git branch -d victim", ShellDialect::Posix),
            ("then else git branch -d victim", ShellDialect::Posix),
            ("echo g${part}t branch -d victim", ShellDialect::Posix),
            ("git status -${flag}", ShellDialect::Posix),
            ("git branch --format \"$value\"", ShellDialect::Posix),
            ("git branch -- \"$value\"", ShellDialect::Posix),
            ("git branch --format \"$value\"", ShellDialect::PowerShell),
            ("git branch -- \"$value\"", ShellDialect::PowerShell),
            // A variable at PowerShell statement position is an expression
            // statement; `$cmd branch -d victim` is a parse error in real
            // PowerShell and cannot invoke `$cmd` (#273). The POSIX dialect
            // keeps the equivalent unquoted form fail-closed above, so the
            // all-dialect route still denies it.
            ("$cmd branch -d victim", ShellDialect::PowerShell),
            ("git branch --format \"%VALUE%\"", ShellDialect::Cmd),
            ("git branch -- \"%VALUE%\"", ShellDialect::Cmd),
            ("call g^it branch --format -^d", ShellDialect::Cmd),
            ("@g^it branch --format -^d", ShellDialect::Cmd),
            ("call echo git branch -d victim", ShellDialect::Cmd),
            (
                "$outlook = New-Object -ComObject Outlook.Application\n\
                 $mail = $outlook.CreateItem(0)\n\
                 $mail.Subject = 'Daily dossier'\n\
                 $mail.HTMLBody = Get-Content .\\dossier.html -Raw\n\
                 $mail.Send()",
                ShellDialect::PowerShell,
            ),
        ] {
            assert_ne!(
                branch_command_decision_in_dialect(command, dialect),
                BranchCommandDecision::Destructive,
                "active data must not be reinterpreted as Git syntax: {command}"
            );
        }

        for command in [
            "git x -d victim",
            "git x --delete victim",
            "git x -M old new",
        ] {
            assert_eq!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::Destructive,
                "an unresolved command can be a persistent branch alias: {command}"
            );
        }
        for command in ["git status -d", "git x -- -d", "git x"] {
            assert_ne!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::Destructive,
                "known builtins and post-terminator data remain safe: {command}"
            );
        }

        let outlook_assignment = "$outlook = New-Object -ComObject Outlook.Application";
        assert!(
            !command_executes_git_in_dialect(outlook_assignment, ShellDialect::PowerShell),
            "a PowerShell assignment must analyze its executable RHS, not its dynamic lvalue"
        );

        for command in [
            "& ('g'+'it') -c 'alias.x=!rm -r ./tree' x",
            "& $('git') -c 'alias.x=!rm -r ./tree' x",
        ] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::PowerShell),
                InvokedGitAliasDecision::Unverified,
                "PowerShell call-operator expressions must fail closed: {command}"
            );
        }
    }

    #[test]
    fn posix_control_prefixes_expose_only_the_introduced_command() {
        for command in [
            "if git reset --hard",
            "then git reset --hard",
            "elif env FOO=1 git reset --hard",
            "else sudo git reset --hard",
            "while ! git reset --hard",
            "until { git reset --hard",
            "do git reset --hard",
            "{ git reset --hard",
            "! git reset --hard",
            "then { sudo git reset --hard",
            "\\\n then git reset --hard",
            "coproc git reset --hard",
            "then coproc git reset --hard",
            "coproc JOB { git reset --hard",
            "coproc JOB ( git reset --hard )",
            "coproc JOB if git reset --hard",
            "function f { git reset --hard",
            "function f() { git reset --hard",
            "function f if git reset --hard",
            "then function f { git reset --hard",
        ] {
            assert!(
                command_executes_git_in_dialect(command, ShellDialect::Posix),
                "reserved control prefix must expose Git: {command}"
            );
        }

        for command in [
            "command then git reset --hard",
            "env then git reset --hard",
            "sudo then git reset --hard",
            "/usr/bin/then git reset --hard",
            "'then' git reset --hard",
            "ifconfig git reset --hard",
            "then else git reset --hard",
            "do then git reset --hard",
            "coproc echo git reset --hard",
            "coproc JOB { echo git reset --hard",
            "function f { echo git reset --hard",
            "command coproc git reset --hard",
            "env coproc git reset --hard",
            "sudo coproc git reset --hard",
            "/usr/bin/coproc git reset --hard",
            "'coproc' git reset --hard",
        ] {
            assert!(
                !command_executes_git_in_dialect(command, ShellDialect::Posix),
                "argv data or invalid reserved-word order must not expose Git: {command}"
            );
        }

        let mut deeply_nested = String::new();
        for index in 0..80 {
            let _ = write!(deeply_nested, "function f{index} {{ ");
        }
        deeply_nested.push_str("git reset --hard");
        for index in (0..80).rev() {
            let _ = write!(deeply_nested, "; }}; f{index}");
        }
        let (deeply_nested_body, _) =
            command_after_posix_control_prefixes(&deeply_nested, ShellDialect::Posix);
        assert!(
            command_executes_git_in_dialect(&deeply_nested, ShellDialect::Posix),
            "valid structural nesting beyond the parser budget must fail closed; parser body: \
             {deeply_nested_body:?}"
        );
    }

    #[test]
    fn visible_git_alias_state_flows_across_shell_segments() {
        assert_shell_alias(
            "git config alias.x '!rm -r ./tree'; git x",
            ShellDialect::Posix,
            "rm -r ./tree",
            &[],
        );
        for command in [
            "git config alias.x 'reset --hard'; if true; then git x; fi",
            "git config alias.x '!rm -r ./tree'; while true; do git x; done",
        ] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
                InvokedGitAliasDecision::Unverified,
                "control-flow alias invocation must fail closed: {command}"
            );
        }
        assert_shell_alias(
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; git x",
            ShellDialect::Posix,
            "rm -r ./tree",
            &[],
        );
        assert_shell_alias(
            "set GIT_CONFIG_COUNT=1 & set GIT_CONFIG_KEY_0=alias.x & set \"GIT_CONFIG_VALUE_0=!rm -r ./tree\" & git x",
            ShellDialect::Cmd,
            "rm -r ./tree",
            &[],
        );
        assert_shell_alias(
            "$env:GIT_CONFIG_COUNT='1'; $env:GIT_CONFIG_KEY_0='alias.x'; $env:GIT_CONFIG_VALUE_0='!rm -r ./tree'; git x",
            ShellDialect::PowerShell,
            "rm -r ./tree",
            &[],
        );
        assert_shell_alias(
            "$Env:GIT_CONFIG_COUNT = '1'; $ENV:GIT_CONFIG_KEY_0 = 'alias.x'; $env:GIT_CONFIG_VALUE_0 = '!rm -r ./tree'; git x",
            ShellDialect::PowerShell,
            "rm -r ./tree",
            &[],
        );
        assert_shell_alias(
            "export GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; GIT_CONFIG_COUNT=1; GIT_CONFIG_KEY_0=alias.x; GIT_CONFIG_VALUE_0='!rm -r ./tree'; git x",
            ShellDialect::Posix,
            "rm -r ./tree",
            &[],
        );
        assert_expanded_alias(
            "git config alias.x status; git x",
            ShellDialect::Posix,
            "status",
            &[],
        );
        let removed = "git config alias.x '!rm -r ./tree' && git config --unset alias.x && git x";
        assert_eq!(
            invoked_visible_git_alias_in_dialect(removed, ShellDialect::Posix),
            InvokedGitAliasDecision::Unverified,
            "unknown helper namespace remains unverified after alias removal: {removed}"
        );
        for command in [
            "git config alias.x '!rm -r ./tree'; false && git config alias.x status; git x",
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; false && GIT_CONFIG_VALUE_0=status; git x",
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; (GIT_CONFIG_VALUE_0=status); git x",
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; GIT_CONFIG_VALUE_0=status | cat; git x",
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; f() { GIT_CONFIG_VALUE_0=status; }; git x",
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; while false; do GIT_CONFIG_VALUE_0=status; done; git x",
            "export GIT_CONFIG_COUNT=1; export GIT_CONFIG_KEY_0=alias.x; export GIT_CONFIG_VALUE_0='!rm -r ./tree'; case no in yes) GIT_CONFIG_VALUE_0=status ;; esac; git x",
        ] {
            assert_eq!(
                invoked_visible_git_alias_in_dialect(command, ShellDialect::Posix),
                InvokedGitAliasDecision::Unverified,
                "conditional alias-state mutation must not be flattened: {command}"
            );
        }
        let skipped_multiline_override = "export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=alias.x
export GIT_CONFIG_VALUE_0='!printf EXECUTED'
if false
then
GIT_CONFIG_VALUE_0=status
fi
git x";
        assert_eq!(
            invoked_visible_git_alias_in_dialect(skipped_multiline_override, ShellDialect::Posix),
            InvokedGitAliasDecision::Unverified,
            "a skipped multiline override must not hide the dangerous alias"
        );
        assert_expanded_alias(
            "export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=alias.x
export GIT_CONFIG_VALUE_0='!printf EXECUTED'
GIT_CONFIG_VALUE_0=status
git x",
            ShellDialect::Posix,
            "status",
            &[],
        );
        assert_expanded_alias(
            "git config alias.x '!rm -r ./tree'; git config alias.x status; git x",
            ShellDialect::Posix,
            "status",
            &[],
        );
    }

    #[test]
    fn dynamic_shell_executables_receive_a_conservative_git_view() {
        for (command, dialect) in [
            (
                "& @('noop', ('g'+'it'))[1] reset --hard",
                ShellDialect::PowerShell,
            ),
            ("& $G reset --hard", ShellDialect::PowerShell),
            ("%G% reset --hard", ShellDialect::Cmd),
            ("g${PART}t reset --hard", ShellDialect::Posix),
        ] {
            assert!(
                git_semantic_scan_required(command, dialect),
                "dynamic executable must force core.git candidate selection: {command}"
            );
            assert!(
                command_executes_git_in_dialect(command, dialect),
                "dynamic executable must conservatively remain Git-capable: {command}"
            );
            let view = syntax_view_in_dialect(command, dialect)
                .unwrap_or_else(|| panic!("dynamic executable needs a syntax view: {command}"));
            assert_eq!(view, "git reset --hard", "unexpected view for {command}");
            assert_eq!(
                create_pack()
                    .matches_destructive(&view)
                    .and_then(|matched| matched.name),
                Some("reset-hard"),
                "semantic view must reach the destructive reset rule: {command}"
            );
        }

        for (command, dialect) in [
            ("echo '$G reset --hard'", ShellDialect::Posix),
            ("echo '$G reset --hard'", ShellDialect::PowerShell),
        ] {
            assert!(
                !git_semantic_scan_required(command, dialect),
                "single-quoted data must not force a semantic scan: {command}"
            );
        }
    }

    // =========================================================================
    // Critical Severity Pattern Tests
    // =========================================================================

    #[test]
    fn test_reset_hard_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git reset --hard", Severity::Critical);
        assert_blocks_with_pattern(&pack, "git reset --hard", "reset-hard");
        assert_blocks(&pack, "git reset --hard HEAD", "destroys uncommitted");
        assert_blocks(&pack, "git reset --hard HEAD~1", "destroys uncommitted");
        assert_blocks(
            &pack,
            "git reset --hard origin/main",
            "destroys uncommitted",
        );
    }

    #[test]
    fn test_clean_force_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git clean -f", Severity::Critical);
        assert_blocks_with_pattern(&pack, "git clean -f", "clean-force");
        assert_blocks(&pack, "git clean -fd", "removes untracked files");
        assert_blocks(&pack, "git clean -xf", "removes untracked files");
    }

    #[test]
    fn test_push_force_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git push --force", Severity::Critical);
        assert_blocks_with_severity(&pack, "git push -f", Severity::Critical);
        assert_blocks(
            &pack,
            "git push origin main --force",
            "destroy remote history",
        );
        assert_blocks(
            &pack,
            "git push --force origin main",
            "destroy remote history",
        );

        // Combined short-flag forms that resolve to `-f` at parse time.
        assert_blocks_with_severity(&pack, "git push -uf origin main", Severity::Critical);
        assert_blocks_with_severity(&pack, "git push -fv origin main", Severity::Critical);
        assert_blocks_with_severity(&pack, "git push -fuv origin main", Severity::Critical);
        assert_blocks_with_severity(&pack, "git push -vf origin main", Severity::Critical);

        // Branch names that happen to contain `-f` must NOT be treated as a
        // force flag.
        assert!(
            pack.check("git push origin feature-f").is_none(),
            "branch named `feature-f` must not be treated as a force flag"
        );
        assert!(
            pack.check("git push origin hotfix-fallback").is_none(),
            "branch named `hotfix-fallback` must not be treated as a force flag"
        );
        // Branch name literally containing `--force` must not be treated as
        // the long force flag.
        assert!(
            pack.check("git push origin feature--force").is_none(),
            "branch name `feature--force` must not trigger push-force-long"
        );

        // --force-with-lease (safer) must NOT trigger push-force-short.
        // (push-force-long's negative lookahead already excludes it.)
        assert!(
            pack.check("git push --force-with-lease origin main")
                .is_none(),
            "--force-with-lease is the safer alternative and must not be blocked"
        );
        // --force-if-includes (safer) must also stay allowed.
        assert!(
            pack.check("git push --force-with-lease --force-if-includes origin main")
                .is_none(),
            "--force-with-lease --force-if-includes must not be blocked"
        );

        // Regression for #124: the bounded token-walker must not span shell
        // command boundaries (`&&`, `||`, `;`, `|`, `$( )`, backticks) the way
        // the old unbounded `(?:\S+\s+)*` walker did. A read-only `git push`
        // (or unrelated `git push --force-with-lease`) in one statement must
        // not let a later statement's `--force` flag back-match the earlier
        // `git push`, and a `git ... push ...` walker must not reach across a
        // separator into a `--force` token that belongs to a different command.
        for cmd in [
            // `git push` (no force) in one statement; `--force` text lives in a
            // separate statement that is NOT a push — must not match push-force.
            "git push origin main && echo done --force",
            "git push origin main; echo --force",
            "git push origin main || echo --force",
            "git push origin main | tee log --force",
            "branch=$(git rev-parse HEAD) && git push --force-with-lease origin main",
            "echo `git push origin main` && true --force",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "push-force must not span shell boundaries; cmd={cmd}"
            );
        }

        // ...but a genuine force-push that spans a separator (its own complete
        // `git push --force` statement) must STILL be blocked.
        for cmd in [
            "git fetch && git push --force origin main",
            "git fetch; git push -f origin main",
            "git fetch || git push --force",
        ] {
            assert!(
                pack.check(cmd).is_some(),
                "a real force-push statement after a separator must still be blocked; cmd={cmd}"
            );
        }
    }

    #[test]
    fn test_stash_clear_critical() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git stash clear", Severity::Critical);
        assert_blocks_with_pattern(&pack, "git stash clear", "stash-clear");
    }

    // =========================================================================
    // High Severity Pattern Tests
    // =========================================================================

    #[test]
    fn test_checkout_discard_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git checkout -- file.txt", Severity::High);
        assert_blocks_with_pattern(&pack, "git checkout -- file.txt", "checkout-discard");
        assert_blocks(&pack, "git checkout -- .", "discards uncommitted changes");
    }

    /// #373: the checkout-ref-discard remediation recommends
    /// `git show <ref>:<path>`, which is safe bare but reaches the identical
    /// overwrite when redirected back onto the same path. The sibling rule
    /// denies exactly the same-path redirected shape; every capture to a new
    /// file and the bare view stay allowed.
    #[test]
    fn show_redirect_onto_same_path_is_denied_373() {
        let pack = create_pack();

        for cmd in [
            // The reported shape.
            "git show origin/main:Directory.Packages.props > Directory.Packages.props",
            "git show HEAD~1:src/config.rs > src/config.rs",
            "git show origin/main:README.md >> README.md",
            "git show origin/main:README.md >| README.md",
            "git show HEAD:a.txt > ./a.txt",
            "git show HEAD:a.txt > a.txt && cargo build",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "show-redirect-overwrite-source");
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }

        // Bare view and captures to a new file are the recommended safe forms.
        for cmd in [
            "git show origin/main:Directory.Packages.props",
            "git show HEAD~1:src/config.rs",
            "git show origin/main:README.md > README.md.from-ref",
            "git show origin/main:README.md > /tmp/README.md",
            "git show HEAD:a.txt > b.txt",
            "git show HEAD:a.txt | less",
            "git show HEAD:a.txt | grep TODO",
        ] {
            assert!(
                pack.check(cmd)
                    .is_none_or(|hit| hit.name != Some("show-redirect-overwrite-source")),
                "safe form must not match show-redirect-overwrite-source: {cmd:?}"
            );
        }
    }

    #[test]
    fn test_restore_worktree_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git restore file.txt", Severity::High);
        assert_blocks(
            &pack,
            "git restore --worktree file.txt",
            "discards uncommitted",
        );
        // Bare `git restore .` (no --staged) discards working-tree changes.
        assert_blocks(&pack, "git restore .", "discards uncommitted");
        // `--staged` combined with `--worktree`/`-W` still touches the working
        // tree and must be blocked even though a staged flag is present (#156).
        assert_blocks(
            &pack,
            "git restore --staged --worktree file.txt",
            "discards uncommitted",
        );
        assert_blocks(&pack, "git restore -S -W file.txt", "discards uncommitted");
        assert_blocks(&pack, "git restore . --worktree", "discards uncommitted");
    }

    #[test]
    fn posix_test_brackets_are_not_branch_mutations() {
        // Regression for #246: a lone `[` (or `[[`) is the literal POSIX test
        // builtin — an unclosed bracket cannot glob-expand into `git` or
        // `git-branch`, so `-d`/`-f`/`-M`/`-C` test operators must not be read
        // as branch mutation flags.
        let pack = create_pack();
        for cmd in [
            "[ -f x ]",
            "[ -d x ]",
            "[ -d /some/dir/.git ]",
            "[ -d \"$p/.git\" ]",
            "[[ -f x ]]",
            "[[ -d \"$repo/.git\" ]]",
            "[ -f .git/config ]",
            "test -d \"$p/.git\"",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "POSIX test must not be blocked: {cmd}"
            );
            assert!(
                matches!(
                    branch_command_decision(cmd),
                    BranchCommandDecision::NotBranch
                ),
                "POSIX test must not parse as a branch command: {cmd}"
            );
        }

        // A bracket expression that closes in the same word can still
        // glob-expand into `git`, so the semantic layer must keep treating it
        // as a possible branch mutation. (`gi[t]` contains no literal `git`
        // substring, so the pack-level keyword quick-reject never reaches the
        // regex — the semantic decision is the meaningful guard here.)
        assert!(
            matches!(
                branch_command_decision("gi[t] branch -D feature"),
                BranchCommandDecision::Destructive | BranchCommandDecision::DestructiveDynamic
            ),
            "closed bracket expression in executable position must stay fail-closed"
        );
    }

    #[test]
    fn branch_regex_walkers_do_not_bridge_newlines() {
        // Regression for the newline-bridge variant of #246: a benign
        // read-only `git branch` line must not lend its `git … branch` prefix
        // to a `-d`-looking token on a later line of the same submission.
        let pack = create_pack();
        for cmd in [
            "git branch --list\n[ -d \"$p/.git\" ] && echo x",
            "git branch --show-current\ntest -d \"$p/.git\"",
            "git branch\ncat -d file",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "newline-separated benign lines must not combine into a branch deletion: {cmd}"
            );
        }
    }

    #[test]
    fn test_branch_delete_and_force_update_high() {
        // Every branch deletion form and forced ref update is a default-deny
        // user-intent boundary, even when Git considers the branch merged.
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git branch -d feature", Severity::High);
        assert_blocks_with_severity(&pack, "git branch -D feature", Severity::High);
        assert_blocks_with_pattern(&pack, "git branch -d feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -D feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch --delete feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch --force feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -f feature", "branch-force-delete");
        for cmd in [
            "git branch -M old existing",
            "git branch -C old existing",
            "git branch --d feature",
            "git branch --del feature",
            "git branch --dele feature",
            "git branch --delet feature",
            "git branch --forc feature",
            "git branch --no-format -d feature",
            "git branch --no-sort -d feature",
            "git branch --no-points-at -d feature",
            "git branch --no-set-upstream-to -d feature",
            "git branch --set-upstream -d feature",
            "git branch --merged HEAD -d feature",
            "git branch --contains HEAD --delete feature",
            "git branch --no-delete -d feature",
            "git branch --no-force -f feature",
            "git branch -D --no-delete --no-force feature",
            "git --no-literal-pathspecs branch --del feature",
            "git --shallow-file shallow branch -d feature",
            "git --attr-source HEAD branch --del feature",
            "FOO=bar git branch --del feature",
            "exec git branch --del feature",
            "gIt.ExE branch -d feature",
            "git-branch -d feature",
            "/usr/lib/git-core/git-branch --delete feature",
            "git -c alias.x=branch x -d feature",
            "git -calias.x=branch x --delete feature",
            "git -c alias.x=y -c alias.y=branch x -D feature",
            "git -c 'alias.x=!git branch' x -d feature",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.x GIT_CONFIG_VALUE_0=branch git x -d feature",
            "ALIAS_COMMAND=branch git --config-env=alias.x=ALIAS_COMMAND x -d feature",
            r"& 'C:\Program Files\Git\cmd\git.exe' branch -d feature",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "branch-force-delete");
        }

        // Combined short-flag forms (previously missed) — all map to
        // force-delete semantics:
        //   -Dr   (force-delete a remote-tracking branch)
        //   -vD   (verbose + force-delete)
        //   -fv   (force + verbose)
        //   -vdf  (verbose + delete + force)
        assert_blocks_with_pattern(
            &pack,
            "git branch -Dr origin/feature",
            "branch-force-delete",
        );
        assert_blocks_with_pattern(&pack, "git branch -vD feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -vd feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -fv feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -vdf feature", "branch-force-delete");
        assert_blocks_with_pattern(
            &pack,
            "sudo git -C /tmp/repo branch -d feature",
            "branch-force-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "git --no-pager branch --delete feature",
            "branch-force-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "git branch --format -d --delete feature",
            "branch-force-delete",
        );
        // Read-only and branch-creation forms remain safe.
        assert!(
            pack.check("git branch -a").is_none(),
            "listing all branches must not be blocked"
        );
        assert!(
            pack.check("git branch --merged").is_none(),
            "merged-branch listing must not be blocked"
        );
        assert!(
            pack.check("git branch feature").is_none(),
            "ordinary branch creation must not be blocked"
        );

        // Regression for #121: `--force-with-lease` and `--force-if-includes`
        // are the safer alternatives dcg itself recommends. They must NOT
        // false-match the `--force` alternative of branch-force-delete.
        for cmd in [
            "git push --force-with-lease origin main",
            "git push --force-if-includes origin HEAD:main",
            "git push --force-with-lease=main:abc123 origin",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "`--force-with-lease` / `--force-if-includes` must not trip branch-force-delete; cmd={cmd}"
            );
        }

        // Regression for #121: branch-force-delete must not span shell
        // command boundaries (`&&`, `||`, `;`, `|`, `$( )`, backticks).
        // The motivating case was
        //   branch=$(git branch --show-current) && git push --force-with-lease ...
        // — `git branch` is a read-only query and `git push --force-with-lease`
        // is a safe push, but the old regex consumed across the `)` and `&&`
        // to match `--force` inside `--force-with-lease`.
        for cmd in [
            "branch=$(git branch --show-current) && git push --force-with-lease origin HEAD:main",
            "git branch --show-current && git push --force-with-lease origin main",
            "git branch --show-current; git push --force-with-lease origin main",
            "git branch --show-current || git push --force-with-lease origin main",
            "git branch --show-current | tee /tmp/branch && git push --force-with-lease",
            "`git branch --show-current` && git push --force-with-lease",
            "git branch --show-current && ls -d",
            "git branch --show-current; printf '%s' --delete",
            "git branch --show-current || echo --force",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "branch-force-delete must not span shell boundaries; cmd={cmd}"
            );
        }

        // Option-like text inside a quoted format string is data, not a
        // branch deletion option.
        for cmd in [
            "git branch --format='%(refname:short) -d'",
            "git branch --format='--delete %(refname:short)'",
            "git branch --format -d",
            "git branch --sort -d",
            "git branch --points-at -d",
            "git branch --set-upstream-to -d",
            "git branch --form -d",
            "git branch --so -d",
            "git branch --poi -d",
            "git branch --merged -d feature",
            "git branch --contains -d feature",
            "git branch --with -d feature",
            "git branch --without --delete feature",
            "git branch -u -d feature",
            "git branch -tdirect",
            "git branch -tinherit",
            "git branch -- -d",
            "git branch --end-of-options -d",
            "git branch --delete --no-delete feature",
            "git branch -d --no-delete feature",
            "git branch --force --no-force feature",
            "git branch --delete=feature",
            "git branch --force=feature",
            "git branch --help -d feature",
            "git branch -dh feature",
            "git branch -hd feature",
            "git help branch -d feature",
            "git --version branch -d feature",
            "git --exec-path branch -d feature",
            "FOO=bar git branch --format -d",
            "time git branch --format -d",
            "git-branch --format -d",
            "/usr/lib/git-core/git-branch --merged -d feature",
            "git -c 'alias.x=branch --format' x -d",
            "git -c alias.x=status x -d feature",
            "git -c alias.x=y -c alias.y=status x -d feature",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.x GIT_CONFIG_VALUE_0='branch --format' git x -d",
            "ALIAS_COMMAND='branch --format' git --config-env alias.x=ALIAS_COMMAND x -d",
            r"& 'C:\Program Files\Git\cmd\git.exe' branch --format -d",
            r#"git branch --format -d "$(printf feature)""#,
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "quoted format data must not trigger branch deletion; cmd={cmd}"
            );
        }
        assert_blocks_with_pattern(
            &pack,
            "git branch -tdirect -d feature",
            "branch-force-delete",
        );
    }

    #[test]
    fn posix_literal_printf_substitutions_cannot_hide_branch_deletion() {
        let destructive = [
            "g$(printf it) br$(printf anch) -$(printf d) feature",
            "g`printf it` br`printf anch` -`printf d` feature",
            "g$(printf it) branch -d feature",
            "git br$(printf anch) -d feature",
            "git branch -$(printf d) feature",
            "$(printf git) branch -d feature",
            "git $(printf branch) -d feature",
            "git branch --$(printf delete) feature",
            "g$(printf '')it branch -d feature",
        ];
        for command in destructive {
            assert_eq!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::Destructive,
                "literal command substitution must not hide deletion: {command}"
            );
            assert_eq!(
                branch_command_decision(command),
                BranchCommandDecision::Destructive,
                "unknown callers must conservatively recognize POSIX substitution: {command}"
            );
        }

        for command in [
            "git branch --format $(printf %s -d)",
            "git branch --format \"$(printf %s -d)\"",
        ] {
            assert_eq!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::NonDestructive,
                "option data must stay non-destructive: {command}"
            );
        }

        let reset_view = syntax_view_in_dialect(
            "g$(printf it) re$(printf set) --ha$(printf rd)",
            ShellDialect::Posix,
        )
        .expect("static printf substitution should produce a syntax view");
        assert_eq!(reset_view, "git reset --hard");

        let inert_view =
            syntax_view_in_dialect("echo \"$(printf 'git reset --hard')\"", ShellDialect::Posix)
                .expect("literal substitution data should produce a non-matching view");
        assert_eq!(inert_view, "__dcg_non_git_command__");
    }

    #[test]
    fn unresolved_posix_substitutions_are_role_aware() {
        for command in [
            "g$(producer) branch -d feature",
            "git br$(producer) -d feature",
            "git branch -$(producer) feature",
            "$(producer) branch -d feature",
            "git $(producer) -d feature",
            "git branch $(producer)",
            "git branch --format $(producer)",
            "/usr/bin/git branch $(producer)",
            "sudo git branch $(producer)",
        ] {
            assert_eq!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::DestructiveDynamic,
                "dynamic shell output can occupy a destructive syntax role: {command}"
            );
        }

        for command in [
            "echo $(producer)",
            "git branch --format \"$(producer)\"",
            "git branch '$(producer)'",
            r"git branch \$(producer)",
            "git branch -- \"$(producer)\"",
            "git branch -udanger --format \"$(producer)\"",
        ] {
            assert_ne!(
                branch_command_decision_in_dialect(command, ShellDialect::Posix),
                BranchCommandDecision::Destructive,
                "inert or quoted option data must remain safe: {command}"
            );
        }
    }

    #[test]
    fn test_stash_drop_medium() {
        // Stash drop is Medium severity (recoverable via fsck)
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git stash drop", Severity::Medium);
        assert_blocks(&pack, "git stash drop stash@{0}", "Recoverable");
    }

    // =========================================================================
    // Safe Pattern Tests
    // =========================================================================

    #[test]
    fn test_safe_checkout_new_branch() {
        let pack = create_pack();

        assert_safe_pattern_matches(&pack, "git checkout -b feature");
        assert_safe_pattern_matches(&pack, "git checkout -b feature/new-thing");
        assert_allows(&pack, "git checkout -b fix-123");
    }

    #[test]
    fn test_safe_checkout_orphan() {
        let pack = create_pack();

        assert_safe_pattern_matches(&pack, "git checkout --orphan gh-pages");
        assert_allows(&pack, "git checkout --orphan new-root");
    }

    #[test]
    fn test_safe_restore_staged() {
        let pack = create_pack();

        assert_allows(&pack, "git restore --staged file.txt");
        assert_allows(&pack, "git restore -S file.txt");
        // `--staged`/`-S` may appear AFTER the pathspec; it is the same
        // (safe) unstage operation and must also be allowed (issue #156).
        assert_allows(&pack, "git restore . --staged");
        assert_allows(&pack, "git restore . -S");
        assert_allows(&pack, "git restore --staged");
        assert_allows(&pack, "git -C /tmp/repo restore . --staged");
    }

    #[test]
    fn test_safe_clean_dry_run() {
        let pack = create_pack();

        assert_allows(&pack, "git clean -n");
        assert_allows(&pack, "git clean -dn");
        assert_allows(&pack, "git clean --dry-run");
    }

    // =========================================================================
    // Specificity Tests (False Positive Prevention)
    // =========================================================================

    #[test]
    fn test_specificity_safe_git_commands() {
        let pack = create_pack();

        test_batch_allows(
            &pack,
            &[
                "git status",
                "git log",
                "git log --oneline",
                "git diff",
                "git diff --cached",
                "git show HEAD",
                "git branch",
                "git branch -a",
                "git remote -v",
                "git fetch",
                "git pull",
                "git push", // Without --force
                "git add .",
                "git commit -m 'message'",
                "git branch --merged",
            ],
        );
    }

    #[test]
    fn test_specificity_unrelated_commands() {
        let pack = create_pack();

        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "cargo build");
        assert_no_match(&pack, "npm install");
        assert_no_match(&pack, "docker run");
    }

    #[test]
    fn test_specificity_substring_not_matched() {
        let pack = create_pack();

        // "git" as substring should not trigger
        assert_no_match(&pack, "cat .gitignore");
        assert_no_match(&pack, "echo digit");
    }

    // =========================================================================
    // Performance Tests
    // =========================================================================

    #[test]
    fn test_performance_normal_commands() {
        let pack = create_pack();

        assert_matches_within_budget(&pack, "git reset --hard");
        assert_matches_within_budget(&pack, "git push --force origin main");
        assert_matches_within_budget(&pack, "git checkout -b feature/new");
    }

    #[test]
    fn test_performance_pathological_inputs() {
        let pack = create_pack();

        let long_flags = format!("git {}", "-".repeat(500));
        assert_matches_within_budget(&pack, &long_flags);

        let many_spaces = format!("git{}status", " ".repeat(100));
        assert_matches_within_budget(&pack, &many_spaces);
    }

    // =========================================================================
    // Issue #250: cross-dialect tokenizer artifacts are not alias candidates
    // =========================================================================

    #[test]
    fn dispatchable_git_subcommand_tokens_are_name_shaped() {
        // Builtins, unknown alias names, and external `git-<name>` helper
        // names all stay candidates for Git's subcommand dispatch.
        for token in ["pull", "lg", "foo-bar", "st.sub", "a_b", "x+y", "v2"] {
            assert!(
                git_subcommand_token_is_dispatchable(token),
                "expected {token:?} to be dispatchable"
            );
        }
    }

    #[test]
    fn tokenizer_artifacts_are_not_dispatchable_git_subcommands() {
        // Shell punctuation can never appear in a config key or helper
        // filename that Git would dispatch; such tokens are cross-dialect
        // tokenizer artifacts (e.g. the Cmd view of POSIX `git pull; done`).
        for token in [
            "pull;", "pull'", "fetch\"", "", "sub|x", "x&y", "sub>out", "pu ll", "x`y", "$(x)",
        ] {
            assert!(
                !git_subcommand_token_is_dispatchable(token),
                "expected {token:?} to be rejected as a tokenizer artifact"
            );
        }
    }
}

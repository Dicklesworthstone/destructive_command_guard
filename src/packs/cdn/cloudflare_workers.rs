//! Cloudflare Workers pack - protections for destructive Wrangler CLI operations.
//!
//! Covers destructive operations:
//! - Worker deletion (`wrangler delete`)
//! - Deployment rollback (`wrangler deployments rollback`)
//! - KV operations (namespace/key/bulk delete)
//! - R2 operations (bucket/object delete)
//! - D1 database deletion

use crate::normalize::{
    NormalizeTokenKind, ShellDialect, ShellTokenDecoder, ShellTokenRole, strip_wrapper_prefixes,
    tokenize_for_shell_dialect,
};
use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const MAX_WRANGLER_SEMANTIC_BYTES: usize = 64 * 1024;
const MAX_WRANGLER_SEMANTIC_TOKENS: usize = 128;
const MAX_WRANGLER_SEMANTIC_SEGMENTS: usize = 64;

pub(crate) const WRANGLER_UNVERIFIED_RULE: &str = "wrangler-semantic-unverified";
pub(crate) const WRANGLER_UNVERIFIED_REASON: &str =
    "Wrangler syntax depends on shell expansion or exceeds dcg's bounded semantic analysis.";

/// Semantic result for a Wrangler command.
///
/// The generic pack/evaluator paths map `Destructive(rule)` back to the
/// existing named regex rule so its reason, severity, and allowlist identity
/// remain authoritative. `Safe` covers only explicitly known read-only or
/// informational commands; unrecognized syntax falls back to the existing
/// regex layer through `NoMatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WranglerSemanticDecision {
    NoMatch,
    Safe,
    Destructive(&'static str),
    /// Wrangler is established, but bounded semantic inspection cannot prove
    /// which operation will execute. Callers must handle this fail-closed.
    Unverified,
}

/// A shell program supplied to npm's `exec`/`npx` `-c|--call` option.
///
/// npm executes this value through a shell rather than treating it as package
/// argv.  The pack cannot safely reinterpret that shell grammar itself, so the
/// evaluator must recurse into a proven `Payload` as POSIX shell syntax.  A
/// dynamic or structurally incomplete option is deliberately fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WranglerRunnerShellDecision {
    NoMatch,
    Payload(String),
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WranglerCursorStop {
    Dynamic,
    Terminated,
    Invalid,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct WranglerTerminalFlags {
    help: Option<bool>,
    version: Option<bool>,
    dry_run: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WranglerOptionArity {
    Flag,
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WranglerOptionScope {
    Global,
    Kv,
    R2,
}

#[derive(Debug, Clone)]
struct WranglerWord {
    decoded: String,
    dynamic: bool,
}

impl WranglerWord {
    fn may_equal(&self, candidate: &str, dialect: ShellDialect) -> bool {
        symbolic_word_may_equal(&self.decoded, self.dynamic, dialect, candidate, false)
    }
}

struct WranglerWordCursor<'a> {
    words: &'a [WranglerWord],
    index: usize,
    terminal_flags: WranglerTerminalFlags,
}

impl<'a> WranglerWordCursor<'a> {
    fn new(words: &'a [WranglerWord], index: usize) -> Self {
        Self {
            words,
            index,
            terminal_flags: WranglerTerminalFlags::default(),
        }
    }

    fn next(
        &mut self,
        scope: WranglerOptionScope,
    ) -> Result<Option<&'a WranglerWord>, WranglerCursorStop> {
        while let Some(word) = self.words.get(self.index) {
            self.index += 1;
            let text = word.decoded.as_str();
            if text == "--" {
                return Err(WranglerCursorStop::Terminated);
            }
            if update_terminal_flags(text, &mut self.terminal_flags) {
                continue;
            }
            if let Some(arity) = wrangler_option_arity(text, scope) {
                if arity == WranglerOptionArity::Value {
                    let Some(value) = self.words.get(self.index) else {
                        return Err(WranglerCursorStop::Invalid);
                    };
                    if value.decoded == "--" {
                        return Err(WranglerCursorStop::Invalid);
                    }
                    self.index += 1;
                }
                continue;
            }
            if word.dynamic {
                return Err(WranglerCursorStop::Dynamic);
            }
            if text.starts_with('-') {
                return Err(WranglerCursorStop::Invalid);
            }
            return Ok(Some(word));
        }
        Ok(None)
    }
}

fn wrangler_option_arity(word: &str, scope: WranglerOptionScope) -> Option<WranglerOptionArity> {
    if matches!(
        word,
        "--install-skills" | "--no-install-skills" | "--verbose"
    ) || ["--install-skills=", "--verbose="]
        .iter()
        .any(|prefix| word.starts_with(prefix) && word.len() > prefix.len())
    {
        return Some(WranglerOptionArity::Flag);
    }
    if matches!(
        word,
        "-c" | "--config" | "--cwd" | "-e" | "--env" | "--env-file" | "--profile"
    ) {
        return Some(WranglerOptionArity::Value);
    }
    if ["--config=", "--cwd=", "--env=", "--env-file=", "--profile="]
        .iter()
        .any(|prefix| word.starts_with(prefix) && word.len() > prefix.len())
        || word.starts_with('-')
            && word.len() > 2
            && matches!(word.as_bytes().get(1), Some(b'c' | b'e'))
    {
        return Some(WranglerOptionArity::Flag);
    }

    if matches!(scope, WranglerOptionScope::Kv | WranglerOptionScope::R2) {
        if matches!(word, "--local" | "--remote")
            || ["--local=", "--remote="]
                .iter()
                .any(|prefix| word.starts_with(prefix) && word.len() > prefix.len())
        {
            return Some(WranglerOptionArity::Flag);
        }
        if word == "--persist-to" {
            return Some(WranglerOptionArity::Value);
        }
        if word.starts_with("--persist-to=") && word.len() > "--persist-to=".len() {
            return Some(WranglerOptionArity::Flag);
        }
    }

    if scope == WranglerOptionScope::Kv {
        if matches!(
            word,
            "--preview" | "-f" | "--force" | "-y" | "--skip-confirmation"
        ) || word.starts_with("--preview=") && word.len() > "--preview=".len()
        {
            return Some(WranglerOptionArity::Flag);
        }
        if matches!(word, "--namespace-id" | "--binding") {
            return Some(WranglerOptionArity::Value);
        }
        if ["--namespace-id=", "--binding="]
            .iter()
            .any(|prefix| word.starts_with(prefix) && word.len() > prefix.len())
        {
            return Some(WranglerOptionArity::Flag);
        }
    }

    if scope == WranglerOptionScope::R2 {
        if matches!(word, "-y" | "--force") {
            return Some(WranglerOptionArity::Flag);
        }
        if matches!(word, "-J" | "--jurisdiction") {
            return Some(WranglerOptionArity::Value);
        }
        if word.starts_with("--jurisdiction=") && word.len() > "--jurisdiction=".len()
            || word.starts_with("-J") && word.len() > 2
        {
            return Some(WranglerOptionArity::Flag);
        }
    }

    None
}

fn update_terminal_flags(word: &str, flags: &mut WranglerTerminalFlags) -> bool {
    match word {
        "-h" | "--help" | "--help=true" => flags.help = Some(true),
        "--no-help" | "--help=false" => flags.help = Some(false),
        "-v" | "--version" | "--version=true" => flags.version = Some(true),
        "--no-version" | "--version=false" => flags.version = Some(false),
        "--dry-run" | "--dry-run=true" => flags.dry_run = Some(true),
        "--no-dry-run" | "--dry-run=false" => flags.dry_run = Some(false),
        _ => return false,
    }
    true
}

fn executable_basename(word: &str) -> &str {
    let basename = word.rsplit(['/', '\\']).next().unwrap_or(word);
    [".exe", ".cmd", ".bat", ".com"]
        .iter()
        .find_map(|suffix| {
            basename.len().checked_sub(suffix.len()).and_then(|start| {
                basename
                    .get(start..)
                    .filter(|actual| actual.eq_ignore_ascii_case(suffix))
                    .and_then(|_| basename.get(..start))
            })
        })
        .unwrap_or(basename)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WranglerExecutableDecision {
    NoMatch,
    Found(usize),
    Unverified,
}

fn command_word_index(words: &[WranglerWord], dialect: ShellDialect) -> usize {
    let mut index = 0usize;
    if matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        while words
            .get(index)
            .is_some_and(|word| crate::normalize::is_env_assignment(&word.decoded))
        {
            index += 1;
        }
    }

    if dialect == ShellDialect::Cmd {
        while let Some(word) = words.get(index) {
            let text = word.decoded.trim_start_matches('@');
            if text.is_empty() || text.eq_ignore_ascii_case("call") {
                index += 1;
                continue;
            }
            break;
        }
    }
    index
}

fn runner_shell_payload_from_options(
    words: &[WranglerWord],
    mut index: usize,
) -> WranglerRunnerShellDecision {
    let mut payload = None;
    while let Some(word) = words.get(index) {
        let text = word.decoded.as_str();
        if word.dynamic {
            // Expansion in the option region may become `-c`, `--call`, `--`,
            // or a positional package name and therefore changes argv roles.
            return WranglerRunnerShellDecision::Unverified;
        }
        if text == "--" {
            break;
        }
        if matches!(text, "-c" | "--call") {
            let Some(value) = words.get(index + 1) else {
                return WranglerRunnerShellDecision::Unverified;
            };
            if value.dynamic {
                return WranglerRunnerShellDecision::Unverified;
            }
            payload = Some(value.decoded.clone());
            index += 2;
            continue;
        }
        if let Some(value) = text
            .strip_prefix("--call=")
            .or_else(|| text.strip_prefix("-c="))
        {
            payload = Some(value.to_string());
            index += 1;
            continue;
        }
        if matches!(
            text,
            "-p" | "--package" | "--cache" | "--userconfig" | "--dir" | "-C" | "-w" | "--workspace"
        ) {
            let Some(value) = words.get(index + 1) else {
                return WranglerRunnerShellDecision::Unverified;
            };
            if value.decoded == "--" {
                return WranglerRunnerShellDecision::Unverified;
            }
            index += 2;
            continue;
        }
        if text.starts_with('-') {
            index += 1;
            continue;
        }
        // npx stops parsing its own options at the first positional package.
        // npm exec rejects mixing a positional package with `--call`; either
        // way, a later Wrangler `-c` belongs to Wrangler rather than npm.
        break;
    }

    payload.map_or(
        WranglerRunnerShellDecision::NoMatch,
        WranglerRunnerShellDecision::Payload,
    )
}

fn npm_option_takes_value(text: &str) -> bool {
    matches!(
        text,
        "-p" | "--package"
            | "--cache"
            | "--userconfig"
            | "--dir"
            | "-C"
            | "--prefix"
            | "--registry"
            | "--loglevel"
            | "-w"
            | "--workspace"
    )
}

fn npm_shell_payload_decision(
    words: &[WranglerWord],
    mut index: usize,
) -> WranglerRunnerShellDecision {
    let mut saw_exec_mode = false;
    let mut payload = None;
    while let Some(word) = words.get(index) {
        let text = word.decoded.as_str();
        if word.dynamic {
            return WranglerRunnerShellDecision::Unverified;
        }
        if text == "--" {
            break;
        }
        if matches!(text, "-c" | "--call") {
            let Some(value) = words.get(index + 1) else {
                return WranglerRunnerShellDecision::Unverified;
            };
            if value.dynamic {
                return WranglerRunnerShellDecision::Unverified;
            }
            payload = Some(value.decoded.clone());
            index += 2;
            continue;
        }
        if let Some(value) = text
            .strip_prefix("--call=")
            .or_else(|| text.strip_prefix("-c="))
        {
            payload = Some(value.to_string());
            index += 1;
            continue;
        }
        if npm_option_takes_value(text) {
            let Some(value) = words.get(index + 1) else {
                return WranglerRunnerShellDecision::Unverified;
            };
            if value.decoded == "--" {
                return WranglerRunnerShellDecision::Unverified;
            }
            index += 2;
            continue;
        }
        if text.starts_with('-') {
            index += 1;
            continue;
        }
        if !saw_exec_mode && matches!(text, "exec" | "x") {
            saw_exec_mode = true;
            index += 1;
            continue;
        }
        break;
    }

    if !saw_exec_mode {
        WranglerRunnerShellDecision::NoMatch
    } else {
        payload.map_or(
            WranglerRunnerShellDecision::NoMatch,
            WranglerRunnerShellDecision::Payload,
        )
    }
}

fn npm_exec_runner_start(
    words: &[WranglerWord],
    mut index: usize,
    dialect: ShellDialect,
) -> WranglerExecutableDecision {
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return WranglerExecutableDecision::Unverified;
        }
        let text = word.decoded.as_str();
        if text == "--" {
            return WranglerExecutableDecision::NoMatch;
        }
        if npm_option_takes_value(text) {
            let Some(next) = index.checked_add(2) else {
                return WranglerExecutableDecision::Unverified;
            };
            if next > words.len() {
                return WranglerExecutableDecision::Unverified;
            }
            index = next;
            continue;
        }
        if text.starts_with('-') {
            index += 1;
            continue;
        }
        return if matches!(text, "exec" | "x") {
            runner_wrangler_index(words, index + 1, dialect)
        } else {
            WranglerExecutableDecision::NoMatch
        };
    }
    WranglerExecutableDecision::NoMatch
}

/// Whether argv still literally spells a runner shell-source option.
///
/// Used only where the executable itself is unbounded: the expansion carries no
/// runner evidence, but a literal `-c` / `--call` payload is a real embedded
/// shell seam and stays fail-closed.
fn argv_spells_runner_shell_call(words: &[WranglerWord]) -> bool {
    words.iter().any(|word| {
        !word.dynamic
            && (matches!(word.decoded.as_str(), "-c" | "--call")
                || word.decoded.starts_with("--call=")
                || word.decoded.starts_with("-c="))
    })
}

fn runner_shell_payload_segment_decision(
    segment: &str,
    dialect: ShellDialect,
) -> WranglerRunnerShellDecision {
    let stripped = matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
        .then(|| strip_wrapper_prefixes(segment));
    let segment = stripped
        .as_ref()
        .map_or(segment, |result| result.normalized.as_ref());
    let Some(decoded) = decode_words(segment, dialect) else {
        return WranglerRunnerShellDecision::NoMatch;
    };
    if decoded.over_limit {
        return WranglerRunnerShellDecision::Unverified;
    }
    let index = command_word_index(&decoded.words, dialect);
    let Some(executable) = decoded.words.get(index) else {
        return WranglerRunnerShellDecision::NoMatch;
    };
    if wrangler_word_is_unbounded(executable, dialect) {
        // An executable with zero literal bytes is no more `npx` than it is any
        // other program (#281). Only a literal runner shell-source option keeps
        // this seam fail-closed; `$cmd $arg` is simply an unknown command.
        return if argv_spells_runner_shell_call(&decoded.words[index + 1..]) {
            WranglerRunnerShellDecision::Unverified
        } else {
            WranglerRunnerShellDecision::NoMatch
        };
    }
    if executable.dynamic {
        return if ["npx", "npm"]
            .iter()
            .any(|candidate| symbolic_executable_may_equal(executable, dialect, candidate))
        {
            WranglerRunnerShellDecision::Unverified
        } else {
            WranglerRunnerShellDecision::NoMatch
        };
    }
    let executable = executable_basename(&executable.decoded);
    if executable.eq_ignore_ascii_case("npx") {
        return runner_shell_payload_from_options(&decoded.words, index + 1);
    }
    if !executable.eq_ignore_ascii_case("npm") {
        return WranglerRunnerShellDecision::NoMatch;
    }
    npm_shell_payload_decision(&decoded.words, index + 1)
}

fn runner_wrangler_index(
    words: &[WranglerWord],
    mut index: usize,
    dialect: ShellDialect,
) -> WranglerExecutableDecision {
    while let Some(word) = words.get(index) {
        let text = word.decoded.as_str();
        if text == "--" {
            index += 1;
            continue;
        }
        if matches!(
            text,
            "-y" | "--yes"
                | "--no-install"
                | "--ignore-existing"
                | "--quiet"
                | "--silent"
                | "--verbose"
                | "--bun"
                | "-s"
                | "--prefer-online"
                | "--prefer-offline"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            text,
            "-p" | "--package" | "--cache" | "--userconfig" | "--dir" | "-C"
        ) {
            let Some(next) = index.checked_add(2) else {
                return WranglerExecutableDecision::NoMatch;
            };
            index = next;
            if index > words.len() {
                return WranglerExecutableDecision::NoMatch;
            }
            continue;
        }
        if text.starts_with("--package=")
            || text.starts_with("--cache=")
            || text.starts_with("--userconfig=")
            || text.starts_with("--dir=")
        {
            index += 1;
            continue;
        }
        if word.dynamic {
            // A runner expands its own option/package prefix before deciding
            // which binary to execute. A dynamic word here may disappear,
            // become an option, or name Wrangler, so the following argv cannot
            // be safely reinterpreted as an unrelated command.
            return WranglerExecutableDecision::Unverified;
        }
        if text.starts_with('-') {
            return if remaining_words_may_name_wrangler(words, index + 1, dialect) {
                // Runner option surfaces evolve independently.  If an unknown
                // option precedes a statically visible Wrangler package, it
                // may be a flag or consume that word as its value; neither
                // interpretation proves the protected command harmless.
                WranglerExecutableDecision::Unverified
            } else {
                WranglerExecutableDecision::NoMatch
            };
        }
        return runner_package_decision(text, index);
    }
    WranglerExecutableDecision::NoMatch
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageRunner {
    Bun,
    Pnpm,
    Yarn,
}

fn package_runner_prefix_option_arity(
    runner: PackageRunner,
    option: &str,
) -> Option<WranglerOptionArity> {
    let flag = match runner {
        PackageRunner::Bun => matches!(
            option,
            "-b" | "--bun"
                | "--hot"
                | "--watch"
                | "--smol"
                | "--silent"
                | "--prefer-offline"
                | "--prefer-latest"
                | "--no-install"
                | "--no-env-file"
                | "--workspaces"
                | "--parallel"
                | "--sequential"
                | "--no-exit-on-error"
        ),
        PackageRunner::Pnpm => matches!(
            option,
            "-r" | "--recursive"
                | "-w"
                | "--workspace-root"
                | "--silent"
                | "--parallel"
                | "--stream"
                | "--aggregate-output"
                | "--use-stderr"
                | "--report-summary"
                | "--fail-if-no-match"
        ),
        PackageRunner::Yarn => matches!(
            option,
            "-s" | "--silent"
                | "--verbose"
                | "--offline"
                | "--prefer-offline"
                | "--non-interactive"
                | "--ignore-scripts"
                | "--ignore-engines"
                | "--json"
                | "--no-progress"
                | "--no-default-rc"
        ),
    };
    if flag {
        return Some(WranglerOptionArity::Flag);
    }

    let value = match runner {
        PackageRunner::Bun => matches!(
            option,
            "-r" | "--preload"
                | "--require"
                | "--import"
                | "--inspect"
                | "--inspect-wait"
                | "--inspect-brk"
                | "--install"
                | "--conditions"
                | "--env-file"
                | "--shell"
                | "-F"
                | "--filter"
        ),
        PackageRunner::Pnpm => matches!(
            option,
            "-C" | "--dir"
                | "--filter"
                | "--filter-prod"
                | "--reporter"
                | "--loglevel"
                | "--workspace-concurrency"
                | "--resume-from"
        ),
        PackageRunner::Yarn => matches!(
            option,
            "--cwd"
                | "--cache-folder"
                | "--global-folder"
                | "--link-folder"
                | "--modules-folder"
                | "--mutex"
                | "--network-concurrency"
                | "--network-timeout"
                | "--registry"
                | "--use-yarnrc"
        ),
    };
    value.then_some(WranglerOptionArity::Value)
}

fn package_runner_attached_option(runner: PackageRunner, option: &str) -> bool {
    let prefixes: &[&str] = match runner {
        PackageRunner::Bun => &[
            "--preload=",
            "--require=",
            "--import=",
            "--inspect=",
            "--inspect-wait=",
            "--inspect-brk=",
            "--install=",
            "--conditions=",
            "--env-file=",
            "--shell=",
            "--filter=",
        ],
        PackageRunner::Pnpm => &[
            "--dir=",
            "--filter=",
            "--filter-prod=",
            "--reporter=",
            "--loglevel=",
            "--workspace-concurrency=",
            "--resume-from=",
        ],
        PackageRunner::Yarn => &[
            "--cwd=",
            "--cache-folder=",
            "--global-folder=",
            "--link-folder=",
            "--modules-folder=",
            "--mutex=",
            "--network-concurrency=",
            "--network-timeout=",
            "--registry=",
            "--use-yarnrc=",
        ],
    };
    prefixes
        .iter()
        .any(|prefix| option.starts_with(prefix) && option.len() > prefix.len())
}

/// Literal word whose executable basename is `wrangler` once Windows program
/// suffixes are stripped, mirroring the main resolver's `executable_basename`
/// treatment so `wrangler.exe` / `wrangler.cmd` (and their path forms) carry
/// the same evidence weight at the wrapper seam (#283).
fn literal_word_names_wrangler_executable(word: &WranglerWord, dialect: ShellDialect) -> bool {
    if word.dynamic {
        return false;
    }
    let decoded = if dialect == ShellDialect::Cmd {
        word.decoded.trim_start_matches('@')
    } else {
        word.decoded.as_str()
    };
    executable_basename(decoded).eq_ignore_ascii_case("wrangler")
}

/// A word that is a pure expansion with zero literal bytes: it may expand to
/// anything, so it names nothing in particular and carries no Wrangler evidence
/// on its own (#281, mirroring `git_semantic_word_is_unbounded`). A partially
/// literal expansion such as `wran$X` keeps its conservative treatment.
fn wrangler_word_is_unbounded(word: &WranglerWord, dialect: ShellDialect) -> bool {
    if !word.dynamic {
        return false;
    }
    let decoded = if dialect == ShellDialect::Cmd {
        word.decoded.trim_start_matches('@')
    } else {
        word.decoded.as_str()
    };
    let basename = decoded.rsplit(['/', '\\']).next().unwrap_or(decoded);
    dynamic_fragments(basename, dialect)
        .iter()
        .all(String::is_empty)
}

/// Positive Wrangler evidence in `words[index..]`, ignoring unbounded words.
///
/// This is [`remaining_words_may_name_wrangler`] restricted to words that can
/// actually testify: an unbounded expansion matches every candidate, so letting
/// it satisfy the evidence gate would re-admit the whole `$X $Y` class (#281).
fn remaining_words_carry_wrangler_evidence(
    words: &[WranglerWord],
    index: usize,
    dialect: ShellDialect,
) -> bool {
    words[index..].iter().any(|word| {
        !wrangler_word_is_unbounded(word, dialect)
            && (symbolic_executable_may_equal(word, dialect, "wrangler")
                || (!word.dynamic
                    && (word.decoded.starts_with("wrangler@")
                        || literal_word_names_wrangler_executable(word, dialect)
                        || is_wrangler_script_path(&word.decoded))))
    })
}

fn remaining_words_may_name_wrangler(
    words: &[WranglerWord],
    index: usize,
    dialect: ShellDialect,
) -> bool {
    words[index..].iter().any(|word| {
        symbolic_executable_may_equal(word, dialect, "wrangler")
            || (!word.dynamic
                && (word.decoded.starts_with("wrangler@")
                    || literal_word_names_wrangler_executable(word, dialect)
                    || is_wrangler_script_path(&word.decoded)))
    })
}

fn package_runner_command_index(
    words: &[WranglerWord],
    mut index: usize,
    dialect: ShellDialect,
    runner: PackageRunner,
) -> Result<usize, WranglerExecutableDecision> {
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return Err(
                if runner == PackageRunner::Bun
                    && trailing_argv_is_destructive_wrangler_shape(words, index + 1, dialect)
                    || remaining_words_may_name_wrangler(words, index, dialect)
                {
                    WranglerExecutableDecision::Unverified
                } else {
                    WranglerExecutableDecision::NoMatch
                },
            );
        }
        let option = word.decoded.as_str();
        if option == "--" {
            return Ok(index + 1);
        }
        if package_runner_attached_option(runner, option) {
            index += 1;
            continue;
        }
        if let Some(arity) = package_runner_prefix_option_arity(runner, option) {
            index += 1;
            if arity == WranglerOptionArity::Value {
                if words.get(index).is_none() {
                    return Err(WranglerExecutableDecision::NoMatch);
                }
                index += 1;
            }
            continue;
        }
        if option.starts_with('-') {
            return Err(
                if remaining_words_may_name_wrangler(words, index + 1, dialect) {
                    WranglerExecutableDecision::Unverified
                } else {
                    WranglerExecutableDecision::NoMatch
                },
            );
        }
        return Ok(index);
    }
    Err(WranglerExecutableDecision::NoMatch)
}

fn runner_package_decision(package: &str, index: usize) -> WranglerExecutableDecision {
    if package.starts_with('@') || package.contains("npm:") {
        return WranglerExecutableDecision::Unverified;
    }
    if executable_basename(package).eq_ignore_ascii_case("wrangler") {
        return WranglerExecutableDecision::Found(index);
    }

    if let Some(spec) = package.strip_prefix("wrangler@") {
        if !spec.is_empty()
            && !spec.contains([':', '/', '@'])
            && spec.chars().all(|ch| {
                ch.is_ascii_alphanumeric()
                    || matches!(
                        ch,
                        '.' | '-' | '_' | '+' | '~' | '^' | '<' | '>' | '=' | '*' | 'x' | 'X'
                    )
            })
        {
            return WranglerExecutableDecision::Found(index);
        }
        return WranglerExecutableDecision::Unverified;
    }

    WranglerExecutableDecision::NoMatch
}

fn is_wrangler_script_path(path: &str) -> bool {
    let basename = path.rsplit(['/', '\\']).next().unwrap_or(path);
    matches_ignore_ascii_case(basename, &["wrangler.js", "wrangler.mjs", "wrangler.cjs"])
}

fn matches_ignore_ascii_case(candidate: &str, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|value| candidate.eq_ignore_ascii_case(value))
}

fn posix_quote_semantic_word(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn trailing_argv_is_destructive_wrangler_shape(
    words: &[WranglerWord],
    index: usize,
    dialect: ShellDialect,
) -> bool {
    let trailing = &words[index..];
    if trailing.iter().any(|word| word.dynamic) {
        return trailing
            .iter()
            .any(|word| word.may_equal("delete", dialect) || word.may_equal("rollback", dialect));
    }

    let mut synthetic = String::from("wrangler");
    for word in trailing {
        synthetic.push(' ');
        synthetic.push_str(&posix_quote_semantic_word(&word.decoded));
    }
    matches!(
        wrangler_segment_semantic_decision(&synthetic, ShellDialect::Posix),
        WranglerSemanticDecision::Destructive(_) | WranglerSemanticDecision::Unverified
    )
}

/// Destructive Wrangler argv behind an *unbounded* executable word.
///
/// Same question as [`trailing_argv_is_destructive_wrangler_shape`], except an
/// unbounded trailing word may not supply the `delete`/`rollback` evidence:
/// otherwise `$X $Y` would deny on the strength of two words that name nothing
/// (#281). Literal argv (`$W r2 bucket delete x`) still denies.
fn unbounded_executable_argv_is_destructive_wrangler_shape(
    words: &[WranglerWord],
    index: usize,
    dialect: ShellDialect,
) -> bool {
    let trailing = &words[index..];
    if trailing.is_empty() {
        return false;
    }
    if trailing.iter().any(|word| word.dynamic) {
        return trailing.iter().any(|word| {
            !wrangler_word_is_unbounded(word, dialect)
                && (word.may_equal("delete", dialect) || word.may_equal("rollback", dialect))
        });
    }
    trailing_argv_is_destructive_wrangler_shape(words, index, dialect)
}

fn runtime_script_candidate_decision(
    words: &[WranglerWord],
    index: usize,
    dialect: ShellDialect,
) -> WranglerExecutableDecision {
    let Some(candidate) = words.get(index) else {
        return WranglerExecutableDecision::NoMatch;
    };
    if !candidate.dynamic {
        return if is_wrangler_script_path(&candidate.decoded) {
            WranglerExecutableDecision::Found(index)
        } else {
            WranglerExecutableDecision::NoMatch
        };
    }

    // The token decoder may resolve an expansion to an empty placeholder, so
    // no decoded fragment can prove that a dynamic script path is unrelated.
    // Keep the fail-closed decision narrowly gated by destructive Wrangler
    // argv; `$SCRIPT --version` remains an irrelevant safe control.
    if trailing_argv_is_destructive_wrangler_shape(words, index + 1, dialect) {
        WranglerExecutableDecision::Unverified
    } else {
        WranglerExecutableDecision::NoMatch
    }
}

fn node_wrangler_script_index(
    words: &[WranglerWord],
    mut index: usize,
    dialect: ShellDialect,
) -> WranglerExecutableDecision {
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return runtime_script_candidate_decision(words, index, dialect);
        }
        let text = word.decoded.as_str();
        if text == "--" {
            return runtime_script_candidate_decision(words, index + 1, dialect);
        }
        if matches_ignore_ascii_case(
            text,
            &[
                "-e",
                "--eval",
                "-p",
                "--print",
                "-c",
                "--check",
                "--syntax-check",
                "-h",
                "--help",
                "-v",
                "--version",
            ],
        ) || text.starts_with("--eval=")
            || text.starts_with("--print=")
        {
            // Inline source, syntax-only, and terminal-information modes do
            // not execute a later script-looking argv word.
            return WranglerExecutableDecision::NoMatch;
        }
        if matches_ignore_ascii_case(
            text,
            &[
                "-r",
                "--require",
                "--import",
                "--loader",
                "--experimental-loader",
                "-C",
                "--conditions",
                "--inspect-port",
                "--diagnostic-dir",
                "--openssl-config",
                "--icu-data-dir",
            ],
        ) {
            let Some(next) = index.checked_add(2) else {
                return WranglerExecutableDecision::Unverified;
            };
            if next > words.len() {
                return WranglerExecutableDecision::Unverified;
            }
            index = next;
            continue;
        }
        if text.starts_with('-') {
            index += 1;
            continue;
        }
        return runtime_script_candidate_decision(words, index, dialect);
    }
    WranglerExecutableDecision::NoMatch
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaScriptRuntime {
    Bun,
    Deno,
}

fn javascript_runtime_wrangler_script_index(
    words: &[WranglerWord],
    mut index: usize,
    dialect: ShellDialect,
    runtime: JavaScriptRuntime,
) -> WranglerExecutableDecision {
    let mut accepted_run_mode = false;
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return runtime_script_candidate_decision(words, index, dialect);
        }
        let text = word.decoded.as_str();
        if text == "--" {
            return runtime_script_candidate_decision(words, index + 1, dialect);
        }
        if matches_ignore_ascii_case(
            text,
            &[
                "-e",
                "--eval",
                "-p",
                "--print",
                "-h",
                "--help",
                "-v",
                "--version",
            ],
        ) || text.starts_with("--eval=")
        {
            return WranglerExecutableDecision::NoMatch;
        }
        if matches_ignore_ascii_case(
            text,
            &[
                "-C",
                "--cwd",
                "-r",
                "--preload",
                "--env-file",
                "--loader",
                "--define",
                "--conditions",
                "-c",
                "--config",
                "--import-map",
                "--cert",
                "--location",
                "--v8-flags",
                "--seed",
            ],
        ) {
            let Some(next) = index.checked_add(2) else {
                return WranglerExecutableDecision::Unverified;
            };
            if next > words.len() {
                return WranglerExecutableDecision::Unverified;
            }
            index = next;
            continue;
        }
        if text.starts_with('-') {
            index += 1;
            continue;
        }
        if !accepted_run_mode && text.eq_ignore_ascii_case("run") {
            accepted_run_mode = true;
            index += 1;
            continue;
        }
        let non_execution_modes: &[&str] = match runtime {
            JavaScriptRuntime::Bun => &[
                "add", "build", "create", "help", "init", "install", "link", "pm", "remove",
                "test", "unlink", "update", "upgrade",
            ],
            JavaScriptRuntime::Deno => &[
                "add",
                "bench",
                "check",
                "compile",
                "doc",
                "fmt",
                "help",
                "info",
                "install",
                "jupyter",
                "lint",
                "repl",
                "task",
                "test",
                "uninstall",
                "upgrade",
            ],
        };
        if !accepted_run_mode && matches_ignore_ascii_case(text, non_execution_modes) {
            return WranglerExecutableDecision::NoMatch;
        }
        return runtime_script_candidate_decision(words, index, dialect);
    }
    WranglerExecutableDecision::NoMatch
}

/// Whether the options after the `command` builtin select its query form.
///
/// POSIX spells it `command [-p] -v|-V name`: `-v`/`-V` print how `name` would
/// resolve instead of running it. Option clustering (`-pv`) counts; a dynamic
/// or non-option word ends the scan without a query.
fn command_builtin_is_lookup_query(
    words: &[WranglerWord],
    mut index: usize,
    dialect: ShellDialect,
) -> bool {
    while let Some(word) = words.get(index) {
        if word.dynamic {
            return false;
        }
        let text = if dialect == ShellDialect::Cmd {
            word.decoded.trim_start_matches('@')
        } else {
            word.decoded.as_str()
        };
        let Some(flags) = text.strip_prefix('-') else {
            return false;
        };
        if flags.is_empty() || flags.starts_with('-') {
            return false;
        }
        if flags.contains(['v', 'V']) {
            return true;
        }
        if !flags.chars().all(|ch| ch == 'p') {
            return false;
        }
        index += 1;
    }
    false
}

fn find_wrangler_index(
    words: &[WranglerWord],
    dialect: ShellDialect,
) -> WranglerExecutableDecision {
    let mut index = 0usize;
    if matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        while words
            .get(index)
            .is_some_and(|word| crate::normalize::is_env_assignment(&word.decoded))
        {
            index += 1;
        }
    }

    if dialect == ShellDialect::Cmd {
        while let Some(word) = words.get(index) {
            let text = word.decoded.trim_start_matches('@');
            if text.is_empty() {
                index += 1;
                continue;
            }
            if text.eq_ignore_ascii_case("call") {
                index += 1;
                continue;
            }
            break;
        }
    }

    let Some(first_word) = words.get(index) else {
        return WranglerExecutableDecision::NoMatch;
    };
    let mut first_text = first_word.decoded.as_str();
    if dialect == ShellDialect::Cmd {
        first_text = first_text.trim_start_matches('@');
    }
    let first = executable_basename(first_text);
    if first.eq_ignore_ascii_case("wrangler") {
        return WranglerExecutableDecision::Found(index);
    }
    if wrangler_word_is_unbounded(first_word, dialect) {
        // An executable word with zero literal bytes may expand to anything, so
        // it is evidence for nothing: `$cmd $arg` and `"$X" "$Y"` are unknown
        // commands, not unverified Wrangler invocations (#281, #273). Fail
        // closed only when the rest of the segment carries positive Wrangler
        // evidence, or spells a destructive Wrangler argv the expansion would
        // complete (`$W r2 bucket delete x`).
        return if remaining_words_carry_wrangler_evidence(words, index + 1, dialect)
            || unbounded_executable_argv_is_destructive_wrangler_shape(words, index + 1, dialect)
        {
            WranglerExecutableDecision::Unverified
        } else {
            WranglerExecutableDecision::NoMatch
        };
    }
    if first_word.dynamic {
        return if symbolic_executable_may_equal(first_word, dialect, "wrangler")
            || symbolic_executable_may_equal(first_word, dialect, "wrangler.exe")
            || ["npx", "bunx", "bun", "pnpm", "yarn", "npm", "node", "deno"]
                .iter()
                .any(|runner| symbolic_executable_may_equal(first_word, dialect, runner))
        {
            WranglerExecutableDecision::Unverified
        } else {
            WranglerExecutableDecision::NoMatch
        };
    }

    if first.eq_ignore_ascii_case("command")
        && command_builtin_is_lookup_query(words, index + 1, dialect)
    {
        // `command -v NAME` / `command -V NAME` *looks NAME up* and executes
        // nothing, which is why the normalizer refuses to peel it (#289 §3).
        // The suffix naming Wrangler is therefore not a Wrangler invocation
        // under any dialect; `command wrangler ...` (no -v) still runs it.
        return WranglerExecutableDecision::NoMatch;
    }

    if ["sudo", "env", "command", "exec", "nohup", "time", "!"]
        .iter()
        .any(|wrapper| first.eq_ignore_ascii_case(wrapper))
    {
        // The shared normalizer deliberately caps recursive wrappers. If a
        // wrapper remains at this seam, suffix execution is real but lies
        // beyond our bounded peel depth. Fail closed only when the suffix
        // carries positive Wrangler evidence; a bare wrapper word whose
        // suffix is absent or provably unrelated (`command -v foo`, `env`,
        // `time foo`) is not a Wrangler invocation (#283).
        return if remaining_words_may_name_wrangler(words, index + 1, dialect) {
            WranglerExecutableDecision::Unverified
        } else {
            WranglerExecutableDecision::NoMatch
        };
    }

    if first.eq_ignore_ascii_case("npx") || first.eq_ignore_ascii_case("bunx") {
        return runner_wrangler_index(words, index + 1, dialect);
    }
    if first.eq_ignore_ascii_case("bun") {
        let mode_index =
            match package_runner_command_index(words, index + 1, dialect, PackageRunner::Bun) {
                Ok(index) => index,
                Err(decision) => return decision,
            };
        let Some(mode) = words.get(mode_index) else {
            return WranglerExecutableDecision::NoMatch;
        };
        if mode.dynamic {
            return runtime_script_candidate_decision(words, mode_index, dialect);
        }
        return if matches!(mode.decoded.as_str(), "x" | "exec") {
            runner_wrangler_index(words, mode_index + 1, dialect)
        } else {
            javascript_runtime_wrangler_script_index(
                words,
                mode_index,
                dialect,
                JavaScriptRuntime::Bun,
            )
        };
    }
    if first.eq_ignore_ascii_case("pnpm") || first.eq_ignore_ascii_case("yarn") {
        let runner = if first.eq_ignore_ascii_case("pnpm") {
            PackageRunner::Pnpm
        } else {
            PackageRunner::Yarn
        };
        let mut package_index =
            match package_runner_command_index(words, index + 1, dialect, runner) {
                Ok(index) => index,
                Err(decision) => return decision,
            };
        if let Some(mode) = words.get(package_index) {
            if mode.dynamic {
                return WranglerExecutableDecision::Unverified;
            }
            if matches!(mode.decoded.as_str(), "dlx" | "exec") {
                package_index += 1;
            }
        }
        return runner_wrangler_index(words, package_index, dialect);
    }
    if first.eq_ignore_ascii_case("npm") {
        return npm_exec_runner_start(words, index + 1, dialect);
    }
    if first.eq_ignore_ascii_case("node") {
        return node_wrangler_script_index(words, index + 1, dialect);
    }
    if first.eq_ignore_ascii_case("deno") {
        return javascript_runtime_wrangler_script_index(
            words,
            index + 1,
            dialect,
            JavaScriptRuntime::Deno,
        );
    }

    WranglerExecutableDecision::NoMatch
}

fn words_prove_irrelevant_executable(words: &[WranglerWord], dialect: ShellDialect) -> bool {
    let mut index = 0usize;
    if matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        while words
            .get(index)
            .is_some_and(|word| crate::normalize::is_env_assignment(&word.decoded))
        {
            index += 1;
        }
    }
    if dialect == ShellDialect::Cmd {
        while let Some(word) = words.get(index) {
            let text = word.decoded.trim_start_matches('@');
            if text.is_empty() || text.eq_ignore_ascii_case("call") {
                index += 1;
                continue;
            }
            break;
        }
    }

    let Some(word) = words.get(index) else {
        return false;
    };
    if word.dynamic {
        return false;
    }
    let text = if dialect == ShellDialect::Cmd {
        word.decoded.trim_start_matches('@')
    } else {
        &word.decoded
    };
    let executable = executable_basename(text);
    !executable.eq_ignore_ascii_case("wrangler")
        && !["npx", "bunx", "bun", "pnpm", "yarn", "npm", "node", "deno"]
            .iter()
            .any(|runner| executable.eq_ignore_ascii_case(runner))
        && !["sudo", "env", "command", "exec", "nohup", "time", "!"]
            .iter()
            .any(|wrapper| executable.eq_ignore_ascii_case(wrapper))
}

fn token_has_active_expansion(raw: &str, dialect: ShellDialect) -> bool {
    match dialect {
        ShellDialect::Posix | ShellDialect::Unknown => posix_token_has_active_expansion(raw),
        ShellDialect::PowerShell => powershell_token_has_active_expansion(raw),
        ShellDialect::Cmd => cmd_token_has_active_expansion(raw),
    }
}

fn posix_token_has_active_expansion(raw: &str) -> bool {
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
            '$' if !single => {
                if !matches!(chars.peek(), Some('\'' | '"')) {
                    return true;
                }
            }
            '`' if !single => return true,
            '*' | '?' | '[' | '{' if !single && !double => return true,
            '<' | '>' if !single && chars.peek() == Some(&'(') => return true,
            _ => {}
        }
    }
    false
}

fn powershell_token_has_active_expansion(raw: &str) -> bool {
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

fn cmd_token_has_active_expansion(raw: &str) -> bool {
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

fn dynamic_fragments(decoded: &str, dialect: ShellDialect) -> Vec<String> {
    let mut fragments = vec![String::new()];
    let chars: Vec<char> = decoded.chars().collect();
    let mut index = 0usize;
    let mut dynamic = false;
    while index < chars.len() {
        let start_dynamic = match dialect {
            ShellDialect::Posix | ShellDialect::Unknown => match chars[index] {
                '$' | '`' | '*' | '?' | '{' => true,
                // POSIX globbing only activates a bracket expression that
                // closes; an unmatched `[` stays a literal character, so the
                // bare test builtin `[` must not read as "may be any
                // executable" (#283).
                '[' => chars[index + 1..].contains(&']'),
                _ => false,
            },
            ShellDialect::PowerShell => {
                chars[index] == '$' || chars[index] == '@' && chars.get(index + 1) == Some(&'(')
            }
            ShellDialect::Cmd => matches!(chars[index], '%' | '!'),
        };
        if !start_dynamic {
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

fn symbolic_word_may_equal(
    decoded: &str,
    dynamic: bool,
    dialect: ShellDialect,
    candidate: &str,
    ascii_case_insensitive: bool,
) -> bool {
    if !dynamic {
        return if ascii_case_insensitive {
            decoded.eq_ignore_ascii_case(candidate)
        } else {
            decoded == candidate
        };
    }
    let decoded = if ascii_case_insensitive {
        decoded.to_ascii_lowercase()
    } else {
        decoded.to_string()
    };
    let candidate = if ascii_case_insensitive {
        candidate.to_ascii_lowercase()
    } else {
        candidate.to_string()
    };
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

fn symbolic_executable_may_equal(
    word: &WranglerWord,
    dialect: ShellDialect,
    candidate: &str,
) -> bool {
    let decoded = if dialect == ShellDialect::Cmd {
        word.decoded.trim_start_matches('@')
    } else {
        &word.decoded
    };
    let basename = decoded.rsplit(['/', '\\']).next().unwrap_or(decoded);
    symbolic_word_may_equal(basename, word.dynamic, dialect, candidate, true)
}

struct DecodedWranglerWords {
    words: Vec<WranglerWord>,
    over_limit: bool,
}

fn decode_words(command: &str, dialect: ShellDialect) -> Option<DecodedWranglerWords> {
    let dialect = if dialect == ShellDialect::Unknown {
        ShellDialect::Posix
    } else {
        dialect
    };
    let tokens = tokenize_for_shell_dialect(command, dialect);
    if tokens
        .iter()
        .any(|token| token.kind == NormalizeTokenKind::Separator)
    {
        return None;
    }
    let over_limit = tokens.len() > MAX_WRANGLER_SEMANTIC_TOKENS;
    let mut decoder = ShellTokenDecoder::new(dialect);
    let mut powershell_literal = false;
    let words = tokens
        .iter()
        .filter(|token| token.kind == NormalizeTokenKind::Word)
        .take(MAX_WRANGLER_SEMANTIC_TOKENS)
        .map(|token| {
            let raw = token.text(command)?;
            let decoded = decoder.decode(raw, ShellTokenRole::Syntax);
            let Some(decoded) = decoded else {
                powershell_literal = true;
                return Some(None);
            };
            let dynamic = !powershell_literal && token_has_active_expansion(raw, dialect);
            Some(Some(WranglerWord {
                decoded: decoded.into_owned(),
                dynamic,
            }))
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    Some(DecodedWranglerWords { words, over_limit })
}

fn terminal_override(
    words: &[WranglerWord],
    mut index: usize,
    scope: WranglerOptionScope,
    allow_dry_run: bool,
    mut terminal_flags: WranglerTerminalFlags,
) -> Option<WranglerSemanticDecision> {
    while let Some(word) = words.get(index) {
        index += 1;
        let text = word.decoded.as_str();
        if text == "--" {
            break;
        }
        if update_terminal_flags(text, &mut terminal_flags) {
            continue;
        }
        if !word.dynamic && wrangler_option_arity(text, scope) == Some(WranglerOptionArity::Value) {
            index += usize::from(words.get(index).is_some());
        }
    }
    if terminal_flags.help == Some(true)
        || terminal_flags.version == Some(true)
        || allow_dry_run && terminal_flags.dry_run == Some(true)
    {
        Some(WranglerSemanticDecision::Safe)
    } else {
        None
    }
}

fn wrangler_segment_semantic_decision(
    segment: &str,
    dialect: ShellDialect,
) -> WranglerSemanticDecision {
    if !matches!(
        runner_shell_payload_segment_decision(segment, dialect),
        WranglerRunnerShellDecision::NoMatch
    ) {
        // The evaluator must recurse into a static payload as a separate shell
        // program.  This direct pack API cannot do so, therefore it remains
        // fail-closed even when the payload itself is statically decoded.
        return WranglerSemanticDecision::Unverified;
    }
    // Enforce the token budget against the submitted segment before wrapper
    // normalization. Otherwise a long assignment/env prefix can be partially
    // stripped by the separately bounded wrapper pass and turn an over-budget
    // command into a deceptively small, fully classified Wrangler invocation.
    let Some(original_decoded) = decode_words(segment, dialect) else {
        return WranglerSemanticDecision::NoMatch;
    };
    if original_decoded.over_limit {
        return match find_wrangler_index(&original_decoded.words, dialect) {
            WranglerExecutableDecision::Found(_) | WranglerExecutableDecision::Unverified => {
                WranglerSemanticDecision::Unverified
            }
            WranglerExecutableDecision::NoMatch
                if words_prove_irrelevant_executable(&original_decoded.words, dialect) =>
            {
                WranglerSemanticDecision::NoMatch
            }
            WranglerExecutableDecision::NoMatch => WranglerSemanticDecision::Unverified,
        };
    }
    let stripped = matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
        .then(|| strip_wrapper_prefixes(segment));
    let segment = stripped
        .as_ref()
        .map_or(segment, |result| result.normalized.as_ref());
    let Some(decoded) = decode_words(segment, dialect) else {
        return WranglerSemanticDecision::NoMatch;
    };
    let executable = find_wrangler_index(&decoded.words, dialect);
    if decoded.over_limit {
        return match executable {
            WranglerExecutableDecision::Found(_) | WranglerExecutableDecision::Unverified => {
                WranglerSemanticDecision::Unverified
            }
            WranglerExecutableDecision::NoMatch
                if words_prove_irrelevant_executable(&decoded.words, dialect) =>
            {
                WranglerSemanticDecision::NoMatch
            }
            WranglerExecutableDecision::NoMatch => WranglerSemanticDecision::Unverified,
        };
    }
    let wrangler_index = match executable {
        WranglerExecutableDecision::Found(index) => index,
        WranglerExecutableDecision::Unverified => return WranglerSemanticDecision::Unverified,
        WranglerExecutableDecision::NoMatch => return WranglerSemanticDecision::NoMatch,
    };
    let mut cursor = WranglerWordCursor::new(&decoded.words, wrangler_index + 1);

    macro_rules! next_word {
        ($scope:expr, $candidates:expr) => {
            match cursor.next($scope) {
                Ok(Some(word)) => word,
                Err(WranglerCursorStop::Dynamic) => {
                    let word = &decoded.words[cursor.index - 1];
                    if word.decoded.starts_with('-')
                        || $candidates
                            .iter()
                            .any(|candidate| word.may_equal(candidate, dialect))
                    {
                        return WranglerSemanticDecision::Unverified;
                    }
                    return WranglerSemanticDecision::NoMatch;
                }
                Ok(None)
                    if cursor.terminal_flags.help == Some(true)
                        || cursor.terminal_flags.version == Some(true) =>
                {
                    return WranglerSemanticDecision::Safe;
                }
                Ok(None) | Err(WranglerCursorStop::Terminated | WranglerCursorStop::Invalid) => {
                    return WranglerSemanticDecision::NoMatch
                }
            }
        };
    }

    let first = next_word!(
        WranglerOptionScope::Global,
        [
            "delete",
            "whoami",
            "dev",
            "tail",
            "help",
            "version",
            "deployments",
            "d1",
            "r2",
            "kv",
            "kv:key",
            "kv:namespace",
            "kv:bulk"
        ]
    )
    .decoded
    .as_str();
    match first {
        "delete" => terminal_override(
            &decoded.words,
            cursor.index,
            WranglerOptionScope::Global,
            true,
            cursor.terminal_flags,
        )
        .unwrap_or(WranglerSemanticDecision::Destructive("wrangler-delete")),
        "whoami" | "dev" | "tail" | "help" | "version" => WranglerSemanticDecision::Safe,
        "deployments" => match next_word!(WranglerOptionScope::Global, ["rollback"])
            .decoded
            .as_str()
        {
            "rollback" => terminal_override(
                &decoded.words,
                cursor.index,
                WranglerOptionScope::Global,
                false,
                cursor.terminal_flags,
            )
            .unwrap_or(WranglerSemanticDecision::Destructive(
                "wrangler-deployments-rollback",
            )),
            _ => WranglerSemanticDecision::NoMatch,
        },
        "d1" => match next_word!(WranglerOptionScope::Global, ["delete", "list", "info"])
            .decoded
            .as_str()
        {
            "delete" => terminal_override(
                &decoded.words,
                cursor.index,
                WranglerOptionScope::Global,
                false,
                cursor.terminal_flags,
            )
            .unwrap_or(WranglerSemanticDecision::Destructive("wrangler-d1-delete")),
            "list" | "info" => WranglerSemanticDecision::Safe,
            _ => WranglerSemanticDecision::NoMatch,
        },
        "r2" => {
            let resource = next_word!(WranglerOptionScope::R2, ["object", "bucket"])
                .decoded
                .as_str();
            let operation = next_word!(WranglerOptionScope::R2, ["delete", "get", "list"])
                .decoded
                .as_str();
            match (resource, operation) {
                ("object", "delete") => terminal_override(
                    &decoded.words,
                    cursor.index,
                    WranglerOptionScope::R2,
                    false,
                    cursor.terminal_flags,
                )
                .unwrap_or(WranglerSemanticDecision::Destructive(
                    "wrangler-r2-object-delete",
                )),
                ("bucket", "delete") => terminal_override(
                    &decoded.words,
                    cursor.index,
                    WranglerOptionScope::R2,
                    false,
                    cursor.terminal_flags,
                )
                .unwrap_or(WranglerSemanticDecision::Destructive(
                    "wrangler-r2-bucket-delete",
                )),
                ("object", "get") | ("bucket", "list") => WranglerSemanticDecision::Safe,
                _ => WranglerSemanticDecision::NoMatch,
            }
        }
        "kv" | "kv:key" | "kv:namespace" | "kv:bulk" => {
            let resource = match first {
                "kv" => next_word!(WranglerOptionScope::Kv, ["key", "namespace", "bulk"])
                    .decoded
                    .as_str(),
                "kv:key" => "key",
                "kv:namespace" => "namespace",
                "kv:bulk" => "bulk",
                _ => unreachable!(),
            };
            let operation = next_word!(WranglerOptionScope::Kv, ["delete", "get", "list"])
                .decoded
                .as_str();
            match (resource, operation) {
                ("key", "delete") => terminal_override(
                    &decoded.words,
                    cursor.index,
                    WranglerOptionScope::Kv,
                    false,
                    cursor.terminal_flags,
                )
                .unwrap_or(WranglerSemanticDecision::Destructive(
                    "wrangler-kv-key-delete",
                )),
                ("namespace", "delete") => terminal_override(
                    &decoded.words,
                    cursor.index,
                    WranglerOptionScope::Kv,
                    false,
                    cursor.terminal_flags,
                )
                .unwrap_or(WranglerSemanticDecision::Destructive(
                    "wrangler-kv-namespace-delete",
                )),
                ("bulk", "delete") => terminal_override(
                    &decoded.words,
                    cursor.index,
                    WranglerOptionScope::Kv,
                    false,
                    cursor.terminal_flags,
                )
                .unwrap_or(WranglerSemanticDecision::Destructive(
                    "wrangler-kv-bulk-delete",
                )),
                ("key", "get" | "list") | ("namespace", "list") => WranglerSemanticDecision::Safe,
                _ => WranglerSemanticDecision::NoMatch,
            }
        }
        _ => WranglerSemanticDecision::NoMatch,
    }
}

/// Analyze Wrangler syntax with bounded, caller-proven shell decoding.
///
/// This catches global options interleaved at any command depth and literal
/// POSIX quote/escape concatenation without reinterpreting dynamic expansion.
#[must_use]
pub(crate) fn wrangler_semantic_decision_in_dialect(
    command: &str,
    dialect: ShellDialect,
) -> WranglerSemanticDecision {
    if dialect == ShellDialect::Unknown {
        let decisions = [
            wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
            wrangler_semantic_decision_in_dialect(command, ShellDialect::PowerShell),
            wrangler_semantic_decision_in_dialect(command, ShellDialect::Cmd),
        ];
        if let Some(decision) = decisions
            .iter()
            .copied()
            .find(|decision| matches!(decision, WranglerSemanticDecision::Destructive(_)))
        {
            return decision;
        }
        if decisions.contains(&WranglerSemanticDecision::Unverified) {
            return WranglerSemanticDecision::Unverified;
        }
        return if decisions.contains(&WranglerSemanticDecision::Safe) {
            WranglerSemanticDecision::Safe
        } else {
            WranglerSemanticDecision::NoMatch
        };
    }

    if command.len() > MAX_WRANGLER_SEMANTIC_BYTES {
        return WranglerSemanticDecision::Unverified;
    }
    let segments = crate::packs::split_command_segments_in_dialect(command, dialect);
    if segments.len() > MAX_WRANGLER_SEMANTIC_SEGMENTS {
        return if segments.iter().all(|segment| {
            let stripped = matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown)
                .then(|| strip_wrapper_prefixes(segment));
            let segment = stripped
                .as_ref()
                .map_or(*segment, |result| result.normalized.as_ref());
            decode_words(segment, dialect)
                .is_some_and(|decoded| words_prove_irrelevant_executable(&decoded.words, dialect))
        }) {
            WranglerSemanticDecision::NoMatch
        } else {
            WranglerSemanticDecision::Unverified
        };
    }
    let mut saw_safe = false;
    let mut saw_unverified = false;
    for segment in segments {
        match wrangler_segment_semantic_decision(segment, dialect) {
            decision @ WranglerSemanticDecision::Destructive(_) => return decision,
            WranglerSemanticDecision::Safe => saw_safe = true,
            WranglerSemanticDecision::Unverified => saw_unverified = true,
            WranglerSemanticDecision::NoMatch => {}
        }
    }
    if saw_unverified {
        WranglerSemanticDecision::Unverified
    } else if saw_safe {
        WranglerSemanticDecision::Safe
    } else {
        WranglerSemanticDecision::NoMatch
    }
}

/// Analyze Wrangler syntax when the caller cannot prove the shell dialect.
/// Dialect-aware hook callers should use [`wrangler_semantic_decision_in_dialect`]
/// instead.
#[must_use]
pub(crate) fn wrangler_semantic_decision(command: &str) -> WranglerSemanticDecision {
    wrangler_semantic_decision_in_dialect(command, ShellDialect::Unknown)
}

/// Decode npm's executable `-c|--call` shell envelope for evaluator recursion.
///
/// Callers should pass one shell segment. `Payload` is an inner POSIX shell
/// program; `Unverified` must be denied under the semantic fail-closed rule.
#[must_use]
pub(crate) fn wrangler_runner_shell_decision_in_dialect(
    segment: &str,
    dialect: ShellDialect,
) -> WranglerRunnerShellDecision {
    if segment.len() > MAX_WRANGLER_SEMANTIC_BYTES {
        return WranglerRunnerShellDecision::Unverified;
    }
    if dialect != ShellDialect::Unknown {
        return runner_shell_payload_segment_decision(segment, dialect);
    }

    let decisions = [
        runner_shell_payload_segment_decision(segment, ShellDialect::Posix),
        runner_shell_payload_segment_decision(segment, ShellDialect::PowerShell),
        runner_shell_payload_segment_decision(segment, ShellDialect::Cmd),
    ];
    if decisions
        .iter()
        .any(|decision| decision == &WranglerRunnerShellDecision::Unverified)
    {
        return WranglerRunnerShellDecision::Unverified;
    }
    let mut payloads = decisions.iter().filter_map(|decision| match decision {
        WranglerRunnerShellDecision::Payload(payload) => Some(payload),
        WranglerRunnerShellDecision::NoMatch | WranglerRunnerShellDecision::Unverified => None,
    });
    let Some(first) = payloads.next() else {
        return WranglerRunnerShellDecision::NoMatch;
    };
    if payloads.all(|payload| payload == first)
        && decisions
            .iter()
            .all(|decision| matches!(decision, WranglerRunnerShellDecision::Payload(_)))
    {
        WranglerRunnerShellDecision::Payload(first.clone())
    } else {
        WranglerRunnerShellDecision::Unverified
    }
}

/// Bounded candidate override for commands whose shell-decoded executable can
/// be Wrangler even though the raw keyword matcher cannot see `wrangler`.
#[must_use]
pub(crate) fn cloudflare_workers_semantic_scan_required(
    command: &str,
    dialect: ShellDialect,
) -> bool {
    !matches!(
        wrangler_semantic_decision_in_dialect(command, dialect),
        WranglerSemanticDecision::NoMatch
    )
}

/// Create the Cloudflare Workers pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cdn.cloudflare_workers".to_string(),
        name: "Cloudflare Workers",
        description: "Protects against destructive Cloudflare Workers, KV, R2, and D1 operations \
                      via the Wrangler CLI.",
        keywords: &["wrangler"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Account/auth info
        safe_pattern!(
            "wrangler-whoami",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s|$)"
        ),
        // KV read operations
        safe_pattern!(
            "wrangler-kv-get",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv(?::|\s+)key\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-kv-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv(?::|\s+)key\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-kv-namespace-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv(?::|\s+)namespace\s+list(?=\s|$)"
        ),
        // R2 read operations
        safe_pattern!(
            "wrangler-r2-object-get",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+object\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-r2-bucket-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+bucket\s+list(?=\s|$)"
        ),
        // D1 read operations
        safe_pattern!(
            "wrangler-d1-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+d1\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-d1-info",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+d1\s+info(?=\s|$)"
        ),
        // Development/debugging
        safe_pattern!(
            "wrangler-dev",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+dev(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-tail",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+tail(?=\s|$)"
        ),
        // Version/help
        safe_pattern!(
            "wrangler-version",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-v|--version|version)(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-help",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-h|--help|help)(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Evaluated explicitly by the bounded Wrangler semantic pass. The
        // regex is intentionally unsatisfiable so ordinary text matching
        // cannot manufacture an unverified finding.
        DestructivePattern {
            regex: crate::packs::regex_engine::LazyCompiledRegex::new(r"(?!)"),
            reason: WRANGLER_UNVERIFIED_REASON,
            name: Some(WRANGLER_UNVERIFIED_RULE),
            severity: crate::packs::Severity::High,
            explanation: Some(
                "Review the fully expanded Wrangler executable and command path before allowing execution. Dynamic shell values and commands beyond the semantic parser's bounds can hide destructive Worker, KV, R2, D1, or deployment operations.",
            ),
            suggestions: &[],
            executables: None,
        },
        // Worker deletion
        destructive_pattern!(
            "wrangler-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "wrangler delete removes a Worker from Cloudflare.",
            Critical,
            "Deleting a Cloudflare Worker immediately stops all edge processing for that \
             Worker. Any routes pointing to it will return errors. Custom domains and \
             bindings (KV, R2, D1) associated with the Worker remain but become orphaned.\n\n\
             Safer alternatives:\n\
             - wrangler deployments list: Review deployment history first\n\
             - Disable routes instead of deleting the Worker\n\
             - Use wrangler tail to verify traffic before deletion"
        ),
        // Deployment rollback (can break things)
        destructive_pattern!(
            "wrangler-deployments-rollback",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+deployments\s+rollback\b",
            "wrangler deployments rollback reverts to a previous Worker version.",
            High,
            "Rolling back a deployment replaces your current Worker code with a previous \
             version. This can reintroduce bugs, break API compatibility, or cause issues \
             if the previous version relies on removed bindings or environment variables.\n\n\
             Safer alternatives:\n\
             - wrangler deployments list: Review available versions first\n\
             - Test the target version in a staging environment\n\
             - Deploy a fix forward instead of rolling back"
        ),
        // KV destructive operations
        destructive_pattern!(
            "wrangler-kv-key-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv(?::|\s+)key\s+delete\b",
            "wrangler kv key delete removes a key from KV storage.",
            Medium,
            "Deleting a KV key immediately removes the data at all edge locations. \
             Applications reading this key will receive null or errors. KV deletions \
             propagate globally within seconds.\n\n\
             Safer alternatives:\n\
             - wrangler kv:key get: Retrieve and backup the value first\n\
             - Set an expiration instead of deleting for temporary data\n\
             - Use KV namespaces for environment separation"
        ),
        destructive_pattern!(
            "wrangler-kv-namespace-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv(?::|\s+)namespace\s+delete\b",
            "wrangler kv namespace delete removes an entire KV namespace.",
            Critical,
            "Deleting a KV namespace permanently removes ALL keys and values within it. \
             Any Workers bound to this namespace will fail when accessing KV. This cannot \
             be undone and all data is lost.\n\n\
             Safer alternatives:\n\
             - wrangler kv:key list: Inventory all keys first\n\
             - Export data before deletion\n\
             - Remove Worker bindings before deleting the namespace"
        ),
        destructive_pattern!(
            "wrangler-kv-bulk-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv(?::|\s+)bulk\s+delete\b",
            "wrangler kv bulk delete removes multiple keys from KV storage.",
            High,
            "Bulk delete removes many KV keys at once based on a JSON file. This is \
             efficient but dangerous - a malformed keys file can delete unintended data. \
             All deletions are immediate and irreversible.\n\n\
             Safer alternatives:\n\
             - Review the keys JSON file carefully before execution\n\
             - Test with a single wrangler kv:key delete first\n\
             - Back up affected keys before bulk deletion"
        ),
        // R2 destructive operations
        destructive_pattern!(
            "wrangler-r2-object-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+object\s+delete\b",
            "wrangler r2 object delete removes an object from R2 storage.",
            Medium,
            "Deleting an R2 object permanently removes the file from storage. Any URLs \
             or Workers accessing this object will receive 404 errors. Unlike S3, R2 does \
             not charge for delete operations but data is unrecoverable.\n\n\
             Safer alternatives:\n\
             - wrangler r2 object get: Download the object first\n\
             - Use object lifecycle rules for automatic expiration\n\
             - Move to a separate 'archive' bucket instead of deleting"
        ),
        destructive_pattern!(
            "wrangler-r2-bucket-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+bucket\s+delete\b",
            "wrangler r2 bucket delete removes an entire R2 bucket.",
            Critical,
            "Deleting an R2 bucket removes the bucket and ALL objects within it. Workers \
             bound to this bucket will fail. The bucket name becomes available for reuse \
             by any Cloudflare account.\n\n\
             Safer alternatives:\n\
             - wrangler r2 bucket list: Verify the bucket contents\n\
             - Empty the bucket and verify it's truly unused\n\
             - Remove Worker bindings before bucket deletion"
        ),
        // D1 destructive operations
        destructive_pattern!(
            "wrangler-d1-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+d1\s+delete\b",
            "wrangler d1 delete removes a D1 database.",
            Critical,
            "Deleting a D1 database permanently removes all tables, data, and schema. \
             Workers bound to this database will fail with binding errors. D1 databases \
             cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - wrangler d1 export: Export the database first\n\
             - wrangler d1 info: Review database details\n\
             - Remove Worker bindings before deletion"
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
        assert_eq!(pack.id, "cdn.cloudflare_workers");
        assert_eq!(pack.name, "Cloudflare Workers");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"wrangler"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Account info
        assert_safe_pattern_matches(&pack, "wrangler whoami");
        // KV read
        assert_safe_pattern_matches(&pack, "wrangler kv:key get --namespace-id=abc KEY");
        assert_safe_pattern_matches(&pack, "wrangler kv:key list --namespace-id=abc");
        assert_safe_pattern_matches(&pack, "wrangler kv:namespace list");
        assert_safe_pattern_matches(&pack, "wrangler kv key get --namespace-id=abc KEY");
        assert_safe_pattern_matches(&pack, "npx wrangler kv key list --namespace-id=abc");
        assert_safe_pattern_matches(&pack, "pnpm wrangler kv namespace list");
        // R2 read
        assert_safe_pattern_matches(&pack, "wrangler r2 object get my-bucket/path/to/obj");
        assert_safe_pattern_matches(&pack, "wrangler r2 bucket list");
        // D1 read
        assert_safe_pattern_matches(&pack, "wrangler d1 list");
        assert_safe_pattern_matches(&pack, "wrangler d1 info my-db");
        // Dev/debug
        assert_safe_pattern_matches(&pack, "wrangler dev");
        assert_safe_pattern_matches(&pack, "wrangler tail");
        // Version/help
        assert_safe_pattern_matches(&pack, "wrangler --version");
        assert_safe_pattern_matches(&pack, "wrangler -v");
        assert_safe_pattern_matches(&pack, "wrangler help");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Worker deletion
        assert_blocks_with_pattern(&pack, "wrangler delete", "wrangler-delete");
        assert_blocks_with_pattern(&pack, "wrangler delete my-worker", "wrangler-delete");
        // Deployments
        assert_blocks_with_pattern(
            &pack,
            "wrangler deployments rollback",
            "wrangler-deployments-rollback",
        );
        // KV
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:key delete --namespace-id=abc KEY",
            "wrangler-kv-key-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:namespace delete --namespace-id=abc",
            "wrangler-kv-namespace-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:bulk delete --namespace-id=abc keys.json",
            "wrangler-kv-bulk-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv key delete --namespace-id=abc KEY",
            "wrangler-kv-key-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "npx wrangler kv namespace delete --binding=CACHE",
            "wrangler-kv-namespace-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "pnpm wrangler kv bulk delete --namespace-id=abc keys.json",
            "wrangler-kv-bulk-delete",
        );
        // R2
        assert_blocks_with_pattern(
            &pack,
            "wrangler r2 object delete bucket/key",
            "wrangler-r2-object-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler r2 bucket delete my-bucket",
            "wrangler-r2-bucket-delete",
        );
        // D1
        assert_blocks_with_pattern(&pack, "wrangler d1 delete my-db", "wrangler-d1-delete");
    }

    #[test]
    fn global_flags_do_not_bypass() {
        let pack = create_pack();
        // wrangler accepts --config, --cwd, --env, --verbose global flags.
        assert_blocks_with_pattern(
            &pack,
            "wrangler --config wrangler.toml delete my-worker",
            "wrangler-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler --env prod d1 delete my-db",
            "wrangler-d1-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler --cwd ./project r2 bucket delete my-bucket",
            "wrangler-r2-bucket-delete",
        );
        assert!(
            pack.check("wrangler --env prod whoami").is_none(),
            "safe read with env flag should remain safe"
        );
    }

    #[test]
    fn semantic_view_blocks_interleaved_globals_and_posix_concatenation() {
        let destructive = [
            (
                "wran''gler k''v --env prod name''space --config wrangler.toml del''ete cache",
                "wrangler-kv-namespace-delete",
            ),
            (
                "npx --yes wran''gler kv --cwd ./project key --profile production delete KEY",
                "wrangler-kv-key-delete",
            ),
            (
                "pnpm wrangler kv bulk --env-file .env --env-file .env.local delete keys.json",
                "wrangler-kv-bulk-delete",
            ),
            (
                "wrangler kv:key --env prod delete KEY",
                "wrangler-kv-key-delete",
            ),
            (
                "sudo env DCG_TEST=1 command wrangler r''2 --cwd . bucket del''ete assets",
                "wrangler-r2-bucket-delete",
            ),
            (
                "wrangler d''1 --config=wrangler.toml del''ete database",
                "wrangler-d1-delete",
            ),
            (
                "wrangler deployments --profile production roll''back",
                "wrangler-deployments-rollback",
            ),
            ("wrangler --env prod del''ete worker", "wrangler-delete"),
            (
                "wrangler whoami && wrangler kv namespace --env prod delete cache",
                "wrangler-kv-namespace-delete",
            ),
        ];
        for (command, rule) in destructive {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::Destructive(rule),
                "{command}"
            );
        }
    }

    #[test]
    fn semantic_view_preserves_reads_and_does_not_reinterpret_data() {
        for command in [
            "wrangler kv --env delete namespace list",
            "wrangler kv key --config delete get KEY",
            "wrangler k''v name''space --cwd . li''st",
            "npx --yes wrangler kv key --env prod list",
            "pnpm wrangler r2 object --profile production get bucket/key",
            "wrangler d1 --env prod info database",
            "wrangler --help",
            "wrangler kv --version namespace delete cache",
        ] {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::Safe,
                "{command}"
            );
        }

        for command in [
            "echo wrangler kv namespace delete cache",
            "echo 'wrangler kv namespace delete cache'",
            "wrangler kvnamespace delete cache",
            "wrangler kv::namespace delete cache",
            "npx echo wrangler kv namespace delete cache",
            "wrangler kv --not-a-global namespace delete cache",
        ] {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::NoMatch,
                "{command}"
            );
        }
    }

    #[test]
    fn semantic_view_decodes_windows_dialects_and_launch_wrappers() {
        for (command, dialect, rule) in [
            (
                r"@call WRANGLER.ExE k^v namespace del^ete cache",
                ShellDialect::Cmd,
                "wrangler-kv-namespace-delete",
            ),
            (
                r#"call "C:\Tools\Wrangler.eXe" r2 bucket del^ete assets"#,
                ShellDialect::Cmd,
                "wrangler-r2-bucket-delete",
            ),
            (
                r"@WRANGLER.EXE d1 del^ete database",
                ShellDialect::Cmd,
                "wrangler-d1-delete",
            ),
            (
                r"& 'C:\Tools\Wrangler.ExE' k`v namespace del`ete cache",
                ShellDialect::PowerShell,
                "wrangler-kv-namespace-delete",
            ),
            (
                r"WRANGLER.EXE k^v namespace del^ete cache",
                ShellDialect::Unknown,
                "wrangler-kv-namespace-delete",
            ),
            (
                r"WRANGLER.EXE k`v namespace del`ete cache",
                ShellDialect::Unknown,
                "wrangler-kv-namespace-delete",
            ),
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, dialect),
                WranglerSemanticDecision::Destructive(rule),
                "{dialect:?}: {command}"
            );
        }
    }

    #[test]
    fn semantic_view_understands_leaf_options_runners_and_assignments() {
        let destructive = [
            (
                "DCG_TEST=1 wrangler --install-skills=false kv --namespace-id abc key --binding CACHE --preview delete KEY",
                "wrangler-kv-key-delete",
            ),
            (
                "wrangler --no-install-skills kv bulk --local --persist-to .wrangler/state delete keys.json",
                "wrangler-kv-bulk-delete",
            ),
            (
                "wrangler kv namespace --binding CACHE delete namespace",
                "wrangler-kv-namespace-delete",
            ),
            (
                "wrangler r2 -J eu bucket --jurisdiction=eu delete assets",
                "wrangler-r2-bucket-delete",
            ),
            (
                "wrangler r2 object --jurisdiction fedramp delete assets/key",
                "wrangler-r2-object-delete",
            ),
            (
                "bun x wrangler kv namespace delete cache",
                "wrangler-kv-namespace-delete",
            ),
            ("bunx --bun wran''gler delete worker", "wrangler-delete"),
            (
                "bunx --verbose wran''gler r2 bucket delete assets",
                "wrangler-r2-bucket-delete",
            ),
            ("bun x --bun wran''gler delete worker", "wrangler-delete"),
            ("bun --bun x wran''gler delete worker", "wrangler-delete"),
            (
                "pnpm exec wrangler r2 bucket delete assets",
                "wrangler-r2-bucket-delete",
            ),
            (
                "pnpm --dir . exec wran''gler r2 bucket delete assets",
                "wrangler-r2-bucket-delete",
            ),
            (
                "npx wrangler@latest kv namespace delete cache",
                "wrangler-kv-namespace-delete",
            ),
            (
                "bunx wrangler@4.111.0 r2 bucket delete assets",
                "wrangler-r2-bucket-delete",
            ),
            (
                "pnpm dlx wrangler@4 d1 delete database",
                "wrangler-d1-delete",
            ),
            ("yarn dlx wrangler@latest delete worker", "wrangler-delete"),
            (
                "yarn --cwd . exec wran''gler delete worker",
                "wrangler-delete",
            ),
        ];
        for (command, rule) in destructive {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::Destructive(rule),
                "{command}"
            );
        }
    }

    #[test]
    fn semantic_view_exposes_npm_runner_call_payloads_for_shell_recursion() {
        for (command, expected) in [
            (
                r#"npx -c "wran''gler kv namespace delete cache""#,
                "wran''gler kv namespace delete cache",
            ),
            (
                r#"npm exec --package wrangler --call="wrangler r2 bucket delete assets""#,
                "wrangler r2 bucket delete assets",
            ),
            (
                r#"npx -c "printf first" --call="wrangler delete worker""#,
                "wrangler delete worker",
            ),
            (
                r#"npm --silent exec --call="wrangler d1 delete database""#,
                "wrangler d1 delete database",
            ),
            (
                r#"npm --prefix . -c "wrangler delete worker" exec"#,
                "wrangler delete worker",
            ),
        ] {
            assert_eq!(
                wrangler_runner_shell_decision_in_dialect(command, ShellDialect::Posix),
                WranglerRunnerShellDecision::Payload(expected.to_string()),
                "{command}"
            );
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
                WranglerSemanticDecision::Unverified,
                "the direct pack API must fail closed until the evaluator recurses: {command}"
            );
        }

        for command in [
            "npx -c",
            r#"npx -c "$PAYLOAD""#,
            r#"npm exec --call="$PAYLOAD""#,
            r#"npx $OPTIONS -c "wrangler delete worker""#,
        ] {
            assert_eq!(
                wrangler_runner_shell_decision_in_dialect(command, ShellDialect::Posix),
                WranglerRunnerShellDecision::Unverified,
                "{command}"
            );
        }

        assert_eq!(
            wrangler_runner_shell_decision_in_dialect(
                "npx wrangler -c wrangler.toml delete worker",
                ShellDialect::Posix,
            ),
            WranglerRunnerShellDecision::NoMatch,
            "Wrangler's post-package -c is a config option, not npx shell source"
        );
        assert_eq!(
            wrangler_semantic_decision("npx wrangler -c wrangler.toml delete worker"),
            WranglerSemanticDecision::Destructive("wrangler-delete")
        );
        assert_eq!(
            wrangler_semantic_decision_in_dialect(
                "npm --silent exec wrangler kv namespace delete cache",
                ShellDialect::Posix,
            ),
            WranglerSemanticDecision::Destructive("wrangler-kv-namespace-delete")
        );
        assert_eq!(
            wrangler_semantic_decision_in_dialect(
                r"npx.cmd wrangler kv namespace delete cache",
                ShellDialect::Cmd,
            ),
            WranglerSemanticDecision::Destructive("wrangler-kv-namespace-delete")
        );
    }

    #[test]
    fn semantic_view_recognizes_direct_wrangler_javascript_entrypoints() {
        for (command, rule) in [
            (
                "node /opt/node_modules/wran''gler/bin/wran''gler.js kv namespace delete cache",
                "wrangler-kv-namespace-delete",
            ),
            (
                "bun ./node_modules/wrangler/bin/wrangler.mjs r2 bucket delete assets",
                "wrangler-r2-bucket-delete",
            ),
            (
                "bun run ./node_modules/wrangler/bin/wrangler.cjs d1 delete database",
                "wrangler-d1-delete",
            ),
            (
                "deno run ./vendor/wrangler.js deployments rollback",
                "wrangler-deployments-rollback",
            ),
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
                WranglerSemanticDecision::Destructive(rule),
                "{command}"
            );
        }

        for command in [
            "node ./node_modules/wrangler/bin/wrangler.js --version",
            "bun ./node_modules/wrangler/bin/wrangler.mjs whoami",
            "deno run ./vendor/wrangler.cjs kv namespace list",
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
                WranglerSemanticDecision::Safe,
                "{command}"
            );
        }

        for command in [
            r#"node "$SCRIPT" kv namespace delete cache"#,
            r#"bun "$SCRIPT" r2 bucket delete assets"#,
            r#"deno run "$SCRIPT" d1 delete database"#,
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
                WranglerSemanticDecision::Unverified,
                "a dynamic script path can resolve to Wrangler: {command}"
            );
        }

        for command in [
            r#"node "$SCRIPT" --version"#,
            r#"node -e "console.log('wrangler.js delete')""#,
            "node ./helper.js wrangler.js delete worker",
            "bun test ./wrangler.js delete worker",
            "deno check ./wrangler.js delete worker",
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
                WranglerSemanticDecision::NoMatch,
                "nonexecuted script-looking data must stay inert: {command}"
            );
        }
    }

    #[test]
    fn semantic_candidate_override_sees_shell_decoded_wrangler_forms() {
        for command in [
            "PART=gler; wran${PART} kv namespace delete cache",
            r#"npx -c "wran''gler kv namespace delete cache""#,
            "node /opt/node_modules/wran''gler/bin/wran''gler.js delete worker",
        ] {
            assert!(
                cloudflare_workers_semantic_scan_required(command, ShellDialect::Posix),
                "{command}"
            );
        }
        assert!(!cloudflare_workers_semantic_scan_required(
            "node ./helper.js --version",
            ShellDialect::Posix,
        ));
    }

    #[test]
    fn semantic_scan_needs_wrangler_evidence_past_wrapper_words_issue_283() {
        // #283: a generic wrapper word (or the `[` test builtin) whose suffix
        // carries no Wrangler evidence must not force the pack in and deny as
        // Unverified.
        for dialect in [
            ShellDialect::Posix,
            ShellDialect::Unknown,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
        ] {
            for command in ["command -v foo", "env", "[ -f x ] && echo yes", "time foo"] {
                assert_eq!(
                    wrangler_semantic_decision_in_dialect(command, dialect),
                    WranglerSemanticDecision::NoMatch,
                    "{dialect:?}: {command}"
                );
                assert!(
                    !cloudflare_workers_semantic_scan_required(command, dialect),
                    "{dialect:?}: {command}"
                );
            }
        }

        // Wrapper suffixes with positive Wrangler evidence keep failing closed
        // or resolve to the genuine destructive rule.
        assert_eq!(
            wrangler_semantic_decision_in_dialect(
                "sudo wrangler kv key delete --binding=FOO key",
                ShellDialect::Posix,
            ),
            WranglerSemanticDecision::Destructive("wrangler-kv-key-delete"),
        );
        for command in [
            // Cmd never peels POSIX wrappers, so the wrapper word survives to
            // the resolver seam with a literal Wrangler suffix behind it.
            "time wrangler delete worker",
            "command wrangler r2 bucket delete assets",
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Cmd),
                WranglerSemanticDecision::Unverified,
                "{command}"
            );
        }
    }

    #[test]
    fn wrapper_seam_evidence_accepts_windows_wrangler_program_suffixes_issue_283() {
        // The #283 evidence gate must strip Windows program suffixes exactly
        // like the main resolver's `executable_basename`. Under PowerShell and
        // Cmd no POSIX wrapper is ever peeled, so `wrangler.exe`/`wrangler.cmd`
        // reaches the seam as the wrapper's suffix and must still fail closed.
        for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
            for command in [
                "time wrangler.exe d1 delete mydb",
                "sudo wrangler.exe r2 bucket delete assets",
                "env FOO=1 wrangler.cmd r2 bucket delete assets",
                "command node_modules/.bin/wrangler.cmd r2 bucket delete assets",
            ] {
                assert_eq!(
                    wrangler_semantic_decision_in_dialect(command, dialect),
                    WranglerSemanticDecision::Unverified,
                    "{dialect:?}: {command}"
                );
                assert!(
                    cloudflare_workers_semantic_scan_required(command, dialect),
                    "{dialect:?}: {command}"
                );
            }
            // Wrapper suffixes that are still provably unrelated stay out.
            for command in ["command -v foo", "time foo.exe", "env"] {
                assert_eq!(
                    wrangler_semantic_decision_in_dialect(command, dialect),
                    WranglerSemanticDecision::NoMatch,
                    "{dialect:?}: {command}"
                );
            }
        }
    }

    #[test]
    fn unbounded_dynamic_executables_carry_no_wrangler_evidence_issue_281() {
        // #281/#273: an executable word that is a pure expansion with zero
        // literal bytes may become anything, so it is evidence for nothing.
        // Every dialect must agree, quoted and unquoted alike.
        for dialect in [
            ShellDialect::Posix,
            ShellDialect::Unknown,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
        ] {
            for command in [
                "$cmd $arg",
                "$X $Y",
                r#""$X" "$Y""#,
                r#""$BIN" run "$ARG""#,
                "$SCRIPT --version",
            ] {
                assert_eq!(
                    wrangler_semantic_decision_in_dialect(command, dialect),
                    WranglerSemanticDecision::NoMatch,
                    "{dialect:?}: {command}"
                );
                assert_eq!(
                    wrangler_runner_shell_decision_in_dialect(command, dialect),
                    WranglerRunnerShellDecision::NoMatch,
                    "{dialect:?}: {command}"
                );
            }
        }

        // Evidence elsewhere in the segment still reaches the fail-closed rule:
        // a literal Wrangler token, a destructive Wrangler argv the expansion
        // would complete, a partially literal executable, or a runner shell
        // payload option.
        for command in [
            "$X wrangler r2 bucket delete assets",
            "$W r2 bucket delete x",
            "$W r2 bucket delete $NAME",
            "wran$X kv namespace delete cache",
            r#"$X -c "wrangler delete worker""#,
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, ShellDialect::Posix),
                WranglerSemanticDecision::Unverified,
                "{command}"
            );
        }
    }

    #[test]
    fn command_builtin_lookup_form_is_a_query_not_an_invocation_issue_283() {
        // `command -v NAME` resolves a name and executes nothing, so a literal
        // `wrangler` behind it is not a Wrangler invocation under any dialect.
        for dialect in [
            ShellDialect::Posix,
            ShellDialect::Unknown,
            ShellDialect::PowerShell,
            ShellDialect::Cmd,
        ] {
            for command in [
                "command -v wrangler",
                "command -V wrangler",
                "command -p -v wrangler",
                "command -pv wrangler.exe",
            ] {
                assert_eq!(
                    wrangler_semantic_decision_in_dialect(command, dialect),
                    WranglerSemanticDecision::NoMatch,
                    "{dialect:?}: {command}"
                );
            }
        }

        // Without `-v`, `command` really runs its suffix.
        for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(
                    "command wrangler r2 bucket delete assets",
                    dialect,
                ),
                WranglerSemanticDecision::Unverified,
                "{dialect:?}"
            );
        }
        assert_eq!(
            wrangler_semantic_decision_in_dialect(
                "command wrangler r2 bucket delete assets",
                ShellDialect::Posix,
            ),
            WranglerSemanticDecision::Destructive("wrangler-r2-bucket-delete"),
        );
    }

    #[test]
    fn semantic_view_honors_terminal_info_dry_run_and_data_roles() {
        for command in [
            "wrangler delete worker --help",
            "wrangler kv namespace delete cache --version",
            "wrangler r2 object delete assets/key -h",
            "wrangler delete worker --dry-run",
            "wrangler delete --dry-run=true worker",
        ] {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::Safe,
                "{command}"
            );
        }

        for (command, rule) in [
            ("wrangler delete worker --dry-run=false", "wrangler-delete"),
            (
                "wrangler --config \"$CONFIG\" kv namespace delete cache",
                "wrangler-kv-namespace-delete",
            ),
            (
                "wrangler kv --binding \"$BINDING\" namespace delete cache",
                "wrangler-kv-namespace-delete",
            ),
            (
                "wrangler delete worker --dry-run --dry-run=false",
                "wrangler-delete",
            ),
            (
                "wrangler delete worker --dry-run --no-dry-run",
                "wrangler-delete",
            ),
            (
                "wrangler delete worker --help --help=false",
                "wrangler-delete",
            ),
            (
                "wrangler delete worker --version --version=false",
                "wrangler-delete",
            ),
        ] {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::Destructive(rule),
                "{command}"
            );
        }

        for command in [
            "wrangler -- '$SUBCOMMAND'",
            "wrangler -- delete",
            "echo \"wrangler k${PART} namespace delete cache\"",
        ] {
            assert_eq!(
                wrangler_semantic_decision(command),
                WranglerSemanticDecision::NoMatch,
                "post-terminator or non-executable data must stay inert: {command}"
            );
        }
    }

    #[test]
    fn semantic_view_fails_closed_on_dynamic_or_bounded_wrangler_syntax() {
        for (command, dialect) in [
            ("wrang$X kv namespace delete cache", ShellDialect::Posix),
            (
                "wrangler k${REST} namespace delete cache",
                ShellDialect::Posix,
            ),
            ("wrangler kv $RESOURCE delete cache", ShellDialect::Posix),
            (r"%WRANGLER% kv namespace delete cache", ShellDialect::Cmd),
            (
                r"wrangler k%REST% namespace delete cache",
                ShellDialect::Cmd,
            ),
            (
                r"& $wrangler kv namespace delete cache",
                ShellDialect::PowerShell,
            ),
            (
                r"wrangler $subcommand delete cache",
                ShellDialect::PowerShell,
            ),
            (r"npx $FLAGS wrangler delete worker", ShellDialect::Posix),
            (
                r"npm exec $FLAGS -- wrangler delete worker",
                ShellDialect::Posix,
            ),
            (r"npx wrangler@$VERSION delete worker", ShellDialect::Posix),
            (r"npx wrangler@npm:other delete worker", ShellDialect::Posix),
            (r"npx @scope/wrangler delete worker", ShellDialect::Posix),
        ] {
            assert_eq!(
                wrangler_semantic_decision_in_dialect(command, dialect),
                WranglerSemanticDecision::Unverified,
                "{dialect:?}: {command}"
            );
        }

        let oversized = format!(
            "wrangler whoami {}",
            "x".repeat(MAX_WRANGLER_SEMANTIC_BYTES)
        );
        assert_eq!(
            wrangler_semantic_decision(&oversized),
            WranglerSemanticDecision::Unverified
        );

        let oversized_assignment = format!(
            "PAYLOAD={} wran''gler delete worker",
            "x".repeat(MAX_WRANGLER_SEMANTIC_BYTES)
        );
        assert_eq!(
            wrangler_semantic_decision(&oversized_assignment),
            WranglerSemanticDecision::Unverified
        );

        let too_many_tokens = format!(
            "wrangler whoami {}",
            std::iter::repeat_n("argument", MAX_WRANGLER_SEMANTIC_TOKENS)
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(
            wrangler_semantic_decision(&too_many_tokens),
            WranglerSemanticDecision::Unverified
        );

        let assignment_prefix = format!(
            "{} wran''gler delete worker",
            (0..MAX_WRANGLER_SEMANTIC_TOKENS)
                .map(|index| format!("DCG_PREFIX_{index}=x"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(
            wrangler_semantic_decision(&assignment_prefix),
            WranglerSemanticDecision::Unverified
        );

        let wrapper_prefix = format!(
            "{} wran''gler delete worker",
            std::iter::repeat_n("env", MAX_WRANGLER_SEMANTIC_TOKENS)
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(
            wrangler_semantic_decision(&wrapper_prefix),
            WranglerSemanticDecision::Unverified
        );

        let too_many_segments =
            std::iter::repeat_n("wrangler whoami", MAX_WRANGLER_SEMANTIC_SEGMENTS + 1)
                .collect::<Vec<_>>()
                .join(" && ");
        assert_eq!(
            wrangler_semantic_decision(&too_many_segments),
            WranglerSemanticDecision::Unverified
        );
    }

    #[test]
    fn cloudflare_workers_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "wrangler delete my-worker", "wrangler-delete");
        assert_blocks_with_pattern(
            &pack,
            "wrangler deployments rollback",
            "wrangler-deployments-rollback",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:key delete --namespace-id=abc KEY",
            "wrangler-kv-key-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:namespace delete --namespace-id=abc",
            "wrangler-kv-namespace-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:bulk delete --namespace-id=abc keys.json",
            "wrangler-kv-bulk-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv key delete --namespace-id=abc KEY",
            "wrangler-kv-key-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv namespace delete --namespace-id=abc",
            "wrangler-kv-namespace-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv bulk delete --namespace-id=abc keys.json",
            "wrangler-kv-bulk-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler r2 object delete bucket/key",
            "wrangler-r2-object-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler r2 bucket delete my-bucket",
            "wrangler-r2-bucket-delete",
        );
        assert_blocks_with_pattern(&pack, "wrangler d1 delete my-db", "wrangler-d1-delete");
    }

    #[test]
    fn cloudflare_workers_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "wrangler delete my-worker", Severity::Critical);
        assert_blocks_with_severity(&pack, "wrangler deployments rollback", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "wrangler kv:key delete --namespace-id=abc KEY",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler kv:namespace delete --namespace-id=abc",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler kv:bulk delete --namespace-id=abc keys.json",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler r2 object delete bucket/key",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler r2 bucket delete my-bucket",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "wrangler d1 delete my-db", Severity::Critical);
    }

    #[test]
    fn cloudflare_workers_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "wrangler whoami");
        assert_safe_pattern_matches(&pack, "wrangler kv:key get --namespace-id=abc KEY");
        assert_safe_pattern_matches(&pack, "wrangler kv:key list --namespace-id=abc");
        assert_safe_pattern_matches(&pack, "wrangler kv:namespace list");
        assert_safe_pattern_matches(&pack, "wrangler kv key get --namespace-id=abc KEY");
        assert_safe_pattern_matches(&pack, "wrangler kv key list --namespace-id=abc");
        assert_safe_pattern_matches(&pack, "wrangler kv namespace list");
        assert_safe_pattern_matches(&pack, "wrangler r2 object get my-bucket/path/to/obj");
        assert_safe_pattern_matches(&pack, "wrangler r2 bucket list");
        assert_safe_pattern_matches(&pack, "wrangler d1 list");
        assert_safe_pattern_matches(&pack, "wrangler d1 info my-db");
        assert_safe_pattern_matches(&pack, "wrangler dev");
        assert_safe_pattern_matches(&pack, "wrangler tail");
        assert_safe_pattern_matches(&pack, "wrangler --version");
        assert_safe_pattern_matches(&pack, "wrangler help");
    }

    #[test]
    fn cloudflare_workers_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "wrangler kvnamespace delete cache");
        assert_no_match(&pack, "wrangler kv::namespace delete cache");
    }
}

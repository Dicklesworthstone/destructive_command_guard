//! Rebase recovery mode — narrowly relax `git checkout --` / `git restore` blocks
//! when the user is actively recovering from a failed `git pull --rebase` flow.
//!
//! ## Problem
//!
//! When `git pull --rebase` fails partway (unstaged changes, stash-pop
//! conflict, interrupted rebase), the standard recovery path is often
//! `git checkout -- .` or `git restore <paths>`. Both are normally blocked
//! by dcg (rules `core.git:checkout-discard` and `core.git:restore-worktree`),
//! which leaves AI agents stuck and forced to ask the user to run the
//! command by hand. See issue #104.
//!
//! ## Solution
//!
//! Two complementary signals unlock the recovery path, both narrow and
//! bounded so the default safety guarantee is preserved outside of a
//! genuine recovery window:
//!
//! 1. **Active rebase state (automatic, zero-config).** If `.git/rebase-merge/`
//!    or `.git/rebase-apply/` exists, a rebase is in progress. In this state
//!    the discard operations are the documented recovery path, not a
//!    dangerous mistake — so dcg allows them with an informational note
//!    to stderr instead of a hard block.
//!
//! 2. **Explicit permit cookie (opt-in, short-lived).** The agent (or user)
//!    runs `dcg rebase-recover`, which writes a timestamp file into
//!    `.dcg/rebase-recovery-permit`. For the next 120 seconds (or until the
//!    next matching operation is allowed through — whichever comes first),
//!    `git checkout --` and `git restore` are allowed. This covers the
//!    common post-rebase case where the rebase itself already succeeded
//!    but a `git stash pop` left the worktree messy.
//!
//! ## Safety
//!
//! - The permit is scoped to the current repository's `.dcg/` directory.
//! - The permit is single-use (consumed on first successful allow).
//! - The permit expires after a short TTL (default 120s).
//! - Outside of both signals, the block path is unchanged. The safety
//!   guarantee for `core.git:checkout-discard` / `core.git:restore-worktree`
//!   still holds for every command that is not part of a rebase recovery.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default permit TTL in seconds.
pub const DEFAULT_PERMIT_TTL_SECS: u64 = 120;

/// Hard upper bound on permit TTL (prevents accidentally-long permits).
pub const MAX_PERMIT_TTL_SECS: u64 = 600;

/// Pattern names (within `core.git`) that participate in rebase recovery.
///
/// Any of these pattern IDs may be unblocked when a recovery signal is
/// active. Everything else stays on the normal block path.
pub const RECOVERY_PATTERNS: &[&str] = &[
    "checkout-discard",
    "checkout-ref-discard",
    "restore-worktree",
    "restore-worktree-explicit",
];

/// Reason code describing why a recovery allow was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    /// An interactive rebase (`rebase-merge/`) or non-interactive rebase
    /// (`rebase-apply/`) was in progress at the time of the check.
    RebaseInProgress,
    /// A time-bounded permit issued by `dcg rebase-recover` was valid.
    /// The inner `u64` is the number of seconds remaining.
    ActivePermit(u64),
}

impl RecoveryReason {
    /// Short human-readable label for stderr logging.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::RebaseInProgress => "rebase in progress".to_string(),
            Self::ActivePermit(secs) => format!("active rebase-recovery permit ({secs}s left)"),
        }
    }
}

/// Whether `pack_id:pattern_name` is one of the rules rebase recovery may
/// unlock. Only `core.git` patterns participate.
#[must_use]
pub fn is_recovery_rule(pack_id: Option<&str>, pattern_name: Option<&str>) -> bool {
    pack_id == Some("core.git")
        && pattern_name.is_some_and(|name| RECOVERY_PATTERNS.contains(&name))
}

/// Check whether a recovery unblock should fire for this pack/pattern in this cwd.
///
/// Returns `Some(RecoveryReason)` if the given `pack_id`/`pattern_name` is
/// one of the recovery-eligible rules AND a recovery signal is active in
/// `cwd`. Otherwise returns `None` and the caller should keep blocking.
#[must_use]
pub fn should_allow_recovery(
    cwd: &Path,
    pack_id: Option<&str>,
    pattern_name: Option<&str>,
) -> Option<RecoveryReason> {
    if !is_recovery_rule(pack_id, pattern_name) {
        return None;
    }

    // 1. In-progress rebase — automatic unblock.
    if is_rebase_in_progress(cwd) {
        return Some(RecoveryReason::RebaseInProgress);
    }

    // 2. Explicit permit cookie — short-lived unblock.
    if let Some(remaining) = permit_seconds_remaining(cwd) {
        return Some(RecoveryReason::ActivePermit(remaining));
    }

    None
}

/// Resolve the directory a guarded `git` command will actually run in, so the
/// rebase-state probe and the permit lookup target the right repository
/// (issue #331).
///
/// The hook evaluates the command *before* it runs, from a process whose cwd is
/// the harness's current directory. Agents routinely phrase recovery as one
/// line — `cd <worktree> && git restore --ours -- f` — so the repository that
/// matters is the one the command's own `cd` reaches, not the hook's cwd.
/// Probing the hook cwd instead denied the documented recovery path exactly
/// when it was being followed, and left a freshly minted permit unconsumed.
///
/// Resolution walks the top-level segments that precede `match_start` (the
/// byte offset of the matched rule text inside `command`) and applies every
/// `cd` / `pushd` whose target is a static literal, then a `git -C <literal>`
/// on the matched segment. It deliberately gives up — returning `None`, which
/// keeps the original deny — whenever the target cannot be known without
/// running the shell: expansions (`$DIR`, `$(...)`, backticks), globs,
/// `~user`, `cd -`, `popd`, any subshell or group (`(`, `{`) anywhere on the
/// line, unbalanced quotes, or a directory that does not exist. A directory
/// change or `git -C` *after* the matched segment also resolves to `None`:
/// the whole line runs once it is allowed, and a second guarded call could
/// otherwise land in a repository this resolution never probed. When the
/// match offset is unknown the matched segment is taken to be the single
/// top-level `git` segment; with two or more, or none, a command containing a
/// directory change resolves to `None`, so a change dcg cannot attribute can
/// never unlock recovery against the wrong repository.
///
/// This answers *where* the probe runs. Whether the rest of the line is
/// safe is a separate question — see [`relaxed_allowlist`].
///
/// Only POSIX-style shells are modelled; PowerShell and cmd resolve to `base`
/// unchanged (today's behavior). A command with no directory change at all
/// also resolves to `base` unchanged, so existing callers see identical paths.
#[must_use]
pub fn resolve_recovery_cwd(
    base: &Path,
    command: &str,
    match_start: Option<usize>,
    dialect: crate::normalize::ShellDialect,
) -> Option<PathBuf> {
    resolve_recovery_cwd_with_home(
        base,
        command,
        match_start,
        dialect,
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    )
}

/// [`resolve_recovery_cwd`] with an explicit `HOME` (tests must not mutate the
/// process environment).
fn resolve_recovery_cwd_with_home(
    base: &Path,
    command: &str,
    match_start: Option<usize>,
    dialect: crate::normalize::ShellDialect,
    home: Option<&Path>,
) -> Option<PathBuf> {
    use crate::normalize::ShellDialect;

    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        return Some(base.to_path_buf());
    }

    let segments = top_level_segment_ranges(command)?;
    if segments.is_empty() {
        return Some(base.to_path_buf());
    }

    // Subshells and groups anywhere on the line are not modelled: a `cd`
    // inside `( … )` does not reach the outer shell, a match inside `( … )`
    // may run in a directory the walk below would not see, and a group after
    // the match can move a second guarded call elsewhere.
    if has_unquoted_grouping(command) {
        return None;
    }

    // A background `&` or a pipe `|` runs the segment on one side in a
    // subshell, so a `cd` there never reaches the shell that runs the guarded
    // git command. The segment walk below assumes every separator preserves
    // the working directory (true for `&&`, `||`, `;`, newline), so fail
    // closed when a subshell separator is present rather than resolve to a
    // directory the git call does not actually run in.
    if command_has_subshell_separator(command) {
        return None;
    }

    // Classify every top-level segment once. An unparseable segment or one
    // whose executable is only known at run time (`$DO_CD repo`) could be a
    // directory change dcg cannot see, so resolution fails closed on it.
    let mut leading: Vec<Option<(String, Vec<ShellWord>)>> = Vec::with_capacity(segments.len());
    for &(start, end) in &segments {
        let words = shell_words(&command[start..end])?;
        // `GIT_DIR=…` / `GIT_WORK_TREE=…` re-point git at another repository
        // exactly like the `--git-dir` / `--work-tree` options do (which the
        // matched-segment walk fails closed on). A leading assignment is
        // otherwise skipped as inert, so catch these here on any segment.
        if words
            .iter()
            .take_while(|word| is_assignment_word(&word.text))
            .any(|word| is_git_repo_redirecting_assignment(&word.text))
        {
            return None;
        }
        match leading_word(&words) {
            Leading::Dynamic => return None,
            Leading::Empty => leading.push(None),
            Leading::Executable(index) => {
                let name = words[index].text.clone();
                let rest = words.into_iter().skip(index + 1).collect();
                leading.push(Some((name, rest)));
            }
        }
    }

    // Locate the segment that owns the matched rule text.
    let matched_index = match match_start {
        // A match that sits between segments (e.g. on a separator) cannot be
        // attributed.
        Some(offset) => segments
            .iter()
            .position(|&(start, end)| offset >= start && offset < end),
        None => {
            let git_segments: Vec<usize> = leading
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.as_ref().is_some_and(|(name, _)| name == "git"))
                .map(|(index, _)| index)
                .collect();
            match git_segments.as_slice() {
                [only] => Some(*only),
                _ => None,
            }
        }
    };

    // The match must land on a segment whose executable is `git`. A span
    // offset is computed against the normalized command and mapped back with
    // a constant shift, so a mis-mapped offset could otherwise land on a
    // `cd` segment and have the walk below apply only the moves before it.
    // Anything else (an inline shell payload, a separator byte) is
    // unattributable: with no attributed segment, no directory change at all
    // can be placed before or after the guarded call.
    let matched_index = matched_index.filter(|&index| {
        leading[index]
            .as_ref()
            .is_some_and(|(name, _)| name == "git")
    });

    // The whole line runs once the command is allowed, and the re-evaluation
    // that follows grants the recovery rules wherever they appear — including
    // inside a nested shell, whose own `cd` this walk cannot see. So every
    // other segment may only be a static `cd`/`pushd` ahead of the match, a
    // plain `git` call (no `-C`), or an inert builtin. Anything that can run
    // further commands (`bash -c '…'`, `xargs`, `eval`, `source`, a script)
    // or move the shell after the match could put a second guarded call in a
    // repository this resolution never probed, so the window stays closed for
    // the whole line; the documented flow is one command.
    let mut cwd = base.to_path_buf();
    let mut changed = false;

    for (index, entry) in leading.iter().enumerate() {
        if Some(index) == matched_index {
            continue;
        }
        let Some((name, rest)) = entry else {
            continue;
        };
        match name.as_str() {
            "cd" | "pushd" if matched_index.is_some_and(|matched| index < matched) => {
                let target = directory_change_target(name, rest, home)?;
                cwd = join_directory(&cwd, &target);
                changed = true;
            }
            "git"
                if rest
                    .iter()
                    .all(|word| !git_option_moves_repository(&word.text)) => {}
            "echo" | "printf" | "true" | "false" | ":" | "exit" | "pwd" | "test" | "[" => {}
            _ => return None,
        }
    }

    // `git -C <path>` on the matched segment moves the repository the same
    // way. Walk git's global options up to the subcommand: `-C` may sit
    // after other options (`git --no-pager -C other restore`), so stopping
    // at the first non-`-C` word would probe the wrong repository.
    if let Some((name, rest)) = matched_index.and_then(|index| leading[index].as_ref())
        && name == "git"
    {
        let mut args = rest.iter();
        while let Some(word) = args.next() {
            if word.dynamic {
                return None;
            }
            match word.text.as_str() {
                "-C" => {
                    let path = args.next()?;
                    if path.dynamic || path.text.is_empty() {
                        return None;
                    }
                    cwd = join_directory(&cwd, Path::new(&path.text));
                    changed = true;
                }
                // `-c key=value` takes a separate value; never a path.
                "-c" => {
                    args.next()?;
                }
                // `--git-dir` / `--work-tree` / `--namespace` re-point git
                // without moving the shell; not modelled, fail closed.
                text if git_option_moves_repository(text) => return None,
                text if text.starts_with('-') => {}
                // The subcommand: global options end here.
                _ => break,
            }
        }
    }

    if !changed {
        return Some(base.to_path_buf());
    }

    // A target that does not exist has nothing to recover; canonicalizing
    // also collapses `..` segments the way the shell's `cd -P` would.
    fs::canonicalize(&cwd).ok().filter(|path| path.is_dir())
}

/// Words that move a POSIX shell's working directory.
const POSIX_DIRECTORY_CHANGE_WORDS: &[&str] = &["cd", "pushd", "popd"];

/// Words that move the working directory in the dialects dcg does not model
/// (PowerShell, cmd). Their presence is enough to give up.
const FOREIGN_DIRECTORY_CHANGE_WORDS: &[&str] = &[
    "chdir",
    "sl",
    "set-location",
    "push-location",
    "pop-location",
];

/// How many times `command` mentions one of `vocabulary`, as a bare word.
///
/// Deliberately over-approximates: quoting and nesting are ignored, so the
/// `cd` inside `bash -c 'cd /elsewhere && …'` is counted even though the
/// segment walk cannot see it. The walk compares its own tally against this
/// one and gives up when they disagree, which is what keeps a directory
/// change hidden inside a nested payload from resolving to the base
/// directory unchanged. `-` counts as a word character so `git-cd` is one
/// word, not two.
fn count_directory_change_words(command: &str, vocabulary: &[&str]) -> usize {
    command
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .filter(|word| {
            vocabulary
                .iter()
                .any(|candidate| word.eq_ignore_ascii_case(candidate))
        })
        .count()
}

/// Resolve the directory a guarded command will actually run in (issue #387).
///
/// `base` is the directory the agent host reported for the tool call — the
/// hook payload's `cwd`, which is the only authority on where the command
/// runs; the hook process's own `getcwd()` is unrelated to it. A command can
/// still move before the guarded call happens (`cd build && rm -rf .`), so
/// leading static `cd` / `pushd` segments are applied on top of `base`.
///
/// This answers *where*, for directory-scoped allowlist entries. Because such
/// an entry is a permission grant, resolution fails closed — returning `None`,
/// which makes every `paths = [...]` entry inapplicable — whenever the answer
/// is not statically knowable:
///
/// - a directory change whose target needs the shell to compute (`cd $DIR`,
///   `cd -`, globs, `~user`), or a `popd`,
/// - a directory change in a dialect that is not modelled (PowerShell, cmd),
/// - a subshell or group (`( … )`, `{ … }`), or a separator that runs a
///   segment in a subshell (`|`, background `&`), anywhere on the line,
/// - a directory change that follows a real command, which would leave two
///   commands running in two different directories with only one scope answer
///   available for both,
/// - any other mention of a directory-change word that the segment walk did
///   not consume — a `cd` inside a nested payload (`bash -c '…'`, `eval`,
///   `xargs`) that the walk cannot see, or even one that is only quoted text,
/// - a resolved directory that does not exist.
///
/// A `cd` out of a scoped tree therefore revokes the grant; it can never
/// extend it to a directory the grant never named.
#[must_use]
pub fn resolve_effective_cwd(
    base: &Path,
    command: &str,
    dialect: crate::normalize::ShellDialect,
) -> Option<PathBuf> {
    resolve_effective_cwd_with_home(
        base,
        command,
        dialect,
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    )
}

/// [`resolve_effective_cwd`] with an explicit `HOME` (tests must not mutate the
/// process environment).
fn resolve_effective_cwd_with_home(
    base: &Path,
    command: &str,
    dialect: crate::normalize::ShellDialect,
    home: Option<&Path>,
) -> Option<PathBuf> {
    use crate::normalize::ShellDialect;

    let mentions = count_directory_change_words(command, POSIX_DIRECTORY_CHANGE_WORDS);
    let foreign_mentions = count_directory_change_words(command, FOREIGN_DIRECTORY_CHANGE_WORDS);

    // Nothing on the line can move the shell: the command runs at `base`.
    if mentions == 0 && foreign_mentions == 0 {
        return Some(base.to_path_buf());
    }

    // Only POSIX-style shells are modelled below, and a word out of another
    // dialect's vocabulary is not something this walk can attribute either.
    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) || foreign_mentions > 0 {
        return None;
    }

    if has_unquoted_grouping(command) || command_has_subshell_separator(command) {
        return None;
    }

    let segments = top_level_segment_ranges(command)?;

    let mut cwd = base.to_path_buf();
    let mut consumed = 0usize;
    let mut saw_command = false;

    for &(start, end) in &segments {
        let words = shell_words(&command[start..end])?;
        let index = match leading_word(&words) {
            // An executable only known at run time could itself be a `cd`.
            Leading::Dynamic => return None,
            Leading::Empty => continue,
            Leading::Executable(index) => index,
        };
        match words[index].text.as_str() {
            "cd" | "pushd" => {
                // A directory change *after* a real command would leave the
                // two running in different directories, and only one of them
                // can be the answer.
                if saw_command {
                    return None;
                }
                let target =
                    directory_change_target(&words[index].text, &words[index + 1..], home)?;
                cwd = join_directory(&cwd, &target);
                consumed += 1;
            }
            // `popd` depends on a directory stack dcg does not track.
            "popd" => return None,
            _ => saw_command = true,
        }
    }

    // Every mention has to be one of the changes just applied. A leftover is a
    // `cd` the walk could not see — inside `bash -c '…'`, an `eval`, an
    // argument — and the directory it reaches is unknowable.
    if consumed != mentions {
        return None;
    }

    // Canonicalize so the result is comparable with a scope pattern and `..`
    // segments collapse the way the shell's `cd -P` would.
    fs::canonicalize(&cwd).ok().filter(|path| path.is_dir())
}

/// Whether `command` contains an unquoted subshell-creating separator: a
/// background `&` or a pipe `|`/`|&`. `&&`, `||`, `;`, newline, and the `&` of
/// a redirection (`2>&1`, `<&0`, `&>file`) preserve the shell's working
/// directory and are not flagged.
fn command_has_subshell_separator(command: &str) -> bool {
    let bytes = command.as_bytes();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'\\' && !in_single {
            i += 2;
            continue;
        }
        match byte {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'|' if !in_single && !in_double => {
                // `||` preserves cwd; a lone `|` (or `|&`) is a pipe.
                if bytes.get(i + 1) == Some(&b'|') {
                    i += 2;
                    continue;
                }
                return true;
            }
            b'&' if !in_single && !in_double => {
                // `&&` preserves cwd; `&>` is a redirection; a `&` right after
                // a redirect byte is a file-descriptor duplication (`2>&1`,
                // `<&0`). Anything else is backgrounding.
                if bytes.get(i + 1) == Some(&b'&') {
                    i += 2;
                    continue;
                }
                let next_is_redirect = bytes.get(i + 1) == Some(&b'>');
                let prev_is_redirect = i
                    .checked_sub(1)
                    .is_some_and(|p| matches!(bytes[p], b'>' | b'<'));
                if next_is_redirect || prev_is_redirect {
                    i += 1;
                    continue;
                }
                return true;
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Whether a leading `NAME=value` word re-points git at another repository or
/// worktree. These are the environment equivalents of `--git-dir` /
/// `--work-tree` and must fail closed exactly like those options do.
fn is_git_repo_redirecting_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    matches!(
        name,
        "GIT_DIR"
            | "GIT_WORK_TREE"
            | "GIT_COMMON_DIR"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_NAMESPACE"
            | "GIT_INDEX_FILE"
    )
}

/// Whether a `git` global option changes which repository or worktree the
/// invocation operates on. `-C` is followed by the resolver on the matched
/// segment; everything else here is unmodelled and fails closed.
fn git_option_moves_repository(option: &str) -> bool {
    option == "-C"
        || option.starts_with("--git-dir")
        || option.starts_with("--work-tree")
        || option.starts_with("--namespace")
}

/// The allowlist to re-evaluate a command under once a recovery signal has
/// been confirmed for it.
///
/// A recovery signal unlocks only the [`RECOVERY_PATTERNS`] — nothing about
/// an in-progress rebase makes `git reset --hard` or a `git restore` in a
/// second repository safe. The hook therefore re-runs the full evaluation
/// with exactly those rules granted and lets every other finding on the line
/// keep its own verdict: `git restore -- f; git reset --hard` is still denied
/// by `reset-hard`, and the permit is left unconsumed because the command did
/// not run.
#[must_use]
pub fn relaxed_allowlist(
    base: &crate::allowlist::LayeredAllowlist,
) -> crate::allowlist::LayeredAllowlist {
    let rules: Vec<(&str, &str)> = RECOVERY_PATTERNS
        .iter()
        .map(|pattern| ("core.git", *pattern))
        .collect();
    base.with_rule_grants(&rules, "rebase-recovery re-evaluation", "rebase-recovery")
}

/// One shell word with the information the cwd walk needs: its unquoted text
/// and whether any part of it is only known at run time.
struct ShellWord {
    text: String,
    dynamic: bool,
}

/// Split one command segment into words, honoring single quotes, double
/// quotes, and backslash escapes. Returns `None` on an unterminated quote.
///
/// `dynamic` marks words containing an unquoted or double-quoted expansion
/// (`$`, backtick), an unquoted glob metacharacter, or a `~user` tilde — all
/// of which the shell rewrites before `cd` ever sees the argument.
fn shell_words(segment: &str) -> Option<Vec<ShellWord>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut dynamic = false;
    let mut chars = segment.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(inner) => current.push(inner),
                        None => return None,
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(escaped @ ('"' | '\\' | '$' | '`')) => current.push(escaped),
                            Some(other) => {
                                current.push('\\');
                                current.push(other);
                            }
                            None => return None,
                        },
                        Some(inner @ ('$' | '`')) => {
                            dynamic = true;
                            current.push(inner);
                        }
                        Some(inner) => current.push(inner),
                        None => return None,
                    }
                }
            }
            '\\' => {
                in_word = true;
                current.push(chars.next()?);
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(ShellWord {
                        text: std::mem::take(&mut current),
                        dynamic,
                    });
                    in_word = false;
                    dynamic = false;
                }
            }
            '$' | '`' | '*' | '?' | '[' => {
                in_word = true;
                dynamic = true;
                current.push(ch);
            }
            '~' => {
                // `~` and `~/…` are resolvable; `~user` is not modelled.
                if !in_word && !matches!(chars.peek(), None | Some('/')) {
                    dynamic = true;
                }
                in_word = true;
                current.push(ch);
            }
            _ => {
                in_word = true;
                current.push(ch);
            }
        }
    }
    if in_word {
        words.push(ShellWord {
            text: current,
            dynamic,
        });
    }
    Some(words)
}

/// What a segment starts with, once `VAR=value` assignments and the bare
/// transparent wrappers (`command`, `builtin`, `exec`, `sudo`, `env`, `nice`,
/// `nohup`, `time`) are skipped. A wrapper option (`sudo -u bob git …`) is not
/// modelled and reads as an unknown executable, which fails closed.
enum Leading {
    /// Nothing executable (assignments only, or an empty segment).
    Empty,
    /// The executable word is an expansion (`$cmd …`) — unknowable.
    Dynamic,
    /// The executable is the literal word at this index.
    Executable(usize),
}

fn leading_word(words: &[ShellWord]) -> Leading {
    let mut index = 0;
    while let Some(word) = words.get(index) {
        if is_assignment_word(&word.text) {
            index += 1;
            continue;
        }
        if word.dynamic {
            return Leading::Dynamic;
        }
        if matches!(
            word.text.as_str(),
            "command" | "builtin" | "exec" | "sudo" | "env" | "nice" | "nohup" | "time"
        ) {
            index += 1;
            continue;
        }
        return Leading::Executable(index);
    }
    Leading::Empty
}

fn is_assignment_word(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

/// The literal target of a `cd` / `pushd` argument list, or `None` when it
/// depends on run-time state (`cd -`, expansions, `~user`, missing `HOME`,
/// two operands — bash's `cd old new` substitution form).
///
/// `pushd` differs from `cd` in two ways that must fail closed: `pushd -n
/// <dir>` pushes onto the directory stack *without* changing directory, and a
/// bare `pushd` swaps the top two stack entries (it does not go `HOME`).
fn directory_change_target(
    command_name: &str,
    args: &[ShellWord],
    home: Option<&Path>,
) -> Option<PathBuf> {
    let is_pushd = command_name == "pushd";
    let mut operands: Vec<&ShellWord> = Vec::new();
    let mut options_done = false;
    for word in args {
        if !options_done && word.text == "--" && !word.dynamic {
            options_done = true;
            continue;
        }
        // Options (`-P`, `-L`, `-e`, pushd's `-n`); a lone `-` is an operand.
        if !options_done && word.text.len() > 1 && word.text.starts_with('-') {
            // `pushd -n` pushes without changing directory — unmodelled.
            if is_pushd && !word.dynamic && word.text == "-n" {
                return None;
            }
            continue;
        }
        operands.push(word);
    }

    match operands.as_slice() {
        // Bare `cd` goes HOME; bare `pushd` swaps the stack (no attributable
        // move).
        [] if is_pushd => None,
        [] => home.map(Path::to_path_buf),
        [operand] => {
            if operand.dynamic || operand.text == "-" || operand.text.is_empty() {
                return None;
            }
            if let Some(rest) = operand.text.strip_prefix('~') {
                let home = home?;
                return Some(match rest.strip_prefix('/') {
                    Some("") | None => home.to_path_buf(),
                    Some(relative) => home.join(relative),
                });
            }
            Some(PathBuf::from(&operand.text))
        }
        _ => None,
    }
}

fn join_directory(cwd: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        cwd.join(target)
    }
}

/// Whether `prefix` contains an unquoted `(`, `)`, `{`, `}`, or backtick.
fn has_unquoted_grouping(prefix: &str) -> bool {
    let mut chars = prefix.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                if !chars.any(|c| c == '\'') {
                    return true; // unbalanced: treat as unknowable
                }
            }
            '"' => loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => {
                        chars.next();
                    }
                    Some(_) => {}
                    None => return true,
                }
            },
            '\\' => {
                chars.next();
            }
            '(' | ')' | '{' | '}' | '`' => return true,
            _ => {}
        }
    }
    false
}

/// Byte ranges of the top-level command segments of `command`, in order.
///
/// [`crate::packs::split_command_segments`] also returns command substitutions
/// (before their enclosing segment); those are nested inside another range and
/// are dropped here, because a `cd` inside `$( … )` never reaches the shell
/// that runs the guarded command. Returns `None` if a segment cannot be
/// located inside `command` (never expected; fail closed).
fn top_level_segment_ranges(command: &str) -> Option<Vec<(usize, usize)>> {
    let base = command.as_ptr() as usize;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for segment in crate::packs::split_command_segments(command) {
        let start = (segment.as_ptr() as usize).checked_sub(base)?;
        let end = start.checked_add(segment.len())?;
        if end > command.len() {
            return None;
        }
        ranges.push((start, end));
    }
    // Widest range first at equal starts so a nested range always follows the
    // range that contains it.
    ranges.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut top_level: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    let mut covered_until = 0;
    for (start, end) in ranges {
        if start < covered_until {
            continue; // nested inside the previous top-level range
        }
        top_level.push((start, end));
        covered_until = end;
    }
    Some(top_level)
}

/// Detect whether a rebase is in progress in the given working directory.
///
/// Uses the standard git-porcelain convention: the presence of
/// `.git/rebase-merge/` (interactive/merge rebase) or `.git/rebase-apply/`
/// (non-interactive rebase) indicates an active rebase. Also handles
/// worktrees where `.git` is a file pointing to the real git dir.
#[must_use]
pub fn is_rebase_in_progress(cwd: &Path) -> bool {
    let Some(git_dir) = resolve_git_dir(cwd) else {
        return false;
    };
    git_dir.join("rebase-merge").is_dir() || git_dir.join("rebase-apply").is_dir()
}

/// Walk up from `cwd` looking for the nearest `.git`.
///
/// If `.git` is a directory, return it. If `.git` is a file (worktree /
/// submodule), parse its `gitdir:` directive. If nothing is found, return
/// `None` (we'll treat that as "not in a git repo").
fn resolve_git_dir(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd.to_path_buf();
    loop {
        let dot_git = current.join(".git");
        if dot_git.is_dir() {
            return Some(dot_git);
        }
        if dot_git.is_file() {
            if let Ok(contents) = fs::read_to_string(&dot_git) {
                for line in contents.lines() {
                    if let Some(rest) = line.strip_prefix("gitdir:") {
                        let path = PathBuf::from(rest.trim());
                        if path.is_absolute() {
                            return Some(path);
                        }
                        return Some(current.join(path));
                    }
                }
            }
            return None;
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Compute the path where the permit cookie lives for a given working
/// directory. Located inside `.dcg/` so it lives alongside other dcg state
/// and doesn't pollute the project root.
fn permit_path(cwd: &Path) -> PathBuf {
    // Anchor the permit to the repo root when possible so nested `cd`s
    // still see the same cookie during the recovery window. Fall back to
    // the raw `cwd` if we can't resolve a git dir (not in a repo).
    let anchor = resolve_git_dir(cwd)
        .and_then(|g| g.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| cwd.to_path_buf());
    anchor.join(".dcg").join("rebase-recovery-permit")
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a permit cookie valid for `ttl_secs` seconds.
///
/// The cookie stores the absolute expiration time (unix epoch seconds)
/// so clock skew within a single machine doesn't trip us up and we don't
/// need to parse relative times at check-time.
///
/// # Errors
///
/// Returns an IO error if the `.dcg/` directory cannot be created or the
/// permit file cannot be written.
pub fn set_permit(cwd: &Path, ttl_secs: u64) -> std::io::Result<PathBuf> {
    let ttl = ttl_secs.clamp(1, MAX_PERMIT_TTL_SECS);
    let path = permit_path(cwd);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let expires_at = now_epoch_secs().saturating_add(ttl);
    fs::write(&path, format!("{expires_at}\n"))?;
    Ok(path)
}

/// If a permit cookie exists and is still valid, return the number of
/// seconds remaining. Otherwise return `None` (no permit, expired permit,
/// malformed permit).
#[must_use]
pub fn permit_seconds_remaining(cwd: &Path) -> Option<u64> {
    let path = permit_path(cwd);
    let contents = fs::read_to_string(&path).ok()?;
    let first_line = contents.lines().next()?.trim();
    let expires_at: u64 = first_line.parse().ok()?;
    let now = now_epoch_secs();
    if expires_at > now {
        Some(expires_at - now)
    } else {
        // Expired — best-effort cleanup so the next call doesn't see it.
        let _ = fs::remove_file(&path);
        None
    }
}

/// Consume the permit (single-shot): delete the cookie file. Called after
/// a successful recovery-allow so the permit doesn't silently unblock
/// later unrelated commands within the TTL window.
pub fn consume_permit(cwd: &Path) {
    let path = permit_path(cwd);
    let _ = fs::remove_file(path);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a tempdir rooted at `target/` (which is always writable in
    /// our CI) and initialize it as a minimal fake git repo. Returns the
    /// repo root; the test is responsible for cleanup via `Drop`.
    struct FakeRepo {
        root: PathBuf,
    }

    impl FakeRepo {
        fn new(label: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "dcg-rebase-recovery-{}-{}-{}",
                label,
                std::process::id(),
                now_epoch_secs()
            ));
            fs::create_dir_all(base.join(".git")).unwrap();
            Self { root: base }
        }

        fn start_rebase_merge(&self) {
            fs::create_dir_all(self.root.join(".git").join("rebase-merge")).unwrap();
        }

        fn start_rebase_apply(&self) {
            fs::create_dir_all(self.root.join(".git").join("rebase-apply")).unwrap();
        }
    }

    impl Drop for FakeRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn is_rebase_in_progress_false_for_clean_repo() {
        let repo = FakeRepo::new("clean");
        assert!(!is_rebase_in_progress(&repo.root));
    }

    #[test]
    fn is_rebase_in_progress_true_for_rebase_merge() {
        let repo = FakeRepo::new("merge");
        repo.start_rebase_merge();
        assert!(is_rebase_in_progress(&repo.root));
    }

    #[test]
    fn is_rebase_in_progress_true_for_rebase_apply() {
        let repo = FakeRepo::new("apply");
        repo.start_rebase_apply();
        assert!(is_rebase_in_progress(&repo.root));
    }

    #[test]
    fn is_rebase_in_progress_false_outside_repo() {
        let dir = std::env::temp_dir().join(format!(
            "dcg-no-repo-{}-{}",
            std::process::id(),
            now_epoch_secs()
        ));
        fs::create_dir_all(&dir).unwrap();
        assert!(!is_rebase_in_progress(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_allow_recovery_blocks_outside_rebase() {
        let repo = FakeRepo::new("block-outside");
        assert!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("checkout-discard")).is_none(),
            "recovery must NOT fire outside an active rebase or permit"
        );
        assert!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree")).is_none()
        );
    }

    #[test]
    fn should_allow_recovery_fires_during_rebase() {
        let repo = FakeRepo::new("allow-rebase");
        repo.start_rebase_merge();
        assert_eq!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("checkout-discard")),
            Some(RecoveryReason::RebaseInProgress)
        );
        assert_eq!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree")),
            Some(RecoveryReason::RebaseInProgress)
        );
    }

    #[test]
    fn should_allow_recovery_ignores_non_recovery_patterns() {
        let repo = FakeRepo::new("non-recovery");
        repo.start_rebase_merge();
        // Even during a rebase, unrelated destructive patterns must not
        // be auto-unblocked (e.g., `git reset --hard` stays blocked).
        assert!(should_allow_recovery(&repo.root, Some("core.git"), Some("reset-hard")).is_none());
        assert!(should_allow_recovery(&repo.root, Some("core.git"), Some("clean-force")).is_none());
        // Different pack — always stays blocked.
        assert!(
            should_allow_recovery(&repo.root, Some("core.filesystem"), Some("rm-rf-general"))
                .is_none()
        );
    }

    #[test]
    fn permit_valid_within_ttl() {
        let repo = FakeRepo::new("permit-valid");
        set_permit(&repo.root, 60).unwrap();
        let remaining = permit_seconds_remaining(&repo.root);
        assert!(remaining.is_some(), "permit should be active");
        let secs = remaining.unwrap();
        assert!(secs > 0 && secs <= 60, "remaining={secs}, expected <= 60");
    }

    #[test]
    fn permit_allows_recovery_when_not_in_rebase() {
        let repo = FakeRepo::new("permit-allows");
        // No rebase in progress.
        assert!(!is_rebase_in_progress(&repo.root));
        // Without a permit, blocked.
        assert!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree")).is_none()
        );
        // With a permit, allowed.
        set_permit(&repo.root, 60).unwrap();
        let reason = should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree"));
        assert!(matches!(reason, Some(RecoveryReason::ActivePermit(_))));
    }

    #[test]
    fn permit_expires_correctly() {
        let repo = FakeRepo::new("permit-expires");
        // Manually write an already-expired cookie.
        let path = permit_path(&repo.root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let expired_at = now_epoch_secs().saturating_sub(10);
        fs::write(&path, format!("{expired_at}\n")).unwrap();
        assert!(
            permit_seconds_remaining(&repo.root).is_none(),
            "expired permit must not be honored"
        );
        // Expired permit is cleaned up on read.
        assert!(!path.exists(), "expired permit should be auto-removed");
    }

    #[test]
    fn permit_can_be_consumed() {
        let repo = FakeRepo::new("permit-consume");
        set_permit(&repo.root, 60).unwrap();
        assert!(permit_seconds_remaining(&repo.root).is_some());
        consume_permit(&repo.root);
        assert!(
            permit_seconds_remaining(&repo.root).is_none(),
            "consumed permit must not remain valid"
        );
    }

    #[test]
    fn permit_ttl_is_clamped() {
        let repo = FakeRepo::new("permit-clamp");
        // Request a huge TTL; implementation must clamp to MAX.
        set_permit(&repo.root, 60_000).unwrap();
        let remaining = permit_seconds_remaining(&repo.root).unwrap();
        assert!(
            remaining <= MAX_PERMIT_TTL_SECS,
            "remaining={remaining} > MAX={MAX_PERMIT_TTL_SECS}"
        );
    }

    #[test]
    fn malformed_permit_is_ignored() {
        let repo = FakeRepo::new("permit-malformed");
        let path = permit_path(&repo.root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "not-a-number\n").unwrap();
        assert!(permit_seconds_remaining(&repo.root).is_none());
    }

    #[test]
    fn recovery_reason_labels_are_informative() {
        assert_eq!(
            RecoveryReason::RebaseInProgress.label(),
            "rebase in progress"
        );
        let label = RecoveryReason::ActivePermit(45).label();
        assert!(label.contains("45"), "label must include seconds: {label}");
        assert!(
            label.contains("permit"),
            "label must mention permit: {label}"
        );
    }

    // ------------------------------------------------------------------
    // resolve_recovery_cwd (#331): the probe follows the command's own cd.
    // ------------------------------------------------------------------

    use crate::normalize::ShellDialect;

    /// A scratch tree: `<root>/repo/sub`, `<root>/other`, `<root>/home`.
    struct Tree {
        root: PathBuf,
    }

    impl Tree {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "dcg-recovery-cwd-{}-{}-{}",
                label,
                std::process::id(),
                now_epoch_secs()
            ));
            fs::create_dir_all(root.join("repo").join("sub")).unwrap();
            fs::create_dir_all(root.join("other")).unwrap();
            fs::create_dir_all(root.join("home")).unwrap();
            fs::create_dir_all(root.join("dir with space")).unwrap();
            Self {
                root: fs::canonicalize(root).unwrap(),
            }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }

        fn home(&self) -> PathBuf {
            self.path("home")
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// Resolve with the match anchored on the first `git` in `command`.
    fn resolve(tree: &Tree, base: &Path, command: &str) -> Option<PathBuf> {
        let start = command.find("git").expect("command must mention git");
        resolve_recovery_cwd_with_home(
            base,
            command,
            Some(start),
            ShellDialect::Posix,
            Some(&tree.home()),
        )
    }

    /// Resolve the effective cwd for allowlist scoping (#387).
    fn effective(tree: &Tree, base: &Path, command: &str) -> Option<PathBuf> {
        resolve_effective_cwd_with_home(base, command, ShellDialect::Posix, Some(&tree.home()))
    }

    #[test]
    fn effective_cwd_without_directory_change_is_the_base() {
        let tree = Tree::new("eff-no-cd");
        let base = tree.path("other");
        assert_eq!(effective(&tree, &base, "rm -rf build"), Some(base.clone()));
        // Pipes and subshells are only a problem when a `cd` is involved.
        assert_eq!(
            effective(&tree, &base, "find . -name '*.log' | xargs rm -f"),
            Some(base.clone())
        );
        assert_eq!(
            effective(&tree, &base, "(rm -rf build)"),
            Some(base.clone())
        );
    }

    #[test]
    fn effective_cwd_follows_a_static_cd() {
        let tree = Tree::new("eff-cd");
        let base = tree.path("other");
        let repo = tree.path("repo");
        assert_eq!(
            effective(
                &tree,
                &base,
                &format!("cd {} && rm -rf build", repo.display())
            ),
            Some(repo.clone())
        );
        // Relative, and `..` collapsed the way `cd -P` would.
        assert_eq!(
            effective(&tree, &repo, "cd sub && rm -rf build"),
            Some(repo.join("sub"))
        );
        assert_eq!(
            effective(&tree, &repo, "cd ../other && rm -rf build"),
            Some(tree.path("other"))
        );
    }

    #[test]
    fn effective_cwd_fails_closed_when_it_cannot_be_known() {
        let tree = Tree::new("eff-closed");
        let base = tree.path("other");
        for command in [
            "cd \"$DEST\" && rm -rf build",
            "cd $(cat dir) && rm -rf build",
            "cd ~someone && rm -rf build",
            "cd - && rm -rf build",
            "popd && rm -rf build",
            "cd nonexistent-directory && rm -rf build",
            "cd repo | rm -rf build",
            "(cd repo && rm -rf build)",
            "$RUNNER && cd repo && rm -rf build",
        ] {
            assert_eq!(
                effective(&tree, &base, command),
                None,
                "must fail closed: {command}"
            );
        }
    }

    #[test]
    fn effective_cwd_fails_closed_when_a_cd_follows_a_command() {
        let tree = Tree::new("eff-late-cd");
        let base = tree.path("other");
        // Two commands in two directories; one scope answer cannot cover both.
        assert_eq!(
            effective(
                &tree,
                &base,
                &format!(
                    "rm -rf build && cd {} && rm -rf build",
                    tree.path("repo").display()
                )
            ),
            None
        );
    }

    #[test]
    fn effective_cwd_is_unknown_for_unmodelled_dialects_that_move() {
        let tree = Tree::new("eff-dialect");
        let base = tree.path("other");
        assert_eq!(
            resolve_effective_cwd_with_home(
                &base,
                "Set-Location C:\\repo; Remove-Item -Recurse -Force build",
                ShellDialect::PowerShell,
                Some(&tree.home()),
            ),
            None
        );
        // A PowerShell line that cannot move the shell still resolves.
        assert_eq!(
            resolve_effective_cwd_with_home(
                &base,
                "Remove-Item -Recurse -Force build",
                ShellDialect::PowerShell,
                Some(&tree.home()),
            ),
            Some(base.clone())
        );
    }

    #[test]
    fn effective_cwd_fails_closed_on_a_hidden_or_stray_cd() {
        let tree = Tree::new("eff-hidden-cd");
        let base = tree.path("other");
        let repo = tree.path("repo");
        for command in [
            // A `cd` the segment walk cannot see must not resolve to `base`.
            format!("bash -c 'cd {} && rm -rf build'", repo.display()),
            format!("eval \"cd {} && rm -rf build\"", repo.display()),
            "xargs -I{} sh -c 'cd {} && rm -rf build'".to_string(),
            // Even an inert mention is a mention: dcg cannot prove it inert.
            format!("cd {} && rm -rf cd", repo.display()),
        ] {
            assert_eq!(
                effective(&tree, &base, &command),
                None,
                "must fail closed: {command}"
            );
        }
    }

    #[test]
    fn count_directory_change_words_tallies_bare_words_only() {
        assert_eq!(
            count_directory_change_words("cd /tmp && rm -rf .", POSIX_DIRECTORY_CHANGE_WORDS),
            1
        );
        assert_eq!(
            count_directory_change_words("rm -rf .;CD /tmp", POSIX_DIRECTORY_CHANGE_WORDS),
            1
        );
        assert_eq!(
            count_directory_change_words("cd a && cd b", POSIX_DIRECTORY_CHANGE_WORDS),
            2
        );
        assert_eq!(
            count_directory_change_words("git-cd --help", POSIX_DIRECTORY_CHANGE_WORDS),
            0
        );
        assert_eq!(
            count_directory_change_words("rm -rf build", POSIX_DIRECTORY_CHANGE_WORDS),
            0
        );
        assert_eq!(
            count_directory_change_words("Set-Location C:\\x", FOREIGN_DIRECTORY_CHANGE_WORDS),
            1
        );
    }

    #[test]
    fn recovery_cwd_without_directory_change_is_the_base_unchanged() {
        let tree = Tree::new("no-cd");
        let base = tree.path("other");
        assert_eq!(
            resolve(&tree, &base, "git restore --worktree --ours -- f.txt"),
            Some(base.clone())
        );
        // Even a non-canonical base is returned verbatim: nothing moved.
        let raw = tree.root.join("other").join(".");
        assert_eq!(
            resolve(&tree, &raw, "git restore -- f.txt"),
            Some(raw.clone())
        );
    }

    #[test]
    fn recovery_cwd_follows_absolute_cd() {
        let tree = Tree::new("abs-cd");
        let repo = tree.path("repo");
        let command = format!(
            "cd {} && git restore --worktree --ours -- f.txt",
            repo.display()
        );
        assert_eq!(
            resolve(&tree, &tree.path("other"), &command),
            Some(repo.clone())
        );
    }

    #[test]
    fn recovery_cwd_follows_relative_cd_semicolon_and_or_exit() {
        let tree = Tree::new("rel-cd");
        let repo = tree.path("repo");
        for command in [
            "cd repo && git restore -- f.txt",
            "cd repo; git restore -- f.txt",
            "cd repo || exit 1; git checkout -- .",
            "cd ./repo && git restore -- f.txt",
            "cd -- repo && git restore -- f.txt",
            "cd -P repo && git restore -- f.txt",
            "pushd repo && git restore -- f.txt",
            "command cd repo && git restore -- f.txt",
            "GIT_TRACE=1 cd repo && git restore -- f.txt",
            "cd repo && cd sub && cd .. && git restore -- f.txt",
            "cd repo\ngit restore -- f.txt",
        ] {
            assert_eq!(
                resolve(&tree, &tree.root, command),
                Some(repo.clone()),
                "command: {command}"
            );
        }
    }

    #[test]
    fn recovery_cwd_handles_quoted_and_tilde_targets() {
        let tree = Tree::new("quoted-cd");
        let spaced = tree.path("dir with space");
        assert_eq!(
            resolve(&tree, &tree.root, "cd 'dir with space' && git restore -- f"),
            Some(spaced.clone())
        );
        assert_eq!(
            resolve(
                &tree,
                &tree.root,
                "cd \"dir with space\" && git restore -- f"
            ),
            Some(spaced.clone())
        );
        assert_eq!(
            resolve(
                &tree,
                &tree.root,
                "cd dir\\ with\\ space && git restore -- f"
            ),
            Some(spaced)
        );
        assert_eq!(
            resolve(&tree, &tree.path("other"), "cd ~ && git restore -- f"),
            Some(tree.home())
        );
        assert_eq!(
            resolve(&tree, &tree.path("other"), "cd && git restore -- f"),
            Some(tree.home())
        );
        // A literal `$` inside single quotes is not an expansion — but the
        // directory does not exist, so there is nothing to recover there.
        assert_eq!(
            resolve(&tree, &tree.root, "cd '$REPO' && git restore -- f"),
            None
        );
    }

    #[test]
    fn recovery_cwd_follows_git_dash_c() {
        let tree = Tree::new("git-c");
        let repo = tree.path("repo");
        assert_eq!(
            resolve(&tree, &tree.root, "git -C repo restore -- f.txt"),
            Some(repo.clone())
        );
        assert_eq!(
            resolve(
                &tree,
                &tree.path("other"),
                "cd .. && git -C repo -C sub restore -- f"
            ),
            Some(repo.join("sub"))
        );
        let absolute = format!("git -C {} restore -- f", repo.display());
        assert_eq!(
            resolve(&tree, &tree.path("other"), &absolute),
            Some(repo.clone())
        );
        // `-C` after other global options still moves the probe.
        assert_eq!(
            resolve(
                &tree,
                &tree.root,
                "git --no-pager -c core.pager=cat -C repo restore -- f"
            ),
            Some(repo.clone())
        );
        // Only a literal path is followed.
        assert_eq!(
            resolve(&tree, &tree.root, "git -C \"$REPO\" restore -- f"),
            None
        );
        // Re-pointing git without moving the shell is not modelled.
        for command in [
            "git --git-dir=repo/.git restore -- f",
            "git --work-tree repo restore -- f",
            "git --namespace=x restore -- f",
            "git $OPT -C repo restore -- f",
            "git -c",
            "git -C",
            "git restore -- f && git --work-tree=other status",
        ] {
            assert_eq!(resolve(&tree, &tree.root, command), None, "{command}");
        }
        // Options after the subcommand are arguments, not repository moves.
        assert_eq!(
            resolve(
                &tree,
                &tree.path("other"),
                "git restore --source=HEAD -- f && git log --no-pager"
            ),
            Some(tree.path("other"))
        );
    }

    #[test]
    fn recovery_cwd_directory_change_after_the_match_is_not_a_probe_location() {
        // A cd after the match never moves the probe (it runs after the
        // guarded call) — and because the whole line runs once allowed, it
        // closes the window entirely rather than being ignored; see
        // `recovery_cwd_directory_change_after_the_match_fails_closed`.
        let tree = Tree::new("cd-after");
        let base = tree.path("other");
        assert_ne!(
            resolve(&tree, &base, "git restore -- f.txt && cd ../repo"),
            Some(tree.path("repo"))
        );
        assert_ne!(
            resolve(
                &tree,
                &tree.root,
                "cd repo && git restore -- f && cd ../other"
            ),
            Some(tree.path("other"))
        );
    }

    #[test]
    fn recovery_cwd_fails_closed_on_subshell_separators() {
        // A background `&` or a pipe `|` runs the `cd` side in a subshell, so
        // it never reaches the shell that runs the guarded git command. These
        // must not resolve to the `cd` target (which would open recovery
        // against a repo the git call does not run in).
        let tree = Tree::new("subshell");
        for command in [
            "cd repo & git restore -- f",
            "cd repo | git restore -- f",
            "cd repo |& git restore -- f",
            "true | cd repo && git restore -- f",
            "git restore -- f | tee log",
        ] {
            assert_eq!(resolve(&tree, &tree.root, command), None, "{command}");
        }
        // `&&`, `||`, `;`, and the `&` of a redirection are NOT subshell
        // separators, so the detector leaves them resolvable.
        for ok in [
            "cd repo && git restore -- f",
            "cd repo || exit; git restore -- f",
            "git restore -- f 2>&1",
            "git restore -- f >out 2>&1",
            "git restore -- f <&0",
        ] {
            assert!(
                !command_has_subshell_separator(ok),
                "must not be flagged as a subshell separator: {ok}"
            );
        }
        for flagged in ["a | b", "a |& b", "a & b", "cd x & git y"] {
            assert!(
                command_has_subshell_separator(flagged),
                "must be flagged: {flagged}"
            );
        }
        // `&&` isolated (not a lone `&`) plus a redirect `&` resolves normally.
        assert_eq!(
            resolve(&tree, &tree.root, "cd repo && git restore -- f 2>&1"),
            Some(tree.path("repo"))
        );
    }

    #[test]
    fn recovery_cwd_fails_closed_on_git_repo_env_assignments() {
        // GIT_DIR / GIT_WORK_TREE re-point git at another repository exactly
        // like --git-dir / --work-tree, so they must fail closed.
        let tree = Tree::new("git-env");
        for command in [
            "GIT_DIR=/other/.git git restore -- f",
            "GIT_WORK_TREE=/other git restore -- f",
            "GIT_DIR=/other/.git GIT_WORK_TREE=/other git restore -- f",
            "cd repo && GIT_DIR=/other/.git git restore -- f",
            "git restore -- f && GIT_DIR=/other/.git git restore -- g",
        ] {
            assert_eq!(resolve(&tree, &tree.root, command), None, "{command}");
        }
        // An ordinary env assignment (not repo-redirecting) still resolves.
        assert_eq!(
            resolve(&tree, &tree.root, "GIT_TRACE=1 cd repo && git restore -- f"),
            Some(tree.path("repo"))
        );
    }

    #[test]
    fn recovery_cwd_fails_closed_on_pushd_without_a_directory_change() {
        // `pushd -n <dir>` pushes without changing directory; a bare `pushd`
        // swaps the stack. Neither is an attributable cwd move.
        let tree = Tree::new("pushd");
        for command in [
            "pushd -n repo && git restore -- f",
            "pushd && git restore -- f",
            "pushd -n -- repo && git restore -- f",
        ] {
            assert_eq!(resolve(&tree, &tree.root, command), None, "{command}");
        }
        // A plain `pushd <dir>` is a real move and still resolves.
        assert_eq!(
            resolve(&tree, &tree.root, "pushd repo && git restore -- f"),
            Some(tree.path("repo"))
        );
    }

    #[test]
    fn recovery_cwd_fails_closed_on_unknowable_targets() {
        let tree = Tree::new("dynamic");
        for command in [
            "cd \"$REPO\" && git restore -- f",
            "cd $REPO && git restore -- f",
            "cd $(cat where) && git restore -- f",
            "cd `cat where` && git restore -- f",
            "cd ~someone && git restore -- f",
            "cd - && git restore -- f",
            "cd re* && git restore -- f",
            "cd repo other && git restore -- f",
            "popd && git restore -- f",
            "cd missing && git restore -- f",
            "cd repo && popd && git restore -- f",
            "$DO_CD repo && git restore -- f",
            "cd 'repo && git restore -- f",
            "(cd repo) && git restore -- f",
            "{ cd repo; } && git restore -- f",
            "cd repo && (git restore -- f)",
            "cd repo && git -C $SUB restore -- f",
        ] {
            assert_eq!(
                resolve(&tree, &tree.root, command),
                None,
                "command must not resolve: {command}"
            );
        }
    }

    #[test]
    fn recovery_cwd_substitution_cd_does_not_leak_into_outer_shell() {
        let tree = Tree::new("subst");
        // The `cd repo` runs inside `$( … )`; the outer shell never moves. The
        // unquoted `(` ahead of the match makes this fail closed rather than
        // resolve to `repo`.
        assert_eq!(
            resolve(
                &tree,
                &tree.root,
                "echo $(cd repo && pwd) && git restore -- f"
            ),
            None
        );
    }

    #[test]
    fn recovery_cwd_without_match_offset_requires_a_single_git_segment() {
        let tree = Tree::new("no-offset");
        let home = tree.home();
        let unanchored = |base: &Path, command: &str| {
            resolve_recovery_cwd_with_home(base, command, None, ShellDialect::Posix, Some(&home))
        };
        // No directory change: the base stands.
        assert_eq!(
            unanchored(&tree.path("other"), "git restore -- f"),
            Some(tree.path("other"))
        );
        // One git segment: the cd is attributed to it.
        assert_eq!(
            unanchored(&tree.root, "cd repo && git restore -- f"),
            Some(tree.path("repo"))
        );
        // Two git segments with a cd between them: ambiguous, fail closed.
        assert_eq!(
            unanchored(
                &tree.root,
                "cd repo && git status && cd ../other && git restore -- f"
            ),
            None
        );
        // A cd with no git segment at all: nothing attributable, fail closed.
        assert_eq!(unanchored(&tree.root, "cd repo && make restore"), None);
    }

    #[test]
    fn recovery_cwd_match_offset_between_segments_is_unattributable() {
        let tree = Tree::new("separator-offset");
        let command = "cd repo && git restore -- f";
        let separator = command.find("&&").unwrap();
        assert_eq!(
            resolve_recovery_cwd_with_home(
                &tree.root,
                command,
                Some(separator),
                ShellDialect::Posix,
                Some(&tree.home())
            ),
            None
        );
        // …unless nothing moves, in which case the base is still right.
        let plain = "echo hi && git restore -- f";
        assert_eq!(
            resolve_recovery_cwd_with_home(
                &tree.root,
                plain,
                Some(plain.find("&&").unwrap()),
                ShellDialect::Posix,
                Some(&tree.home())
            ),
            Some(tree.root.clone())
        );
    }

    #[test]
    fn recovery_cwd_non_posix_dialects_keep_the_base() {
        let tree = Tree::new("dialect");
        let base = tree.path("other");
        for dialect in [ShellDialect::PowerShell, ShellDialect::Cmd] {
            assert_eq!(
                resolve_recovery_cwd_with_home(
                    &base,
                    "cd ..\\repo; git restore -- f",
                    Some(14),
                    dialect,
                    Some(&tree.home())
                ),
                Some(base.clone()),
                "dialect {dialect:?}"
            );
        }
    }

    #[test]
    fn recovery_cwd_directory_change_after_the_match_fails_closed() {
        // The whole line runs once allowed; a later move could carry a
        // second guarded call into a repository the probe never saw.
        let tree = Tree::new("trailing-move");
        for command in [
            "cd repo && git restore -- f && cd ../other && git restore -- g",
            "git restore -- f && cd other",
            "git restore -- f; pushd other",
            "git restore -- f && popd",
            "git restore -- f && git -C other restore -- g",
            "git restore -- f && git --no-pager -C other status",
            // Anything that can run further commands may carry its own cd,
            // before or after the match.
            "git restore -- f && bash -c 'cd other && git restore -- g'",
            "bash -c 'cd other && git restore -- g' && git restore -- f",
            "git restore -- f | xargs -I{} git -C other restore -- {}",
            "eval 'cd other' && git restore -- f",
            "source ./enter-other.sh && git restore -- f",
            ". ./enter-other.sh && git restore -- f",
            "git restore -- f && ./finish.sh",
            "git restore -- f && make",
        ] {
            assert_eq!(resolve(&tree, &tree.root, command), None, "{command}");
        }
        // Later segments that do not move are fine.
        assert_eq!(
            resolve(
                &tree,
                &tree.root,
                "cd repo && git restore -- f && git status"
            ),
            Some(tree.path("repo"))
        );
    }

    #[test]
    fn recovery_cwd_grouping_anywhere_fails_closed() {
        let tree = Tree::new("trailing-group");
        for command in [
            "git restore -- f && (cd other && git restore -- g)",
            "git restore -- f; { cd other; git restore -- g; }",
        ] {
            assert_eq!(resolve(&tree, &tree.root, command), None, "{command}");
        }
        // Quoted or escaped parens are data, not grouping.
        assert_eq!(
            resolve(
                &tree,
                &tree.root,
                "git restore -- 'f (1).txt' && echo \\(done\\)"
            ),
            Some(tree.root.clone())
        );
    }

    #[test]
    fn recovery_cwd_match_on_a_non_git_segment_is_unattributable() {
        // A mis-mapped span offset landing on the cd segment must not apply
        // the moves before it and then probe there.
        let tree = Tree::new("non-git-segment");
        let command = "cd repo && cd ../other && git restore -- f";
        let home = tree.home();
        let on_second_cd = command.find("cd ../other").unwrap();
        assert_eq!(
            resolve_recovery_cwd_with_home(
                &tree.root,
                command,
                Some(on_second_cd),
                ShellDialect::Posix,
                Some(&home)
            ),
            None
        );
        // Bare transparent wrappers are seen through; an unknown wrapper is
        // an unknown executable and fails closed even when nothing moves.
        assert_eq!(
            resolve_recovery_cwd_with_home(
                &tree.path("other"),
                "sudo git restore -- f",
                Some(0),
                ShellDialect::Posix,
                Some(&home)
            ),
            Some(tree.path("other"))
        );
        assert_eq!(
            resolve_recovery_cwd_with_home(
                &tree.root,
                "cd repo && env GIT_TRACE=1 git restore -- f",
                Some(11),
                ShellDialect::Posix,
                Some(&home)
            ),
            Some(tree.path("repo"))
        );
        for command in ["doas git restore -- f", "sudo -u bob git restore -- f"] {
            assert_eq!(
                resolve_recovery_cwd_with_home(
                    &tree.path("other"),
                    command,
                    Some(0),
                    ShellDialect::Posix,
                    Some(&home)
                ),
                None,
                "{command}"
            );
        }
    }

    #[test]
    fn relaxed_allowlist_grants_exactly_the_recovery_rules() {
        use crate::allowlist::LayeredAllowlist;
        let relaxed = relaxed_allowlist(&LayeredAllowlist::default());
        for pattern in RECOVERY_PATTERNS {
            assert!(
                relaxed
                    .match_rule_at_path("core.git", pattern, None)
                    .is_some(),
                "{pattern} must be granted"
            );
        }
        for (pack, pattern) in [
            ("core.git", "reset-hard"),
            ("core.git", "clean-force"),
            ("core.git", "stash-drop"),
            ("core.filesystem", "rm-rf-general"),
        ] {
            assert!(
                relaxed.match_rule_at_path(pack, pattern, None).is_none(),
                "{pack}:{pattern} must NOT be granted"
            );
        }
    }

    #[test]
    fn recovery_cwd_public_entry_reads_home_from_environment() {
        // Smoke test for the public wrapper: no directory change, base back.
        let tree = Tree::new("public");
        let base = tree.path("other");
        assert_eq!(
            resolve_recovery_cwd(&base, "git restore -- f", Some(0), ShellDialect::Posix),
            Some(base)
        );
    }
}

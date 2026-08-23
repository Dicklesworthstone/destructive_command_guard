//! Core filesystem patterns - protections against destructive filesystem commands.
//!
//! This includes patterns for:
//! - recursive `rm` (`-r`/`-R`, with or without `-f`) outside temp directories
//! - bounded literal `/tmp` and `/var/tmp` recursive-removal exceptions
//! - equivalent destruction through `find -delete`, `unlink`, `truncate`, and
//!   archive/remove or cross-segment relocation primitives

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, Platform, SafePattern, Severity};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `rm -rf` on root/home paths pattern.
const RM_RF_ROOT_HOME_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview what files would be deleted before running",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
    PatternSuggestion::new(
        "rm -rf /tmp/<subdir>",
        "Scope deletion to a disposable temp path — dcg allows literal /tmp targets without confirmation",
    ),
    PatternSuggestion::gated(
        "rm -rf <specific-subdirectory>",
        "A specific non-temp path is safer than root/home but still a recursive delete, so it needs approval",
    ),
];

/// Suggestions for general `rm -rf` pattern.
const RM_RF_GENERAL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::with_platform(
        "trash-put {path}",
        "Move to trash instead of permanent deletion (requires trash-cli)",
        Platform::Linux,
    ),
    PatternSuggestion::with_platform(
        "gio trash {path}",
        "Move to trash via GNOME (requires gio)",
        Platform::Linux,
    ),
    PatternSuggestion::new(
        "mv {path} /tmp/delete-me-{timestamp}",
        "Move to a temp holding area instead of deleting immediately",
    ),
    PatternSuggestion::new(
        "rm -rf /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count files that would be deleted before proceeding",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "List directory contents to verify the path",
    ),
];

/// Suggestions for `rm -r -f` (separate flags) pattern.
const RM_R_F_SEPARATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm -ri {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "rm -r -f /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview files before deletion",
    ),
];

/// Suggestions for `rm --recursive --force` (long flags) pattern.
const RM_RECURSIVE_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "rm --interactive --recursive {path}",
        "Interactive mode: confirms each file before deletion",
    ),
    PatternSuggestion::new(
        "find {path} --maxdepth 2 -ls | head -30",
        "Preview directory structure before deletion",
    ),
    PatternSuggestion::new(
        "rm --recursive --force /tmp/{subdir}",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
];

/// Suggestions for `find ... -delete` patterns. `find -delete` is
/// bytewise-equivalent to `rm -rf` on the matching tree, so the suggestions
/// mirror the rm-rf ones.
const FIND_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "find {path} -type f | head -20",
        "Preview which files `-delete` would remove (drop the -delete flag)",
    ),
    PatternSuggestion::new(
        "find {path} -type f | wc -l",
        "Count files that would be deleted before proceeding",
    ),
    PatternSuggestion::new(
        "find /tmp/{subdir} -delete",
        "Safe temp directory deletion (allowed without confirmation)",
    ),
    PatternSuggestion::gated(
        "find {path} -print -delete",
        "If you must proceed: use -print to log every deletion",
    ),
];

/// Suggestions for `unlink` patterns. `unlink <file>` is the raw POSIX
/// unlink(2) — semantically equivalent to `rm <file>` on a single file.
/// On sensitive targets (`/etc/passwd`, `~/.ssh/...`) it is one-shot
/// destruction with no recovery.
const UNLINK_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("ls -la {path}", "Verify the path before unlinking"),
    PatternSuggestion::gated(
        "cp {path} {path}.bak && unlink {path}",
        "Make a backup first if you really must remove the original",
    ),
    PatternSuggestion::new(
        "unlink /tmp/{subdir}/scratch",
        "Safe temp-directory unlink (allowed without confirmation)",
    ),
    PatternSuggestion::with_platform(
        "trash-put {path}",
        "Move to trash instead of permanent unlink (requires trash-cli)",
        Platform::Linux,
    ),
];

/// Suggestions for `truncate` patterns. `truncate -s 0 <file>` zeros the
/// file in place — equivalent to deleting all content. `truncate -s -<N>`
/// shrinks the file by N bytes (data loss). Both are recoverable only
/// from backups.
const TRUNCATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::gated(
        "cp {path} {path}.bak && truncate -s 0 {path}",
        "Make a backup before zeroing the file",
    ),
    PatternSuggestion::new("wc -c {path}", "Check current size before shrinking"),
    PatternSuggestion::new(
        "truncate -s 0 /tmp/{subdir}/scratch",
        "Safe temp-directory truncate (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "head -c <N> {path} > /tmp/{subdir}/head && cp -f /tmp/{subdir}/head {path}",
        "Keep the first N bytes instead of dropping data blindly (write via a temp file)",
    ),
];

/// Suggestions for `shred` patterns. `shred -u <file>` overwrites then
/// unlinks; `shred -fzu` is the most aggressive form (force, zero-pass,
/// remove). Without `-u`/`--remove` the file is overwritten in place —
/// data is destroyed but the file persists.
const SHRED_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the path before shredding (no recovery)",
    ),
    PatternSuggestion::gated(
        "cp {path} {path}.bak && shred -u {path}",
        "Make a backup first if you might need the data",
    ),
    PatternSuggestion::new(
        "shred -u /tmp/{subdir}/scratch",
        "Safe temp-directory shred (allowed without confirmation)",
    ),
    PatternSuggestion::gated(
        "shred -n 1 -u {path}",
        "Single-pass shred is faster (and on SSDs, multi-pass adds little)",
    ),
];

/// Suggestions for `tar --remove-files` patterns. `tar --remove-files
/// -cf <archive> <source>` archives the source paths into <archive>,
/// then deletes the originals — bytewise-equivalent to `rm -rf <source>`
/// on the destination tree. The destruction trigger is the
/// `--remove-files` flag; without it tar only reads the source.
const TAR_REMOVE_FILES_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "tar -cf {path}.tar {path}",
        "Archive without --remove-files (sources are preserved)",
    ),
    PatternSuggestion::new(
        "tar -cf {path}.tar {path} && rm -ri {path}",
        "Archive first, then remove with confirmation prompts",
    ),
    PatternSuggestion::new(
        "tar --remove-files -cf out.tar /tmp/{subdir}",
        "Safe temp-directory archive + remove (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the source path before archive+delete",
    ),
];

/// Suggestions for `dd` overwrite patterns. `dd if=/dev/zero of=<file>`
/// or `dd if=/dev/urandom of=<file>` overwrites the file's contents in
/// place — equivalent to `truncate -s 0` followed by writing zeros/
/// garbage. Device-level dd (`of=/dev/sda`) is system.disk's territory.
const DD_OVERWRITE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the path before overwriting (no recovery)",
    ),
    PatternSuggestion::gated(
        "cp {path} {path}.bak && dd if=/dev/zero of={path} bs=1M count=10",
        "Make a backup first if you might need the data",
    ),
    PatternSuggestion::new(
        "dd if=/dev/zero of=/tmp/{subdir}/scratch bs=1M count=10",
        "Safe temp-directory dd (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "dd if={path} of=/dev/null",
        "Read-only dd: output discarded (useful for testing read speed)",
    ),
];

/// Suggestions for `mv` cross-segment bypass patterns. The bypass shape is
/// `mv /etc /tmp/x && rm -rf /tmp/x` — each segment is individually
/// allowed but together destroys `/etc`. Blocking on a sensitive source
/// (or destination) closes the first half of the chain.
const MV_SENSITIVE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("ls -la {path}", "Verify the source path before any move"),
    PatternSuggestion::new(
        "cp -a {path} {path}.bak",
        "Copy first (preserves the original) — verify the copy, then remove only after confirmation",
    ),
    PatternSuggestion::gated(
        "mv {path} {path}.deleted-YYYYMMDD",
        "In-place rename for soft-delete (no cross-segment hop, easy to undo) — any mv touching a sensitive path is still gated",
    ),
    PatternSuggestion::new(
        "mv /tmp/{subdir}/foo /tmp/{subdir}/bar",
        "Safe temp-directory rename (allowed without confirmation)",
    ),
];

/// Suggestions for `mv-dynamic-path`. Same shape as the sensitive-path set,
/// but the in-place rename stays ungated: with a *literal* path it is exactly
/// the escape from the dynamic-path denial (a literal non-sensitive rename is
/// allowed), so the gate marker would be wrong here.
const MV_DYNAMIC_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "ls -la {path}",
        "Resolve and verify the expanded path before any move",
    ),
    PatternSuggestion::new(
        "cp -a {path} {path}.bak",
        "Copy first (preserves the original) — verify the copy, then remove only after confirmation",
    ),
    PatternSuggestion::new(
        "mv {path} {path}.deleted-YYYYMMDD",
        "Use resolved literal paths for an in-place soft-delete rename",
    ),
    PatternSuggestion::new(
        "mv /tmp/{subdir}/foo /tmp/{subdir}/bar",
        "Safe temp-directory rename (allowed without confirmation)",
    ),
];

/// Suggestions for sensitive-source propagation chains. These commands first
/// propagate a sensitive path into a temp-family location, then delete that
/// temp tree in a later shell segment.
const SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "ls -la {path}",
        "Verify the sensitive source path before propagating it",
    ),
    PatternSuggestion::new(
        "cp -a {path} {path}.bak",
        "Keep the backup beside the original and verify it before any later deletion",
    ),
    PatternSuggestion::new(
        "diff -r {path} {path}.bak",
        "Compare the source and copy before considering removal",
    ),
    PatternSuggestion::new(
        "rm -ri /tmp/{subdir}",
        "Use interactive removal for temp trees derived from sensitive sources",
    ),
];

/// Suggestions for `redirect-truncate-*` patterns. Bash output redirects
/// (`>`, `>|`, `&>`, `1>`, `2>`) truncate the target file to zero bytes
/// before writing — the truncate-equivalent at the shell-syntax layer.
/// Append (`>>`) is non-destructive and not blocked.
const REDIRECT_TRUNCATE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new("ls -la {path}", "Verify the path before any redirect"),
    PatternSuggestion::new(
        "cp {path} {path}.bak && echo data > /tmp/{subdir}/out && cp -f /tmp/{subdir}/out {path}",
        "Back up the target, write the new content to a temp file, then copy it into place",
    ),
    PatternSuggestion::new(
        "echo data >> {path}",
        "Use append (>>) instead of truncate (>) to preserve existing content",
    ),
    PatternSuggestion::new(
        "echo data > /tmp/{subdir}/scratch",
        "Safe temp-directory redirect (allowed without confirmation)",
    ),
];
use crate::normalize::{
    NormalizeTokenKind, ShellDialect, ShellTokenDecoder, ShellTokenRole,
    tokenize_for_normalization, tokenize_for_shell_dialect,
};
use std::ops::Range;

const RM_RF_ROOT_HOME_NAME: &str = "rm-rf-root-home";
const RM_RF_ROOT_HOME_REASON: &str = "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.";
const RM_R_F_SEPARATE_ROOT_HOME_NAME: &str = "rm-r-f-separate-root-home";
const RM_R_F_SEPARATE_ROOT_HOME_REASON: &str =
    "rm with separate -r -f flags targeting root or home is EXTREMELY DANGEROUS.";
const RM_RECURSIVE_FORCE_ROOT_HOME_NAME: &str = "rm-recursive-force-root-home";
const RM_RECURSIVE_FORCE_ROOT_HOME_REASON: &str =
    "rm --recursive --force targeting root or home is EXTREMELY DANGEROUS.";
const RM_RF_GENERAL_NAME: &str = "rm-rf-general";
const RM_RF_GENERAL_REASON: &str = "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.";
const RM_R_F_SEPARATE_NAME: &str = "rm-r-f-separate";
const RM_R_F_SEPARATE_REASON: &str =
    "rm with separate -r -f flags is destructive and requires human approval.";
const RM_RECURSIVE_FORCE_NAME: &str = "rm-recursive-force-long";
const RM_RECURSIVE_FORCE_REASON: &str =
    "rm --recursive --force is destructive and requires human approval.";
const RM_RECURSIVE_ROOT_HOME_NAME: &str = "rm-recursive-root-home";
const RM_RECURSIVE_ROOT_HOME_REASON: &str = "recursive rm targeting a root, home, or absolute system path is EXTREMELY DANGEROUS, even without --force.";
const RM_RECURSIVE_GENERAL_NAME: &str = "rm-recursive-general";
const RM_RECURSIVE_GENERAL_REASON: &str = "recursive rm can silently remove an entire writable directory tree and requires human approval, even without --force.";
const RM_RECURSIVE_UNVERIFIED_NAME: &str = "rm-recursive-unverified";
const RM_RECURSIVE_UNVERIFIED_REASON: &str = "a dynamically resolved executable may be rm and is followed by recursive deletion syntax that cannot be verified safe before shell expansion.";
const POWERSHELL_REMOVE_ITEM_RECURSIVE_NAME: &str = "powershell-remove-item-recursive";
const POWERSHELL_REMOVE_ITEM_RECURSIVE_REASON: &str = "PowerShell Remove-Item (or an alias) with -Recurse permanently deletes an entire item tree without using the Recycle Bin.";

pub(crate) fn is_pre_rm_propagation_rule(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "cp-sensitive-then-delete"
                | "ln-symlink-sensitive-then-delete"
                | "rsync-sensitive-then-delete"
                // A semantically safe rm must not shadow destruction caused
                // by a redirect in the same shell segment. Keep these ahead
                // of the rm Allow fast path as well.
                | "redirect-truncate-root-home"
                | "redirect-truncate-dynamic-path"
        )
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteKind {
    None,
    Single,
    Double,
}

#[derive(Debug, Clone)]
pub(crate) struct RmParseMatch {
    pub(crate) pattern_name: &'static str,
    pub(crate) reason: &'static str,
    pub(crate) severity: Severity,
    pub(crate) span: Option<Range<usize>>,
}

#[derive(Debug, Clone)]
pub(crate) enum RmParseDecision {
    Allow,
    Deny(RmParseMatch),
    NoMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RmExecutableCertainty {
    Exact,
    MayBeRm,
    Other,
}

#[derive(Debug)]
struct PathToken<'a> {
    unquoted: &'a str,
    quote: QuoteKind,
    range: Range<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmFlagStyle {
    Combined,
    Separate,
    Long,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RmInteractiveMode {
    #[default]
    Default,
    Never,
    Once,
    Always,
}

impl RmInteractiveMode {
    const fn prompts(self) -> bool {
        matches!(self, Self::Once | Self::Always)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RmFlagState {
    force_style: Option<RmFlagStyle>,
    recursive_span: Option<Range<usize>>,
    span: Option<Range<usize>>,
    saw_terminator: bool,
    interactive_mode: RmInteractiveMode,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct RmFlagTracker {
    combined_span: Option<Range<usize>>,
    seen_short_recursive: bool,
    short_recursive_span: Option<Range<usize>>,
    seen_short_force: bool,
    short_force_span: Option<Range<usize>>,
    seen_long_recursive: bool,
    long_recursive_span: Option<Range<usize>>,
    seen_long_force: bool,
    long_force_span: Option<Range<usize>>,
    saw_terminator: bool,
    interactive_mode: RmInteractiveMode,
}

impl RmFlagTracker {
    fn resolve(self) -> Option<RmFlagState> {
        let recursive_span = self
            .short_recursive_span
            .clone()
            .or_else(|| self.long_recursive_span.clone());
        recursive_span.as_ref()?;

        let saw_force = self.seen_short_force || self.seen_long_force;
        let force_style = if !saw_force {
            None
        } else if self.combined_span.is_some() {
            Some(RmFlagStyle::Combined)
        } else if self.seen_long_recursive && self.seen_long_force {
            Some(RmFlagStyle::Long)
        } else {
            // This also covers mixed short/long forms such as
            // `rm -r --force` and `rm --recursive -f`.
            Some(RmFlagStyle::Separate)
        };

        let span = self
            .combined_span
            .or_else(|| recursive_span.clone())
            .or(self.short_force_span)
            .or(self.long_force_span);

        Some(RmFlagState {
            force_style,
            recursive_span,
            span,
            saw_terminator: self.saw_terminator,
            interactive_mode: self.interactive_mode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmLongOption {
    Dir,
    Force,
    Help,
    Interactive,
    NoPreserveRoot,
    OneFileSystem,
    PreserveRoot,
    PresumeInputTty,
    Recursive,
    Verbose,
    Version,
}

const RM_LONG_OPTIONS: &[(&str, RmLongOption)] = &[
    ("dir", RmLongOption::Dir),
    ("force", RmLongOption::Force),
    ("help", RmLongOption::Help),
    ("interactive", RmLongOption::Interactive),
    ("no-preserve-root", RmLongOption::NoPreserveRoot),
    ("one-file-system", RmLongOption::OneFileSystem),
    ("preserve-root", RmLongOption::PreserveRoot),
    ("presume-input-tty", RmLongOption::PresumeInputTty),
    ("recursive", RmLongOption::Recursive),
    ("verbose", RmLongOption::Verbose),
    ("version", RmLongOption::Version),
];

fn resolve_rm_long_option(name: &str) -> Option<RmLongOption> {
    if let Some((_, option)) = RM_LONG_OPTIONS
        .iter()
        .find(|(candidate, _)| *candidate == name)
    {
        return Some(*option);
    }

    let mut matches = RM_LONG_OPTIONS
        .iter()
        .filter(|(candidate, _)| candidate.starts_with(name))
        .map(|(_, option)| *option);
    let option = matches.next()?;
    matches.next().is_none().then_some(option)
}

fn parse_rm_interactive_mode(value: &str) -> Option<RmInteractiveMode> {
    if value.is_empty() {
        return None;
    }

    let candidates = [
        ("never", RmInteractiveMode::Never),
        ("no", RmInteractiveMode::Never),
        ("none", RmInteractiveMode::Never),
        ("once", RmInteractiveMode::Once),
        ("always", RmInteractiveMode::Always),
        ("yes", RmInteractiveMode::Always),
    ];
    let mut resolved = None;
    for (candidate, mode) in candidates {
        if candidate.starts_with(value) {
            if resolved.is_some_and(|existing| existing != mode) {
                return None;
            }
            resolved = Some(mode);
        }
    }
    resolved
}

pub(crate) fn parse_rm_command(command: &str) -> RmParseDecision {
    let segments = crate::packs::split_command_segments(command);
    if segments.len() > 1 {
        let mut saw_allow = false;
        for segment in segments {
            let command_start = command.as_ptr() as usize;
            let segment_start = segment.as_ptr() as usize;
            let automated_stdin = segment_start
                .checked_sub(command_start)
                .is_some_and(|offset| {
                    rm_segment_receives_automated_stdin(command, offset, ShellDialect::Posix)
                });
            match parse_rm_command_segment(segment, automated_stdin) {
                RmParseDecision::Deny(hit) => return RmParseDecision::Deny(hit),
                RmParseDecision::Allow => saw_allow = true,
                RmParseDecision::NoMatch => {}
            }
        }

        return if saw_allow {
            RmParseDecision::Allow
        } else {
            RmParseDecision::NoMatch
        };
    }

    parse_rm_command_segment(command, false)
}

/// Return whether an rm invocation at `segment_start` can read answers from a
/// non-terminal source inherited from the surrounding shell program.
///
/// A command-local redirect is handled by the rm argv parser itself. This
/// helper covers provenance that is invisible in an isolated segment: direct
/// pipeline input, a pipeline feeding an enclosing POSIX brace/subshell group,
/// and a prior `exec 0<...` redirection that persists in the current shell.
/// Unknown callers use the conservative POSIX model; PowerShell/Cmd retain the
/// direct-pipeline behavior while their richer stream semantics are handled by
/// their dialect-specific parsers.
pub(crate) fn rm_segment_receives_automated_stdin(
    command: &str,
    segment_start: usize,
    dialect: ShellDialect,
) -> bool {
    let Some(prefix) = command.get(..segment_start) else {
        return false;
    };
    let prefix = prefix.trim_end();
    if prefix.ends_with("|&") || (prefix.ends_with('|') && !prefix.ends_with("||")) {
        return true;
    }

    if !matches!(dialect, ShellDialect::Posix | ShellDialect::Unknown) {
        return false;
    }

    posix_pipeline_group_is_active(command, segment_start)
        || prior_posix_exec_redirects_stdin(command, segment_start)
}

#[derive(Debug, Clone, Copy)]
struct PosixGroupInput {
    close: PosixGroupClose,
    automated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PosixGroupClose {
    Byte(u8),
    Word(&'static str),
}

fn posix_pipeline_group_is_active(command: &str, segment_start: usize) -> bool {
    let bytes = command.as_bytes();
    let end = segment_start.min(bytes.len());
    let mut groups: Vec<PosixGroupInput> = Vec::new();
    let mut index = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut pipeline_pending = false;
    let mut at_command_start = true;
    let mut heredocs: Vec<(String, bool)> = Vec::new();

    while index < end {
        let byte = bytes[index];
        if byte == b'\\' && !in_single && index + 1 < end {
            index += 2;
            continue;
        }
        if byte == b'\'' && !in_double {
            in_single = !in_single;
            index += 1;
            continue;
        }
        if byte == b'"' && !in_single {
            in_double = !in_double;
            index += 1;
            continue;
        }
        if in_single || in_double {
            index += 1;
            continue;
        }

        if byte == b'#' && posix_comment_starts(bytes, index) {
            index = bytes[index..end]
                .iter()
                .position(|candidate| *candidate == b'\n')
                .map_or(end, |newline| index + newline);
            continue;
        }
        if byte == b'<'
            && bytes.get(index + 1) == Some(&b'<')
            && bytes.get(index + 2) != Some(&b'<')
        {
            if let Some((delimiter, strip_tabs, after)) =
                parse_posix_heredoc_delimiter(command, index, end)
            {
                heredocs.push((delimiter, strip_tabs));
                index = after;
                continue;
            }
        }

        match byte {
            b'|' if bytes.get(index + 1) == Some(&b'|') => {
                pipeline_pending = false;
                at_command_start = true;
                index += 2;
                continue;
            }
            b'|' => {
                pipeline_pending = true;
                at_command_start = true;
                index += 1 + usize::from(bytes.get(index + 1) == Some(&b'&'));
                continue;
            }
            b'&' if bytes.get(index + 1) == Some(&b'&') => {
                pipeline_pending = false;
                at_command_start = true;
                index += 2;
                continue;
            }
            b';' | b'&' => {
                pipeline_pending = false;
                at_command_start = true;
            }
            b'\n' => {
                pipeline_pending = false;
                at_command_start = true;
                if !heredocs.is_empty() {
                    index = skip_posix_heredoc_bodies(command, index + 1, end, &mut heredocs);
                    continue;
                }
            }
            b'(' | b'{' => {
                let inherited =
                    pipeline_pending || groups.last().is_some_and(|group| group.automated);
                groups.push(PosixGroupInput {
                    close: PosixGroupClose::Byte(if byte == b'(' { b')' } else { b'}' }),
                    automated: inherited,
                });
                pipeline_pending = false;
                at_command_start = true;
            }
            b')' | b'}' => {
                if groups
                    .last()
                    .is_some_and(|group| group.close == PosixGroupClose::Byte(byte))
                {
                    groups.pop();
                }
                pipeline_pending = false;
                at_command_start = false;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let word_end = bytes[index..end]
                    .iter()
                    .position(|candidate| !candidate.is_ascii_alphanumeric() && *candidate != b'_')
                    .map_or(end, |offset| index + offset);
                let word = &command[index..word_end];
                if at_command_start {
                    if groups.last().is_some_and(|group| {
                        matches!(group.close, PosixGroupClose::Word(close) if close == word)
                    }) {
                        groups.pop();
                        pipeline_pending = false;
                        at_command_start = false;
                    } else if let Some(close) = posix_compound_close_word(word) {
                        let inherited = pipeline_pending
                            || groups.last().is_some_and(|group| group.automated);
                        groups.push(PosixGroupInput {
                            close: PosixGroupClose::Word(close),
                            automated: inherited,
                        });
                        pipeline_pending = false;
                        at_command_start = false;
                    } else if matches!(word, "do" | "then" | "else" | "elif") {
                        pipeline_pending = false;
                        at_command_start = true;
                    } else {
                        pipeline_pending = false;
                        at_command_start = false;
                    }
                }
                index = word_end;
                continue;
            }
            byte if !byte.is_ascii_whitespace() => {
                pipeline_pending = false;
                at_command_start = false;
            }
            _ => {}
        }
        index += 1;
    }

    groups.iter().any(|group| group.automated)
}

fn posix_compound_close_word(word: &str) -> Option<&'static str> {
    match word {
        "while" | "until" | "for" | "select" => Some("done"),
        "if" => Some("fi"),
        "case" => Some("esac"),
        _ => None,
    }
}

fn posix_comment_starts(bytes: &[u8], index: usize) -> bool {
    index == 0
        || bytes.get(index.wrapping_sub(1)).is_some_and(|previous| {
            previous.is_ascii_whitespace() || matches!(previous, b';' | b'|' | b'&' | b'(' | b'{')
        })
}

fn parse_posix_heredoc_delimiter(
    command: &str,
    operator_start: usize,
    end: usize,
) -> Option<(String, bool, usize)> {
    let bytes = command.as_bytes();
    let mut index = operator_start + 2;
    let strip_tabs = bytes.get(index) == Some(&b'-');
    index += usize::from(strip_tabs);
    while index < end && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    let start = index;
    let mut quote = None;
    let mut delimiter = String::new();
    while index < end {
        let byte = bytes[index];
        if quote.is_none() && (byte.is_ascii_whitespace() || matches!(byte, b';' | b'|' | b'&')) {
            break;
        }
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            } else {
                delimiter.push(char::from(byte));
            }
        } else if byte == b'\\' && quote != Some(b'\'') && index + 1 < end {
            index += 1;
            delimiter.push(char::from(bytes[index]));
        } else {
            delimiter.push(char::from(byte));
        }
        index += 1;
    }
    (!delimiter.is_empty() && index > start).then_some((delimiter, strip_tabs, index))
}

fn skip_posix_heredoc_bodies(
    command: &str,
    mut index: usize,
    end: usize,
    heredocs: &mut Vec<(String, bool)>,
) -> usize {
    while let Some((delimiter, strip_tabs)) = heredocs.first() {
        if index >= end {
            return end;
        }
        let line_end = command[index..end]
            .find('\n')
            .map_or(end, |offset| index + offset);
        let line = &command[index..line_end];
        let comparable = if *strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        index = (line_end + usize::from(line_end < end)).min(end);
        if comparable.trim_end_matches('\r') == delimiter {
            heredocs.remove(0);
        }
    }
    index
}

fn prior_posix_exec_redirects_stdin(command: &str, segment_start: usize) -> bool {
    let command_start = command.as_ptr() as usize;
    let target_scope = posix_subshell_scope_at(command, segment_start);
    let mut redirected = false;

    for segment in crate::packs::split_command_segments(command) {
        let pointer = segment.as_ptr() as usize;
        let Some(start) = pointer.checked_sub(command_start) else {
            continue;
        };
        let end = start.saturating_add(segment.len());
        if end > segment_start {
            continue;
        }
        if posix_exec_stdin_redirect_offset(segment).is_some_and(|exec_offset| {
            posix_subshell_scope_at(command, start.saturating_add(exec_offset)) == target_scope
        }) {
            redirected = true;
        }
    }

    redirected
}

fn posix_subshell_scope_at(command: &str, offset: usize) -> Vec<usize> {
    let bytes = command.as_bytes();
    let end = offset.min(bytes.len());
    let mut scopes = Vec::new();
    let mut index = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while index < end {
        let byte = bytes[index];
        if byte == b'\\' && !in_single && index + 1 < end {
            index += 2;
            continue;
        }
        if byte == b'\'' && !in_double {
            in_single = !in_single;
            index += 1;
            continue;
        }
        if byte == b'"' && !in_single {
            in_double = !in_double;
            index += 1;
            continue;
        }
        if in_single {
            index += 1;
            continue;
        }

        if byte == b'$' && bytes.get(index + 1) == Some(&b'(') {
            scopes.push(index);
            index += 2;
            continue;
        }
        if !in_double && byte == b'(' {
            scopes.push(index);
        } else if byte == b')' && !scopes.is_empty() {
            scopes.pop();
        }
        index += 1;
    }

    scopes
}

fn posix_exec_stdin_redirect_offset(original_segment: &str) -> Option<usize> {
    let segment = strip_leading_posix_group_openers(original_segment).0;
    let suffix_offset =
        (segment.as_ptr() as usize).checked_sub(original_segment.as_ptr() as usize)?;
    let tokens = tokenize_for_normalization(segment);
    let exec_index = tokens.iter().position(|token| {
        token.kind != NormalizeTokenKind::Separator
            && token
                .text(segment)
                .is_some_and(|word| rm_frontend_basename(strip_outer_quotes(word).1) == "exec")
    })?;

    // `exec` must be the command word, not data passed to another utility.
    if tokens[..exec_index].iter().any(|token| {
        token.kind != NormalizeTokenKind::Separator
            && token.text(segment).is_some_and(|word| {
                !crate::normalize::is_env_assignment(word)
                    && shell_redirection_prefix(word).is_none()
            })
    }) {
        return None;
    }

    let redirects = tokens.iter().skip(exec_index + 1).any(|token| {
        token.text(segment).is_some_and(|word| {
            shell_redirection_prefix(word).is_some_and(|redirect| redirect.redirects_stdin)
        })
    });
    redirects.then(|| suffix_offset.saturating_add(tokens[exec_index].byte_range.start))
}

pub(crate) fn parse_rm_command_segment(command: &str, pipeline_stdin: bool) -> RmParseDecision {
    let original = command;
    let (command, stripped_group_opener) = strip_leading_posix_group_openers(original);
    let (command, leading_stdin_redirect) = strip_leading_rm_prefixes(command);
    let stripped_leading_prefix = stripped_group_opener || command.as_ptr() != original.as_ptr();
    let (normalized, was_normalized) = normalize_rm_execution_frontends(command);
    let mut decision =
        parse_normalized_rm_command_segment(&normalized, pipeline_stdin || leading_stdin_redirect);
    if matches!(decision, RmParseDecision::NoMatch) {
        decision = parse_rm_argv_frontend(&normalized);
    }

    // Wrapper/path normalization changes byte offsets. A span into that
    // temporary string must never be reported as if it indexed the original
    // hook command.
    if was_normalized || stripped_leading_prefix {
        if let RmParseDecision::Deny(hit) = &mut decision {
            hit.span = None;
        }
    }

    decision
}

/// Parse one evaluator-proven command slice using the caller's shell dialect.
/// Exact rm invocations retain the established parser. A dynamic executable
/// that can resolve to `rm` is blocked only when the remaining argv is itself
/// recursive-deletion syntax.
pub(crate) fn parse_rm_command_segment_in_dialect(
    command: &str,
    pipeline_stdin: bool,
    dialect: ShellDialect,
) -> RmParseDecision {
    // A PowerShell assignment is an expression statement, not an executable
    // invocation. Treating its variable name as a dynamic command creates
    // false `rm-recursive-unverified` denials whenever the assigned value
    // happens to contain splatting-like data (for example a here-string
    // beginning with `@'`). Any executable `$()` content on the right-hand side
    // is evaluated separately by the outer evaluator before this segment scan.
    if dialect == ShellDialect::PowerShell && powershell_variable_assignment(command) {
        return RmParseDecision::NoMatch;
    }
    if dialect == ShellDialect::PowerShell {
        let powershell = parse_powershell_remove_item_segment(command, pipeline_stdin);
        if !matches!(powershell, RmParseDecision::NoMatch) {
            return powershell;
        }
    }
    if dialect == ShellDialect::Cmd {
        let cmd = parse_cmd_decoded_rm_segment(command, pipeline_stdin);
        if !matches!(cmd, RmParseDecision::NoMatch) {
            return cmd;
        }
    }

    let exact = parse_rm_command_segment(command, pipeline_stdin);
    if !matches!(exact, RmParseDecision::NoMatch) {
        return exact;
    }

    parse_unverified_rm_command_segment(command, pipeline_stdin, dialect)
}

fn powershell_variable_assignment(command: &str) -> bool {
    let Some(mut tail) = command.trim_start().strip_prefix('$') else {
        return false;
    };

    if let Some(braced) = tail.strip_prefix('{') {
        let Some(close) = braced.find('}') else {
            return false;
        };
        tail = &braced[close + 1..];
    } else {
        let variable_len = tail
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
            .count();
        if variable_len == 0 {
            return false;
        }
        tail = &tail[variable_len..];
    }

    let tail = tail.trim_start();
    ["=", "+=", "-=", "*=", "/=", "%="]
        .iter()
        .any(|operator| tail.starts_with(operator))
}

/// Tell the evaluator's keyword-index layer when caller-proven shell syntax
/// can hide the `rm`/`Remove-Item` command word from bytewise pack keywords.
/// The semantic parser must still make the final Allow/Deny decision; this is
/// only a conservative candidate-selection signal.
pub(crate) fn rm_semantic_scan_required(command: &str, dialect: ShellDialect) -> bool {
    match dialect {
        ShellDialect::PowerShell => {
            if !command.contains(['`', '@', '&', '$', '(']) {
                return false;
            }
            if command.contains('&') {
                // The call operator can execute a variable, subexpression, or
                // concatenation whose bytes contain no literal pack keyword.
                return true;
            }
            crate::packs::split_command_segments_in_dialect(command, dialect)
                .into_iter()
                .any(powershell_segment_requires_rm_semantic_scan)
        }
        ShellDialect::Cmd => {
            if !command.contains(['^', '%', '!']) {
                return false;
            }
            crate::packs::split_command_segments_in_dialect(command, dialect)
                .into_iter()
                .any(cmd_segment_requires_rm_semantic_scan)
        }
        ShellDialect::Posix => crate::packs::split_command_segments_in_dialect(command, dialect)
            .into_iter()
            .any(posix_segment_requires_rm_semantic_scan),
        ShellDialect::Unknown => {
            rm_semantic_scan_required(command, ShellDialect::Posix)
                || rm_semantic_scan_required(command, ShellDialect::PowerShell)
                || rm_semantic_scan_required(command, ShellDialect::Cmd)
        }
    }
}

fn posix_segment_requires_rm_semantic_scan(segment: &str) -> bool {
    if !segment.contains(['$', '`', '\'', '"', '\\', '*', '?', '[', '{']) {
        return false;
    }
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::Posix);
    let Some(raw) = tokens
        .iter()
        .find(|token| token.kind != NormalizeTokenKind::Separator)
        .and_then(|token| token.text(segment))
    else {
        return false;
    };
    let dynamic = rm_executable_certainty(raw, ShellDialect::Posix);
    if dynamic == RmExecutableCertainty::MayBeRm {
        return true;
    }
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
    decoder
        .decode(raw, ShellTokenRole::Syntax)
        .is_some_and(|decoded| rm_frontend_basename(decoded.as_ref()) == "rm")
}

/// Candidate-selection signal for every dialect-sensitive semantic owned by
/// core.filesystem. Evaluators should OR this with their ordinary keyword
/// index result before deciding to skip the pack.
pub(crate) fn filesystem_semantic_scan_required(command: &str, dialect: ShellDialect) -> bool {
    rm_semantic_scan_required(command, dialect)
        || (dialect == ShellDialect::Cmd
            && command.contains('>')
            && command.contains(['%', '!', '^']))
        // Fork-bomb reachability (issue #302): the `fork-bomb` rule matches a
        // shell function-definition shape (`name() { … }`). The paren pair is
        // pure syntax that keyword-based quick-reject cannot see, and POSIX
        // permits whitespace inside it (`name ( )`), so a literal `()` keyword
        // both costs a keyword slot and misses the spaced form. A space-
        // tolerant scan here forces core.filesystem to run whenever an empty
        // paren pair is present; the regex then does the precise matching.
        || command_contains_empty_paren_pair(command)
}

/// True when the command contains `(` followed by only ASCII whitespace and
/// then `)` — the empty parameter list of a shell function definition, the one
/// piece of the fork-bomb shape that carries no executable keyword.
fn command_contains_empty_paren_pair(command: &str) -> bool {
    let bytes = command.as_bytes();
    let mut index = 0usize;
    while let Some(open) = bytes[index..].iter().position(|&b| b == b'(') {
        let mut cursor = index + open + 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b')') {
            return true;
        }
        index = index + open + 1;
    }
    false
}

/// Refine the global substring index's candidate signal for core.filesystem.
///
/// The global index deliberately uses substring matching as a conservative
/// first pass. That makes its short keywords prone to unrelated hits: most
/// notably, `cp` appears at the end of both `scp` and `pscp`. Every
/// core.filesystem command pattern requires the corresponding executable name
/// at a regex word boundary, while every redirect pattern contains `>`.
/// Mirroring that necessary lexical condition here preserves a superset of the
/// pack's matches without cold-initializing the pack for unrelated commands.
pub(crate) fn filesystem_keyword_candidate(command: &str) -> bool {
    const COMMAND_WORDS: &[&str] = &[
        "rm", "find", "unlink", "truncate", "shred", "tar", "dd", "mv", "cp", "ln", "rsync",
    ];

    command.contains('>')
        || COMMAND_WORDS
            .iter()
            .any(|word| contains_ascii_command_word(command, word))
}

fn contains_ascii_command_word(command: &str, word: &str) -> bool {
    let bytes = command.as_bytes();
    let word_bytes = word.as_bytes();

    if word_bytes.is_empty() || bytes.len() < word_bytes.len() {
        return false;
    }

    bytes
        .windows(word_bytes.len())
        .enumerate()
        .any(|(start, candidate)| {
            candidate.eq_ignore_ascii_case(word_bytes)
                && (start == 0 || !is_ascii_regex_word(bytes[start - 1]))
                && bytes
                    .get(start + word_bytes.len())
                    .is_none_or(|byte| !is_ascii_regex_word(*byte))
        })
}

const fn is_ascii_regex_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn powershell_segment_requires_rm_semantic_scan(segment: &str) -> bool {
    let segment = segment.trim_start();
    if segment.starts_with('&') {
        return true;
    }
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::PowerShell);
    let Some(raw) = tokens
        .iter()
        .find(|token| token.kind != NormalizeTokenKind::Separator)
        .and_then(|token| token.text(segment))
    else {
        return false;
    };
    let mut decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
    decoder
        .decode(raw, ShellTokenRole::Syntax)
        .is_some_and(|decoded| powershell_remove_item_alias(decoded.as_ref()))
}

fn cmd_segment_requires_rm_semantic_scan(segment: &str) -> bool {
    let tokens = tokenize_for_shell_dialect(segment, ShellDialect::Cmd);
    let Some(raw) = tokens
        .iter()
        .find(|token| token.kind != NormalizeTokenKind::Separator)
        .and_then(|token| token.text(segment))
    else {
        return false;
    };
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Cmd);
    let Some(decoded) = decoder.decode(raw, ShellTokenRole::Syntax) else {
        return false;
    };
    matches!(
        rm_executable_certainty(decoded.as_ref(), ShellDialect::Cmd),
        RmExecutableCertainty::Exact | RmExecutableCertainty::MayBeRm
    )
}

fn parse_cmd_decoded_rm_segment(command: &str, automated_stdin: bool) -> RmParseDecision {
    if !command.contains('^') {
        return RmParseDecision::NoMatch;
    }
    let tokens = tokenize_for_shell_dialect(command, ShellDialect::Cmd);
    let Some((command_index, raw_executable)) =
        tokens.iter().enumerate().find_map(|(index, token)| {
            (token.kind != NormalizeTokenKind::Separator)
                .then(|| token.text(command).map(|word| (index, word)))
                .flatten()
        })
    else {
        return RmParseDecision::NoMatch;
    };
    let mut decoder = ShellTokenDecoder::new(ShellDialect::Cmd);
    let Some(executable) = decoder.decode(raw_executable, ShellTokenRole::Syntax) else {
        return RmParseDecision::NoMatch;
    };
    if rm_executable_certainty(executable.as_ref(), ShellDialect::Cmd)
        != RmExecutableCertainty::Exact
    {
        return RmParseDecision::NoMatch;
    }

    let mut candidate = String::from("rm");
    for token in tokens.iter().skip(command_index + 1) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }
        let Some(raw) = token.text(command) else {
            continue;
        };
        let word = if raw.starts_with('-') {
            decoder
                .decode(raw, ShellTokenRole::Syntax)
                .unwrap_or_else(|| raw.into())
        } else {
            std::borrow::Cow::Borrowed(raw)
        };
        candidate.push(' ');
        candidate.push_str(word.as_ref());
    }

    let mut decision = parse_normalized_rm_command_segment(&candidate, automated_stdin);
    if let RmParseDecision::Deny(hit) = &mut decision {
        hit.span = None;
    }
    decision
}

fn parse_unverified_rm_command_segment(
    command: &str,
    pipeline_stdin: bool,
    dialect: ShellDialect,
) -> RmParseDecision {
    let command = command.trim();
    let powershell_call_operator = dialect == ShellDialect::PowerShell
        && command
            .strip_prefix('&')
            .is_some_and(|suffix| !suffix.trim_start().is_empty());
    let command = if powershell_call_operator {
        command
            .strip_prefix('&')
            .map(str::trim_start)
            .unwrap_or(command)
    } else {
        command
    };
    let powershell_expression_argv = powershell_call_operator
        .then(|| powershell_call_expression_argv(command))
        .flatten();
    let (command, leading_stdin_redirect) = strip_leading_rm_prefixes(command);
    let normalized = strip_rm_dynamic_frontends(command);
    let tokens = tokenize_for_shell_dialect(&normalized, dialect);
    let Some(executable) = tokens
        .iter()
        .find(|token| token.kind != NormalizeTokenKind::Separator)
    else {
        return RmParseDecision::NoMatch;
    };
    let Some(raw_executable) = executable.text(&normalized) else {
        return RmParseDecision::NoMatch;
    };
    let certainty = rm_executable_certainty(raw_executable, dialect);
    let powershell_expression = powershell_call_operator
        && (powershell_expression_argv.is_some()
            || !powershell_call_target_is_static_literal(raw_executable));
    if certainty != RmExecutableCertainty::MayBeRm && !powershell_expression {
        return RmParseDecision::NoMatch;
    }
    let Some(argv) =
        powershell_expression_argv.or_else(|| normalized.get(executable.byte_range.end..))
    else {
        return RmParseDecision::NoMatch;
    };
    let candidate = format!("rm{argv}");
    let automated_stdin = pipeline_stdin || leading_stdin_redirect;
    let posix_decision = parse_normalized_rm_command_segment(&candidate, automated_stdin);
    let powershell_decision = (dialect == ShellDialect::PowerShell)
        .then(|| parse_powershell_remove_item_segment(&candidate, automated_stdin));
    if !matches!(posix_decision, RmParseDecision::Deny(_))
        && !powershell_decision.is_some_and(|decision| matches!(decision, RmParseDecision::Deny(_)))
    {
        return RmParseDecision::NoMatch;
    }

    rm_unverified_deny()
}

fn powershell_call_expression_argv(command: &str) -> Option<&str> {
    let command = command.trim_start();
    let bytes = command.as_bytes();
    let open = if bytes.first() == Some(&b'(') {
        0
    } else if bytes.starts_with(b"$(") {
        1
    } else {
        return None;
    };
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut index = open;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'`' && !in_single && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if byte == b'\'' && !in_double {
            in_single = !in_single;
            index += 1;
            continue;
        }
        if byte == b'"' && !in_single {
            in_double = !in_double;
            index += 1;
            continue;
        }
        if !in_single && !in_double {
            if byte == b'(' {
                depth += 1;
            } else if byte == b')' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return command.get(index + 1..);
                }
            }
        }
        index += 1;
    }
    None
}

fn powershell_call_target_is_static_literal(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.len() >= 2 {
        let first = raw.as_bytes()[0];
        let last = *raw.as_bytes().last().unwrap_or(&0);
        if first == b'\'' && last == b'\'' {
            return true;
        }
        if first == b'"' && last == b'"' {
            return !raw[1..raw.len() - 1].contains(['$', '`']);
        }
    }

    !raw.is_empty()
        && raw.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'\\' | b':')
        })
}

fn parse_powershell_remove_item_segment(command: &str, automated_stdin: bool) -> RmParseDecision {
    let command = command.trim();
    let command = command
        .strip_prefix('&')
        .map(str::trim_start)
        .filter(|suffix| !suffix.is_empty())
        .unwrap_or(command);
    let tokens = tokenize_for_shell_dialect(command, ShellDialect::PowerShell);
    let Some((command_index, executable)) = tokens.iter().enumerate().find_map(|(index, token)| {
        (token.kind != NormalizeTokenKind::Separator)
            .then(|| token.text(command).map(|word| (index, word)))
            .flatten()
    }) else {
        return RmParseDecision::NoMatch;
    };
    let mut decoder = ShellTokenDecoder::new(ShellDialect::PowerShell);
    let Some(executable) = decoder.decode(executable, ShellTokenRole::Syntax) else {
        return RmParseDecision::NoMatch;
    };
    if !powershell_remove_item_alias(executable.as_ref()) {
        return RmParseDecision::NoMatch;
    }

    let mut recurse = false;
    let mut what_if = false;
    let mut has_target = automated_stdin;
    // Pipeline-fed targets are invisible here, so they can never all be
    // proven literal temp subpaths (#285).
    let mut targets_are_literal_temp = !automated_stdin;
    let mut index = command_index + 1;
    while let Some(token) = tokens.get(index) {
        if token.kind == NormalizeTokenKind::Separator {
            let separator = token.text(command).unwrap_or_default();
            index += 1;
            if separator == "(" {
                // Parenthesized PowerShell expressions are evaluated and
                // supplied as a real argument (`-Path (Resolve-Path ...)`).
                // Their runtime value cannot be proven to stay inside a
                // literal temp directory.
                has_target = true;
                targets_are_literal_temp = false;
                continue;
            }
            if separator == ")" {
                continue;
            }
            break;
        }
        let Some(word) = token.text(command) else {
            index += 1;
            continue;
        };
        index += 1;

        if let Some(redirect) = shell_redirection_prefix(word) {
            if redirect.operator_end == word.trim_end().len()
                && tokens
                    .get(index)
                    .is_some_and(|target| target.kind != NormalizeTokenKind::Separator)
            {
                index += 1;
            }
            continue;
        }

        if word.starts_with('@') {
            // Splatting can inject both -Recurse and the target path, so the
            // invocation cannot be proven non-recursive from its raw argv.
            return rm_unverified_deny();
        }
        let syntax_role = if word.starts_with('-') || word == "--%" {
            ShellTokenRole::Syntax
        } else {
            ShellTokenRole::Data
        };
        let Some(decoded_word) = decoder.decode(word, syntax_role) else {
            continue;
        };
        let word = strip_outer_quotes(decoded_word.as_ref())
            .1
            .trim_end_matches(')');
        if word.is_empty() {
            continue;
        }
        if let Some(value) = powershell_switch_value(word, "recurse", 1, true) {
            recurse = value;
            continue;
        }
        if let Some(value) = powershell_switch_value(word, "whatif", 2, false) {
            what_if = value;
            continue;
        }
        if word.starts_with('-') {
            if let Some((_, value)) = word.split_once(':').filter(|(name, value)| {
                matches!(name.to_ascii_lowercase().as_str(), "-path" | "-literalpath")
                    && !value.is_empty()
            }) {
                has_target = true;
                targets_are_literal_temp &= windows_literal_user_temp_subpath(value);
            }
            continue;
        }
        has_target = true;
        targets_are_literal_temp &= windows_literal_user_temp_subpath(word);
    }

    if !recurse || !has_target {
        return RmParseDecision::NoMatch;
    }
    if what_if {
        return RmParseDecision::Allow;
    }
    if targets_are_literal_temp {
        // #285: every proven target is a literal per-user Windows temp
        // subpath — the same carve-out `rm -rf /tmp/<subpath>` gets. Dynamic
        // spellings such as `$env:TEMP\x` keep the `$TMPDIR` review policy.
        return RmParseDecision::Allow;
    }

    RmParseDecision::Deny(RmParseMatch {
        pattern_name: POWERSHELL_REMOVE_ITEM_RECURSIVE_NAME,
        reason: POWERSHELL_REMOVE_ITEM_RECURSIVE_REASON,
        severity: Severity::Critical,
        span: None,
    })
}

fn powershell_remove_item_alias(executable: &str) -> bool {
    ["remove-item", "rm", "ri", "del", "erase", "rd", "rmdir"]
        .iter()
        .any(|alias| executable.eq_ignore_ascii_case(alias))
}

fn powershell_switch_value(
    word: &str,
    canonical: &str,
    minimum_abbreviation: usize,
    unknown_value: bool,
) -> Option<bool> {
    let parameter = word.strip_prefix('-')?;
    let (name, value) = parameter
        .split_once(':')
        .map_or((parameter, None), |(name, value)| (name, Some(value)));
    let name = name.to_ascii_lowercase();
    if name.len() < minimum_abbreviation || !canonical.starts_with(&name) {
        return None;
    }

    Some(match value.map(str::to_ascii_lowercase).as_deref() {
        None | Some("$true" | "true" | "1") => true,
        Some("$false" | "false" | "0") => false,
        Some(_) => unknown_value,
    })
}

fn rm_unverified_deny() -> RmParseDecision {
    RmParseDecision::Deny(RmParseMatch {
        pattern_name: RM_RECURSIVE_UNVERIFIED_NAME,
        reason: RM_RECURSIVE_UNVERIFIED_REASON,
        severity: Severity::High,
        span: None,
    })
}

fn strip_rm_dynamic_frontends(command: &str) -> String {
    let mut current = command.to_string();
    for _ in 0..MAX_RM_EXECUTION_FRONTENDS {
        let stripped = crate::normalize::strip_wrapper_prefixes(&current)
            .normalized
            .into_owned();
        if stripped != current {
            current = stripped;
            continue;
        }
        let Some(suffix) = strip_rm_execution_frontend(&current) else {
            break;
        };
        current = suffix.to_string();
    }
    current
}

pub(crate) fn rm_executable_certainty(
    raw_executable: &str,
    dialect: ShellDialect,
) -> RmExecutableCertainty {
    let dynamic_pattern = match dialect {
        ShellDialect::Posix => symbolic_posix_executable_pattern(raw_executable),
        ShellDialect::PowerShell => symbolic_powershell_executable_pattern(raw_executable),
        ShellDialect::Cmd => symbolic_cmd_executable_pattern(raw_executable),
        ShellDialect::Unknown => symbolic_posix_executable_pattern(raw_executable)
            .or_else(|| symbolic_powershell_executable_pattern(raw_executable))
            .or_else(|| symbolic_cmd_executable_pattern(raw_executable)),
    };
    if let Some(pattern) = dynamic_pattern {
        return if wildcard_pattern_may_equal_rm(&pattern) {
            RmExecutableCertainty::MayBeRm
        } else {
            RmExecutableCertainty::Other
        };
    }

    let executable = strip_outer_quotes(raw_executable).1;
    if rm_frontend_basename(executable) == "rm" {
        RmExecutableCertainty::Exact
    } else {
        RmExecutableCertainty::Other
    }
}

const RM_DYNAMIC_WILDCARD: char = '\0';

fn wildcard_pattern_may_equal_rm(pattern: &str) -> bool {
    let target = "rm";
    let starts_dynamic = pattern.starts_with(RM_DYNAMIC_WILDCARD);
    let ends_dynamic = pattern.ends_with(RM_DYNAMIC_WILDCARD);
    let fragments: Vec<&str> = pattern
        .split(RM_DYNAMIC_WILDCARD)
        .filter(|fragment| !fragment.is_empty())
        .collect();
    let Some(first) = fragments.first() else {
        return true;
    };
    let Some(last) = fragments.last() else {
        return true;
    };
    if !starts_dynamic && !target.starts_with(first) {
        return false;
    }
    if !ends_dynamic && !target.ends_with(last) {
        return false;
    }

    let mut offset = 0usize;
    for fragment in fragments {
        let Some(relative) = target.get(offset..).and_then(|tail| tail.find(fragment)) else {
            return false;
        };
        offset += relative + fragment.len();
    }
    true
}

fn symbolic_posix_executable_pattern(raw: &str) -> Option<String> {
    let mut pattern = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut dynamic = false;

    while let Some(character) = chars.next() {
        if single_quoted {
            if character == '\'' {
                single_quoted = false;
            } else {
                pattern.push(character);
            }
            continue;
        }
        match character {
            '\'' if !double_quoted => single_quoted = true,
            '"' => double_quoted = !double_quoted,
            '\\' => {
                if let Some(literal) = chars.next() {
                    pattern.push(literal);
                }
            }
            '$' => {
                dynamic = true;
                pattern.push(RM_DYNAMIC_WILDCARD);
                skip_symbolic_expansion(&mut chars);
            }
            '`' => {
                dynamic = true;
                pattern.push(RM_DYNAMIC_WILDCARD);
                while let Some(inner) = chars.next() {
                    if inner == '\\' {
                        chars.next();
                    } else if inner == '`' {
                        break;
                    }
                }
            }
            _ => pattern.push(character),
        }
    }

    dynamic.then_some(pattern)
}

fn skip_symbolic_expansion(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(next) = chars.peek().copied() else {
        return;
    };
    match next {
        '{' => {
            chars.next();
            let mut depth = 1usize;
            for character in chars.by_ref() {
                match character {
                    '{' => depth += 1,
                    '}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        '(' => {
            chars.next();
            let mut depth = 1usize;
            for character in chars.by_ref() {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
        '\'' | '"' => {
            let quote = chars.next().unwrap_or(next);
            while let Some(character) = chars.next() {
                if character == '\\' {
                    chars.next();
                } else if character == quote {
                    break;
                }
            }
        }
        character if character.is_ascii_alphabetic() || character == '_' => {
            while chars
                .peek()
                .is_some_and(|character| character.is_ascii_alphanumeric() || *character == '_')
            {
                chars.next();
            }
        }
        _ => {
            chars.next();
        }
    }
}

fn symbolic_powershell_executable_pattern(raw: &str) -> Option<String> {
    let mut pattern = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut single_quoted = false;
    let mut double_quoted = false;
    let mut dynamic = false;

    while let Some(character) = chars.next() {
        if single_quoted {
            if character == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    pattern.push('\'');
                } else {
                    single_quoted = false;
                }
            } else {
                pattern.push(character);
            }
            continue;
        }
        match character {
            '\'' if !double_quoted => single_quoted = true,
            '"' => double_quoted = !double_quoted,
            '`' => {
                if let Some(literal) = chars.next() {
                    pattern.push(literal);
                }
            }
            '$' => {
                dynamic = true;
                pattern.push(RM_DYNAMIC_WILDCARD);
                skip_symbolic_expansion(&mut chars);
            }
            _ => pattern.push(character),
        }
    }

    dynamic.then_some(pattern)
}

fn symbolic_cmd_executable_pattern(raw: &str) -> Option<String> {
    let mut pattern = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    let mut dynamic = false;

    while let Some(character) = chars.next() {
        match character {
            '"' => {}
            '^' => {
                if let Some(literal) = chars.next() {
                    pattern.push(literal);
                }
            }
            delimiter @ ('%' | '!') => {
                let mut expansion = false;
                for inner in chars.by_ref() {
                    if inner == delimiter {
                        expansion = true;
                        break;
                    }
                }
                if expansion {
                    dynamic = true;
                    pattern.push(RM_DYNAMIC_WILDCARD);
                } else {
                    pattern.push(delimiter);
                }
            }
            _ => pattern.push(character),
        }
    }

    dynamic.then_some(pattern)
}

/// Return the executable-bearing suffix after POSIX assignment words and
/// leading redirections. These prefixes do not replace the command word, but
/// they must be removed before the bounded wrapper/path normalizer can see it.
fn strip_leading_rm_prefixes(command: &str) -> (&str, bool) {
    let tokens = tokenize_for_normalization(command);
    let mut index = 0usize;
    let mut saw_prefix = false;
    let mut stdin_redirect = false;

    while let Some(token) = tokens.get(index) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }
        let Some(text) = token.text(command) else {
            return (command, false);
        };
        if crate::normalize::is_env_assignment(text) {
            saw_prefix = true;
            index += 1;
            continue;
        }
        if shell_redirection_prefix(text).is_some() {
            saw_prefix = true;
            stdin_redirect |= starts_with_shell_stdin_redirection(text);
            index += 1;
            if shell_redirection_consumes_next_word(text) {
                let Some(target) = tokens.get(index) else {
                    return (command, stdin_redirect);
                };
                if target.kind == NormalizeTokenKind::Separator {
                    return (command, stdin_redirect);
                }
                index += 1;
            }
            continue;
        }
        break;
    }

    if !saw_prefix {
        return (command, false);
    }
    let Some(command_token) = tokens.get(index) else {
        return (command, stdin_redirect);
    };
    command
        .get(command_token.byte_range.start..)
        .map_or((command, stdin_redirect), |suffix| (suffix, stdin_redirect))
}

fn strip_leading_posix_group_openers(mut command: &str) -> (&str, bool) {
    let original = command;
    loop {
        command = command.trim_start();
        if let Some(suffix) = command.strip_prefix('(') {
            command = suffix;
            continue;
        }
        if let Some(suffix) = command.strip_prefix('{').filter(|suffix| {
            suffix
                .as_bytes()
                .first()
                .is_none_or(u8::is_ascii_whitespace)
        }) {
            command = suffix;
            continue;
        }
        if let Some(suffix) = ["do", "then", "else"].into_iter().find_map(|reserved| {
            command.strip_prefix(reserved).and_then(|suffix| {
                suffix
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_whitespace)
                    .then_some(suffix)
            })
        }) {
            command = suffix;
            continue;
        }
        break;
    }
    (command, command.as_ptr() != original.as_ptr())
}

#[derive(Debug, Clone, Copy)]
struct ShellRedirectionPrefix {
    operator_end: usize,
    redirects_stdin: bool,
}

fn shell_redirection_prefix(text: &str) -> Option<ShellRedirectionPrefix> {
    let leading = text.len().saturating_sub(text.trim_start().len());
    let input = text.get(leading..)?;
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut index = 0usize;
    let mut fd_is_stdin = true;
    if bytes[0].is_ascii_digit() {
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        fd_is_stdin = &input[..index] == "0";
    } else if bytes[0] == b'*' {
        index = 1;
        fd_is_stdin = false;
    } else if bytes[0] == b'{' {
        let close = bytes.iter().position(|byte| *byte == b'}')?;
        let name = input.get(1..close)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return None;
        }
        index = close + 1;
        fd_is_stdin = false;
    }

    let operator = input.get(index..)?;
    let operator_len = [
        "<<<", "<<-", "&>>", "<>", "<&", "<<", ">>", ">&", ">|", "&>", "<", ">",
    ]
    .into_iter()
    .find_map(|candidate| operator.starts_with(candidate).then_some(candidate.len()))?;
    let operator_text = operator.get(..operator_len)?;
    let redirects_stdin =
        fd_is_stdin && operator_text.starts_with('<') && !operator_text.starts_with("<>");

    Some(ShellRedirectionPrefix {
        operator_end: leading + index + operator_len,
        redirects_stdin,
    })
}

fn starts_with_shell_stdin_redirection(text: &str) -> bool {
    shell_redirection_prefix(text).is_some_and(|redirect| redirect.redirects_stdin)
}

fn shell_redirection_consumes_next_word(text: &str) -> bool {
    shell_redirection_prefix(text)
        .is_some_and(|redirect| redirect.operator_end == text.trim_end().len())
}

const MAX_RM_EXECUTION_FRONTENDS: usize = 16;

/// Repeatedly apply the shared wrapper/path normalizer and the small set of
/// POSIX launch frontends whose option arity is known here. The hard layer cap
/// prevents adversarial wrapper chains from turning parsing into unbounded
/// work.
fn normalize_rm_execution_frontends(command: &str) -> (String, bool) {
    let mut current = command.to_string();
    let mut changed = false;

    for _ in 0..MAX_RM_EXECUTION_FRONTENDS {
        let normalized = crate::normalize::normalize_command(&current).into_owned();
        if normalized != current {
            current = normalized;
            changed = true;
            continue;
        }

        let Some(suffix) = strip_rm_execution_frontend(&current) else {
            break;
        };
        current = suffix.to_string();
        changed = true;
    }

    (current, changed)
}

fn rm_frontend_word<'a>(
    command: &'a str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
) -> Option<&'a str> {
    let token = tokens.get(index)?;
    (token.kind != NormalizeTokenKind::Separator)
        .then(|| token.text(command))
        .flatten()
        .map(|text| strip_outer_quotes(text).1)
}

fn rm_frontend_suffix<'a>(
    command: &'a str,
    tokens: &[crate::normalize::NormalizeToken],
    index: usize,
) -> Option<&'a str> {
    let token = tokens.get(index)?;
    (token.kind != NormalizeTokenKind::Separator)
        .then(|| command.get(token.byte_range.start..))
        .flatten()
}

fn rm_frontend_basename(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

fn strip_rm_execution_frontend(command: &str) -> Option<&str> {
    crate::normalize::strip_posix_execution_frontend(command).map(|(remaining, _)| remaining)
}

fn parse_rm_argv_frontend(command: &str) -> RmParseDecision {
    let tokens = tokenize_for_normalization(command);
    let Some(executable) = rm_frontend_word(command, &tokens, 0) else {
        return RmParseDecision::NoMatch;
    };
    match rm_frontend_basename(executable) {
        "xargs" => {
            let Some(command_index) = xargs_command_index(command, &tokens) else {
                return RmParseDecision::NoMatch;
            };
            let Some(child) = rm_frontend_suffix(command, &tokens, command_index) else {
                return RmParseDecision::NoMatch;
            };
            // Input items are appended to INITIAL-ARGS. Model both a recursive
            // option and a non-temp operand so untrusted input cannot supply
            // either half of a destructive rm invocation unnoticed. An
            // explicit child `--` still correctly prevents option injection.
            parse_nested_rm_execution(child, " -r ./__dcg_xargs_input__")
        }
        "find" => parse_find_exec_rm_actions(command, &tokens),
        _ => RmParseDecision::NoMatch,
    }
}

fn xargs_command_index(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
) -> Option<usize> {
    let mut index = 1usize;
    while let Some(word) = rm_frontend_word(command, tokens, index) {
        if word == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if matches!(word, "--help" | "--version") {
            return None;
        }
        if matches!(
            word,
            "-0" | "--null"
                | "-o"
                | "--open-tty"
                | "-p"
                | "--interactive"
                | "-r"
                | "--no-run-if-empty"
                | "-t"
                | "--verbose"
                | "-x"
                | "--exit"
                | "--show-limits"
        ) {
            index += 1;
            continue;
        }
        if matches!(
            word,
            "-a" | "--arg-file"
                | "-d"
                | "--delimiter"
                | "-E"
                | "-I"
                | "-L"
                | "-n"
                | "-P"
                | "-s"
                | "--max-lines"
                | "--max-args"
                | "--max-procs"
                | "--max-chars"
                | "--process-slot-var"
        ) {
            index = index.checked_add(2)?;
            continue;
        }
        if [
            "--arg-file=",
            "--delimiter=",
            "--eof=",
            "--replace=",
            "--max-lines=",
            "--max-args=",
            "--max-procs=",
            "--max-chars=",
            "--process-slot-var=",
        ]
        .iter()
        .any(|prefix| {
            word.strip_prefix(prefix)
                .is_some_and(|value| !value.is_empty())
        }) {
            index += 1;
            continue;
        }
        if matches!(word, "-e" | "-i" | "-l" | "--eof" | "--replace") {
            index += 1;
            continue;
        }
        if let Some(short) = word.strip_prefix('-').filter(|short| !short.is_empty()) {
            let bytes = short.as_bytes();
            let mut position = 0usize;
            let mut consume_next = false;
            while position < bytes.len() {
                match bytes[position] {
                    b'0' | b'o' | b'p' | b'r' | b't' | b'x' => position += 1,
                    b'e' | b'i' | b'l' => {
                        // Optional short-option values must be attached.
                        position = bytes.len();
                    }
                    b'a' | b'd' | b'E' | b'I' | b'L' | b'n' | b'P' | b's' => {
                        consume_next = position + 1 == bytes.len();
                        position = bytes.len();
                    }
                    _ => return None,
                }
            }
            index = index.checked_add(1 + usize::from(consume_next))?;
            continue;
        }
        return Some(index);
    }
    None
}

fn parse_nested_rm_execution(command: &str, synthetic_suffix: &str) -> RmParseDecision {
    let (command, stdin_redirect) = strip_leading_rm_prefixes(command);
    let (normalized, _) = normalize_rm_execution_frontends(command);
    let candidate = format!("{normalized}{synthetic_suffix}");
    let mut decision = parse_normalized_rm_command_segment(&candidate, stdin_redirect);
    if matches!(decision, RmParseDecision::NoMatch) {
        decision =
            parse_unverified_rm_command_segment(&candidate, stdin_redirect, ShellDialect::Posix);
    }
    if let RmParseDecision::Deny(hit) = &mut decision {
        hit.span = None;
    }
    decision
}

fn find_exec_terminator(word: &str) -> bool {
    let word = strip_outer_quotes(word).1;
    matches!(word, ";" | r"\;" | "+")
}

fn parse_find_exec_rm_actions(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
) -> RmParseDecision {
    let mut index = 1usize;
    while index < tokens.len() {
        let Some(word) = rm_frontend_word(command, tokens, index) else {
            index += 1;
            continue;
        };
        if !matches!(word, "-exec" | "-execdir") {
            index += 1;
            continue;
        }

        let child_start = index + 1;
        let mut terminator = child_start;
        while terminator < tokens.len() {
            let Some(candidate) = rm_frontend_word(command, tokens, terminator) else {
                break;
            };
            if find_exec_terminator(candidate) {
                break;
            }
            terminator += 1;
        }
        if child_start >= terminator || terminator >= tokens.len() {
            return RmParseDecision::NoMatch;
        }
        let Some(start) = tokens.get(child_start).map(|token| token.byte_range.start) else {
            return RmParseDecision::NoMatch;
        };
        let Some(end) = tokens
            .get(terminator.saturating_sub(1))
            .map(|token| token.byte_range.end)
        else {
            return RmParseDecision::NoMatch;
        };
        let Some(child) = command.get(start..end) else {
            return RmParseDecision::NoMatch;
        };
        let child_tokens = &tokens[child_start..terminator];
        if let Some(executable) = child_tokens.first().and_then(|token| token.text(command)) {
            let mut decoder = ShellTokenDecoder::new(ShellDialect::Posix);
            let executable = decoder
                .decode(executable, ShellTokenRole::Syntax)
                .unwrap_or_else(|| executable.into());
            if executable.contains("{}") {
                let argv = child_tokens
                    .first()
                    .and_then(|token| command.get(token.byte_range.end..end))
                    .unwrap_or_default();
                let candidate = format!("rm{argv}");
                if matches!(
                    parse_normalized_rm_command_segment(&candidate, false),
                    RmParseDecision::Deny(_)
                ) {
                    return rm_unverified_deny();
                }
            }
        }
        if let RmParseDecision::Deny(hit) = parse_nested_rm_execution(child, "") {
            return RmParseDecision::Deny(hit);
        }
        index = terminator + 1;
    }
    RmParseDecision::NoMatch
}

fn parse_normalized_rm_command_segment(command: &str, automated_stdin: bool) -> RmParseDecision {
    let tokens = tokenize_for_normalization(command);
    if tokens.is_empty() {
        return RmParseDecision::NoMatch;
    }

    let mut i = 0;
    while i < tokens.len() {
        let current = &tokens[i];
        if current.kind == NormalizeTokenKind::Separator {
            i += 1;
            continue;
        }

        let Some(text) = current.text(command) else {
            i += 1;
            continue;
        };

        if text == "rm" {
            return parse_rm_segment(command, &tokens, i + 1, automated_stdin);
        }

        // Skip to the next separator before scanning for another command word.
        i += 1;
        while i < tokens.len() && tokens[i].kind != NormalizeTokenKind::Separator {
            i += 1;
        }
    }

    RmParseDecision::NoMatch
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmOptionScanning {
    /// GNU `getopt_long` permutes options that follow operands.
    GnuPermuted,
    /// Apple/BSD `getopt` stops permanently at the first non-option operand.
    AppleStopAtFirstOperand,
}

fn parse_rm_segment(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start_idx: usize,
    automated_stdin: bool,
) -> RmParseDecision {
    let gnu = parse_rm_segment_with_option_scanning(
        command,
        tokens,
        start_idx,
        automated_stdin,
        RmOptionScanning::GnuPermuted,
    );
    let apple = parse_rm_segment_with_option_scanning(
        command,
        tokens,
        start_idx,
        automated_stdin,
        RmOptionScanning::AppleStopAtFirstOperand,
    );

    // Preserve the established GNU rule identity when both platforms delete,
    // but deny if either supported argv grammar can remove a tree. In
    // particular, GNU treats a trailing `--help` or `-i` as an option, while
    // Apple/BSD treats it as another operand after the first path and may have
    // already deleted the preceding recursive target.
    if matches!(&gnu, RmParseDecision::Deny(_)) {
        return gnu;
    }
    if matches!(&apple, RmParseDecision::Deny(_)) {
        return apple;
    }
    if matches!(gnu, RmParseDecision::Allow) || matches!(apple, RmParseDecision::Allow) {
        RmParseDecision::Allow
    } else {
        RmParseDecision::NoMatch
    }
}

#[allow(clippy::too_many_lines)]
fn parse_rm_segment_with_option_scanning(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start_idx: usize,
    automated_stdin: bool,
    option_scanning: RmOptionScanning,
) -> RmParseDecision {
    let mut options_ended = false;
    let mut flags = RmFlagTracker::default();
    let mut paths: Vec<PathToken<'_>> = Vec::new();
    let mut token_index = start_idx;

    while let Some(token) = tokens.get(token_index) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }

        let Some(text) = token.text(command) else {
            token_index += 1;
            continue;
        };
        token_index += 1;

        // Shell redirections are not argv entries for rm. Consume a detached
        // redirect target together with its operator; evaluator preserves and
        // attributes destructive redirects through its dedicated redirect
        // view before honoring a semantic rm Allow decision.
        if shell_redirection_prefix(text).is_some() {
            if shell_redirection_consumes_next_word(text)
                && tokens
                    .get(token_index)
                    .is_some_and(|target| target.kind != NormalizeTokenKind::Separator)
            {
                token_index += 1;
            }
            continue;
        }

        // A subshell close is shell syntax even when it is lexically glued to
        // the final argv word (`(rm -ri ./tree)`). Remove only unquoted trailing
        // `)` operators; quoted/escaped parentheses remain ordinary operands.
        let text = if token_index == tokens.len() && text.ends_with(')') {
            text.trim_end_matches(')')
        } else {
            text
        };
        if text.is_empty() {
            continue;
        }

        // Option tokens are always executed shell syntax (never data), so a
        // quote embedded in the option cluster is concatenation the shell has
        // already resolved: `rm -r'f' /`, `rm -'r'f /`, and `rm '-r'f /` all
        // run `rm -rf /`. Collapse balanced quotes to read the true flags
        // (bd-5xgt). Operands keep their own quote handling below, so a quoted
        // data path is unaffected. An *unbalanced* quote is a shell syntax
        // error that never runs rm, so it stays opaque and matches nothing.
        let dequoted = dequote_rm_flag_token(text);
        let flag_text = dequoted.as_ref();

        if !options_ended {
            if flag_text == "--" {
                options_ended = true;
                flags.saw_terminator = true;
                continue;
            }

            if flag_text.starts_with('-') && flag_text != "-" {
                let option_decision = if option_scanning
                    == RmOptionScanning::AppleStopAtFirstOperand
                    && !apple_rm_option_token_is_valid(flag_text)
                {
                    RmOptionDecision::Invalid
                } else {
                    apply_rm_option(flag_text, token.byte_range.clone(), &mut flags)
                };
                match option_decision {
                    RmOptionDecision::Continue => {}
                    // GNU rm treats --help and --version as terminal, even
                    // when operands precede them through getopt permutation.
                    RmOptionDecision::Terminal => return RmParseDecision::NoMatch,
                    // An unknown, ambiguous, or malformed option makes rm
                    // fail before it can recursively remove an operand.
                    RmOptionDecision::Invalid => return RmParseDecision::NoMatch,
                }
                continue;
            }
        }

        let (quote, unquoted) = strip_outer_quotes(text);
        paths.push(PathToken {
            unquoted,
            quote,
            range: token.byte_range.clone(),
        });
        if option_scanning == RmOptionScanning::AppleStopAtFirstOperand {
            options_ended = true;
        }
    }

    let flag_state = flags.resolve();
    let Some(flag_state) = flag_state else {
        return RmParseDecision::NoMatch;
    };

    // `rm -r` without an operand only reports a usage error. More
    // importantly, requiring a real operand prevents a bare option token
    // from being mislabeled as an attempted tree deletion.
    if paths.is_empty() {
        return RmParseDecision::NoMatch;
    }

    // GNU rm resolves -f/--force and all interactive modes in argv order.
    // -i and -I override an earlier force; a later force overrides either.
    let redirected_stdin = tokens
        .iter()
        .skip(start_idx)
        .take_while(|token| token.kind != NormalizeTokenKind::Separator)
        .filter_map(|token| token.text(command))
        .any(starts_with_shell_stdin_redirection);
    if flag_state.interactive_mode.prompts() && !automated_stdin && !redirected_stdin {
        return RmParseDecision::Allow;
    }

    // Recursive-only commands use the combined-style literal-temp policy:
    // double quotes preserve a static /tmp path, while expansions and
    // traversal remain denied. Existing force-form behavior is unchanged.
    let path_style = flag_state.force_style.unwrap_or(RmFlagStyle::Combined);
    let safe_paths = !paths.is_empty()
        && !flag_state.saw_terminator
        && paths
            .iter()
            .all(|path| path_is_safe_for_style(path, path_style));

    if safe_paths {
        return RmParseDecision::Allow;
    }

    let is_critical = paths
        .iter()
        .any(|path| path_is_root_home(path) && !path_is_safe_for_style(path, path_style));

    let (pattern_name, reason, severity) = match (is_critical, flag_state.force_style) {
        (true, Some(RmFlagStyle::Combined)) => (
            RM_RF_ROOT_HOME_NAME,
            RM_RF_ROOT_HOME_REASON,
            Severity::Critical,
        ),
        (true, Some(RmFlagStyle::Separate)) => (
            RM_R_F_SEPARATE_ROOT_HOME_NAME,
            RM_R_F_SEPARATE_ROOT_HOME_REASON,
            Severity::Critical,
        ),
        (true, Some(RmFlagStyle::Long)) => (
            RM_RECURSIVE_FORCE_ROOT_HOME_NAME,
            RM_RECURSIVE_FORCE_ROOT_HOME_REASON,
            Severity::Critical,
        ),
        (true, None) => (
            RM_RECURSIVE_ROOT_HOME_NAME,
            RM_RECURSIVE_ROOT_HOME_REASON,
            Severity::Critical,
        ),
        (false, Some(RmFlagStyle::Combined)) => {
            (RM_RF_GENERAL_NAME, RM_RF_GENERAL_REASON, Severity::High)
        }
        (false, Some(RmFlagStyle::Separate)) => {
            (RM_R_F_SEPARATE_NAME, RM_R_F_SEPARATE_REASON, Severity::High)
        }
        (false, Some(RmFlagStyle::Long)) => (
            RM_RECURSIVE_FORCE_NAME,
            RM_RECURSIVE_FORCE_REASON,
            Severity::High,
        ),
        (false, None) => (
            RM_RECURSIVE_GENERAL_NAME,
            RM_RECURSIVE_GENERAL_REASON,
            Severity::High,
        ),
    };

    // Rule-scoped target exemption (#284). The rule that would fire is now
    // known, so its configured `exempt_target_globs` get their one chance
    // here. Only this rule stands down: a different rm spelling resolves to a
    // different rule id and is unaffected, and every non-rm rule still sees the
    // whole command.
    if rm_targets_exempted_for_rule(pattern_name, &paths) {
        return RmParseDecision::Allow;
    }

    let span = flag_state
        .span
        .or(flag_state.recursive_span)
        .or_else(|| paths.first().map(|path| path.range.clone()));

    RmParseDecision::Deny(RmParseMatch {
        pattern_name,
        reason,
        severity,
        span,
    })
}

fn apple_rm_option_token_is_valid(text: &str) -> bool {
    // Apple's file_cmds `rm` calls getopt(3) with exactly
    // `dfiIPRrvWx`; unlike GNU getopt_long, Darwin's getopt stops at
    // the first non-option argv entry.
    let Some(short) = text.strip_prefix('-') else {
        return false;
    };
    !short.is_empty()
        && !short.starts_with('-')
        && short.bytes().all(|byte| {
            matches!(
                byte,
                b'd' | b'f' | b'i' | b'I' | b'P' | b'R' | b'r' | b'v' | b'W' | b'x'
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RmOptionDecision {
    Continue,
    Terminal,
    Invalid,
}

fn apply_rm_option(text: &str, span: Range<usize>, flags: &mut RmFlagTracker) -> RmOptionDecision {
    if let Some(long) = text.strip_prefix("--") {
        return apply_rm_long_option(long, span, flags);
    }

    let short = &text[1..];
    if short.is_empty() || !short.is_ascii() {
        return RmOptionDecision::Invalid;
    }

    let has_recursive = short.bytes().any(|byte| matches!(byte, b'r' | b'R'));
    let has_force = short.as_bytes().contains(&b'f');
    for byte in short.bytes() {
        match byte {
            b'r' | b'R' => {
                flags.seen_short_recursive = true;
                flags
                    .short_recursive_span
                    .get_or_insert_with(|| span.clone());
            }
            b'f' => {
                flags.seen_short_force = true;
                flags.short_force_span.get_or_insert_with(|| span.clone());
                flags.interactive_mode = RmInteractiveMode::Never;
            }
            b'i' => flags.interactive_mode = RmInteractiveMode::Always,
            b'I' => flags.interactive_mode = RmInteractiveMode::Once,
            // GNU plus BSD/macOS neutral rm options. None consumes an
            // additional argv token.
            b'd' | b'E' | b'P' | b'v' | b'W' | b'x' => {}
            _ => return RmOptionDecision::Invalid,
        }
    }

    if has_recursive && has_force {
        flags.combined_span.get_or_insert(span);
    }
    RmOptionDecision::Continue
}

fn apply_rm_long_option(
    text: &str,
    span: Range<usize>,
    flags: &mut RmFlagTracker,
) -> RmOptionDecision {
    let (name, value) = text
        .split_once('=')
        .map_or((text, None), |(name, value)| (name, Some(value)));
    let Some(option) = resolve_rm_long_option(name) else {
        return RmOptionDecision::Invalid;
    };

    match option {
        RmLongOption::Recursive if value.is_none() => {
            flags.seen_long_recursive = true;
            flags.long_recursive_span.get_or_insert(span);
        }
        RmLongOption::Force if value.is_none() => {
            flags.seen_long_force = true;
            flags.long_force_span.get_or_insert(span);
            flags.interactive_mode = RmInteractiveMode::Never;
        }
        RmLongOption::Interactive => {
            let mode = match value {
                Some(value) => parse_rm_interactive_mode(value),
                None => Some(RmInteractiveMode::Always),
            };
            let Some(mode) = mode else {
                return RmOptionDecision::Invalid;
            };
            flags.interactive_mode = mode;
        }
        RmLongOption::PreserveRoot => {
            if value.is_some_and(|value| value.is_empty() || !"all".starts_with(value)) {
                return RmOptionDecision::Invalid;
            }
        }
        RmLongOption::Help | RmLongOption::Version if value.is_none() => {
            return RmOptionDecision::Terminal;
        }
        RmLongOption::Dir
        | RmLongOption::NoPreserveRoot
        | RmLongOption::OneFileSystem
        | RmLongOption::PresumeInputTty
        | RmLongOption::Verbose
            if value.is_none() => {}
        _ => return RmOptionDecision::Invalid,
    }

    RmOptionDecision::Continue
}

/// Collapse balanced shell quotes and backslash escapes within an `rm` option
/// token so the true flag letters are read (`-r'f'` -> `-rf`, `-r"f"` -> `-rf`,
/// `'-r'f` -> `-rf`). Only applied to option-position tokens, which are always
/// executed syntax rather than data.
///
/// Returns the token unchanged (borrowed) when it has no quotes/escapes, or
/// when a quote is *unbalanced* — an unterminated quote is a shell syntax error
/// that never runs `rm`, so it must stay opaque and match no flag rather than
/// be silently "repaired" into a destructive one.
fn dequote_rm_flag_token(token: &str) -> std::borrow::Cow<'_, str> {
    if !token.bytes().any(|b| matches!(b, b'\'' | b'"' | b'\\')) {
        return std::borrow::Cow::Borrowed(token);
    }
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        match c {
            // Single quotes: everything until the next `'` is literal.
            '\'' => {
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == '\'' {
                        closed = true;
                        break;
                    }
                    out.push(inner);
                }
                if !closed {
                    return std::borrow::Cow::Borrowed(token);
                }
            }
            // Double quotes: literal, except backslash escapes `"`, `\`, `$`,
            // and backtick (POSIX double-quote semantics).
            '"' => {
                let mut closed = false;
                while let Some(inner) = chars.next() {
                    match inner {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match chars.next() {
                            Some(esc @ ('"' | '\\' | '$' | '`')) => out.push(esc),
                            Some(other) => {
                                out.push('\\');
                                out.push(other);
                            }
                            None => return std::borrow::Cow::Borrowed(token),
                        },
                        other => out.push(other),
                    }
                }
                if !closed {
                    return std::borrow::Cow::Borrowed(token);
                }
            }
            // A backslash outside quotes escapes the next character.
            '\\' => match chars.next() {
                Some(escaped) => out.push(escaped),
                None => return std::borrow::Cow::Borrowed(token),
            },
            other => out.push(other),
        }
    }
    std::borrow::Cow::Owned(out)
}

fn strip_outer_quotes(token: &str) -> (QuoteKind, &str) {
    if token.len() >= 2 {
        if token.starts_with('"') && token.ends_with('"') {
            return (QuoteKind::Double, &token[1..token.len() - 1]);
        }
        if token.starts_with('\'') && token.ends_with('\'') {
            return (QuoteKind::Single, &token[1..token.len() - 1]);
        }
    }
    (QuoteKind::None, token)
}

/// Whether every `rm` target is covered by `pattern_name`'s configured
/// `exempt_target_globs` (#284).
///
/// All-or-nothing on purpose: `rm -rf ~/scratch/a /etc` must stay denied, so a
/// single unexempted target keeps the rule firing. Single-quoted targets are
/// never eligible — the shell does not expand `~` inside them, so the literal
/// spelling names a different path than the glob's author meant.
fn rm_targets_exempted_for_rule(pattern_name: &str, paths: &[PathToken<'_>]) -> bool {
    if paths.is_empty() {
        return false;
    }
    let rule_id = format!("core.filesystem:{pattern_name}");
    if !crate::config::rule_has_target_exemptions(&rule_id) {
        return false;
    }

    let mut matched: Vec<(&str, String)> = Vec::with_capacity(paths.len());
    for path in paths {
        // A double-quoted path keeps its literal text; the shared normalizer
        // rejects any remaining expansion syntax either way.
        if path.quote == QuoteKind::Single {
            return false;
        }
        let Some(glob) = crate::config::rule_target_exemption(&rule_id, path.unquoted) else {
            return false;
        };
        matched.push((path.unquoted, glob));
    }
    for (target, glob) in &matched {
        crate::config::note_rule_target_suppression(&rule_id, glob, target);
    }
    true
}

fn path_is_safe_for_style(path: &PathToken<'_>, style: RmFlagStyle) -> bool {
    if path.quote == QuoteKind::Double && style != RmFlagStyle::Combined {
        return false;
    }

    match path.quote {
        QuoteKind::None => path_is_safe_unquoted(path.unquoted),
        QuoteKind::Double => path_is_safe_double_quoted(path.unquoted),
        QuoteKind::Single => false,
    }
}

/// Literal temp-family prefixes, including macOS's canonical `/private`
/// forms (`/tmp` and `/var/tmp` are symlinks to them there) (#244).
const LITERAL_TEMP_PREFIXES: [&str; 4] =
    ["/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/"];

fn path_is_safe_unquoted(path: &str) -> bool {
    LITERAL_TEMP_PREFIXES
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .is_some_and(temp_path_suffix_is_static_unquoted)
        || windows_literal_user_temp_subpath(path)
}

fn path_is_safe_double_quoted(path: &str) -> bool {
    // Double quotes do not change literal path text. Keep literal temporary
    // directories in parity with the unquoted path classifier while retaining
    // the same traversal and shell-expansion guards.
    LITERAL_TEMP_PREFIXES
        .iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .is_some_and(temp_path_suffix_is_static_double_quoted)
        || windows_literal_user_temp_subpath(path)
}

/// Literal per-user Windows temp subpaths (#285), the Windows counterpart of
/// the `/tmp/<subpath>` carve-out above. Recognizes the native
/// `C:\Users\<user>\AppData\Local\Temp\<subpath>` spelling (either separator,
/// any drive letter) and the Git Bash / MSYS2
/// `/c/Users/<user>/AppData/Local/Temp/<subpath>` form that Claude Code's Bash
/// tool emits on Windows. Windows path resolution is case-insensitive, so the
/// component comparison is too.
///
/// Deliberately excluded, mirroring the `$TMPDIR` policy documented in the
/// README ("Dynamic temp roots ... Blocked for review"):
/// - dynamic spellings (`$TEMP`, `$env:TEMP`, `%TEMP%`): the variable is
///   caller-controlled and can point anywhere;
/// - the machine-wide `C:\Windows\Temp`: shared with services and other users;
/// - the temp root itself with no subpath, like `/tmp` without a component.
pub(crate) fn windows_literal_user_temp_subpath(path: &str) -> bool {
    // Expansion syntax, quote characters, and cmd/PowerShell multi-argument
    // separators are never part of one static literal path.
    if path.bytes().any(|byte| {
        matches!(
            byte,
            b'$' | b'`' | b'%' | b'{' | b'}' | b'\'' | b'"' | b',' | b';'
        )
    }) {
        return false;
    }

    let bytes = path.as_bytes();
    let rest = if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        // Native drive form `X:\...` / `X:/...`.
        &path[3..]
    } else if bytes.len() >= 3
        && bytes[0] == b'/'
        && bytes[1].is_ascii_alphabetic()
        && bytes[2] == b'/'
    {
        // Git Bash / MSYS2 drive form `/x/...`.
        &path[3..]
    } else {
        return false;
    };
    // A second drive designator (`C:\...Temp\x,D:` style smuggling) cannot be
    // part of the temp subtree.
    if rest.contains(':') {
        return false;
    }

    let mut components: Vec<&str> = rest.split(['/', '\\']).collect();
    while components.last() == Some(&"") {
        components.pop();
    }
    // `Users`, `<user>`, `AppData`, `Local`, `Temp`, plus at least one real
    // component under the temp root (deleting the root itself stays reviewed).
    if components.len() < 6 {
        return false;
    }
    if components.iter().any(|component| {
        // Dot-only components (`.`, `..`, and cmd's `...` and longer, which
        // resolve as repeated parent traversal in some contexts) can leave the
        // temp subtree, and Win32 strips trailing dots and spaces from a
        // component, so `Temp.` / `Temp ` would name a different directory
        // than the one proven here.
        component.is_empty()
            || component.bytes().all(|byte| byte == b'.')
            || component.ends_with('.')
            || component.ends_with(' ')
    }) {
        return false;
    }
    components[0].eq_ignore_ascii_case("Users")
        && components[2].eq_ignore_ascii_case("AppData")
        && components[3].eq_ignore_ascii_case("Local")
        && components[4].eq_ignore_ascii_case("Temp")
}

fn temp_path_suffix_is_static_unquoted(path: &str) -> bool {
    temp_path_suffix_has_real_component(path)
        && !has_dotdot_segment(path)
        && !path
            .bytes()
            .any(|byte| matches!(byte, b'$' | b'`' | b'{' | b'}' | b'\\' | b'\'' | b'"'))
}

fn temp_path_suffix_is_static_double_quoted(path: &str) -> bool {
    if !temp_path_suffix_has_real_component(path) || has_dotdot_segment(path) {
        return false;
    }

    let bytes = path.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            // These retain expansion semantics inside double quotes.
            b'$' | b'`' => return false,
            // An unescaped quote closes the quoted region; any following text
            // is shell concatenation rather than part of the literal path.
            b'"' => return false,
            b'\\' => {
                let Some(&escaped) = bytes.get(index + 1) else {
                    return false;
                };
                if matches!(escaped, b'$' | b'`' | b'"' | b'\\') {
                    // The shell consumes this escape and produces a literal
                    // byte, so skip both bytes. A later unescaped expansion is
                    // still examined normally.
                    index += 2;
                    continue;
                }
            }
            _ => {}
        }
        index += 1;
    }
    true
}

fn temp_path_suffix_has_real_component(path: &str) -> bool {
    path.split('/')
        .any(|component| !component.is_empty() && component != ".")
}

fn has_dotdot_segment(path: &str) -> bool {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .any(|segment| segment == "..")
}

fn path_is_root_home(path: &PathToken<'_>) -> bool {
    // Check if the path is root or home, ignoring quotes for absolute paths.
    // Tilde expansion only happens if UNQUOTED, but / is absolute regardless.

    let text = path.unquoted;
    if path_text_is_root_home(text) {
        return true;
    }

    // Shell quote removal turns unquoted `\/` into `/` and `\~` into `~`.
    // Treat those escaped leading forms like their literal targets so the
    // parser preserves the Critical root/home severity instead of falling
    // through to the general rm-rf rule.
    if let Some(unescaped) = text.strip_prefix('\\') {
        return matches!(unescaped.as_bytes().first(), Some(b'/' | b'~'));
    }

    false
}

fn path_text_is_root_home(text: &str) -> bool {
    // Absolute paths starting with / are dangerous regardless of quotes
    // e.g. rm -rf "/" is just as deadly as rm -rf /
    if text.starts_with('/') {
        return true;
    }

    if text.starts_with('~') {
        return true;
    }

    text == "$HOME"
        || text.starts_with("$HOME/")
        || text == "${HOME}"
        || text.starts_with("${HOME}/")
}

/// Create the core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.filesystem".to_string(),
        name: "Core Filesystem",
        description: "Protects against recursive rm commands and equivalent filesystem destruction outside literal temp subdirectories",
        // `find` is included so the quick-reject filter doesn't drop
        // commands like `find / -delete` — which is bytewise-equivalent
        // to `rm -rf /` and used to bypass dcg entirely (the agent learns
        // to swap `rm -rf` → `find -delete` when blocked).
        //
        // `unlink` is included so the quick-reject filter doesn't drop
        // single-file destruction via the POSIX unlink primitive.
        // `truncate` covers the in-place zero/shrink primitive that
        // destroys file content without removing the inode.
        // `shred` covers overwrite-and-unlink (or just overwrite) — DoD-
        // style data destruction with no recovery.
        // `tar` covers `tar --remove-files <sensitive-source>`, which
        // archives-then-deletes — i.e. recursive-force-delete masquerading
        // as an archive operation.
        // `cp`, `ln`, and `rsync` cover sensitive-source propagation into
        // temp-family paths followed by forced recursive deletion.
        // Mirror entries MUST also exist in src/packs/mod.rs::PACK_ENTRIES
        // (the duplicate-source-of-truth that gates execution).
        keywords: &[
            "rm", "find", "unlink", "truncate", "shred", "tar", "dd", "mv", "cp", "ln", "rsync",
            ">/", "> /", ">~", "> ~", ">$", "> $", ">\"", "> \"", ">'", "> '", "&>", ">&", ">|",
            "1>", "2>", ">%", "> %", ">!", "> !", ">^", "> ^",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

#[allow(clippy::too_many_lines)]
fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // rm -rf in /tmp (combined flags)
        safe_pattern!(
            "rm-rf-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf in /var/tmp (combined flags)
        safe_pattern!(
            "rm-rf-var-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-var-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) in /tmp
        safe_pattern!(
            "rm-r-f-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) in /var/tmp
        safe_pattern!(
            "rm-r-f-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /tmp
        safe_pattern!(
            "rm-recursive-force-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /var/tmp
        safe_pattern!(
            "rm-recursive-force-var-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-var-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // -----------------------------------------------------------------
        // `find ... -delete` safe whitelist for temp directories.
        //
        // WHOLE-COMMAND ANCHOR: `^...$`. The safe pattern only matches
        // when the ENTIRE command is a single `find /tmp ... -delete`
        // invocation. Compound forms (`find /tmp -delete; echo done`,
        // `echo done; find /tmp -delete`, `(find /tmp -delete)`) do NOT
        // short-circuit through the safe pattern.
        //
        // The reason for whole-command anchoring: dcg's destructive
        // evaluator (for non-rm patterns) matches against the whole
        // sanitized command, not per-segment. If any safe pattern in the
        // pack matches, ALL destructive patterns are skipped (see
        // `evaluator.rs` `matches_safe_with_deadline` shadowing). A
        // segment-aware safe pattern would create a real bypass:
        //   find /tmp -delete; find /etc -delete
        // — the first segment matches the safe pattern, the destructive
        // pattern for the second segment is skipped, /etc is deleted.
        //
        // The trade-off is false positives on legitimate compound forms
        // like `echo done; find /tmp -delete` (the destructive
        // `find-delete-general` rule fires). Users can resolve via
        // `dcg allow-once` for one-off cases or temporary allowlist for
        // recurring scripts. Proper fix is a `parse_find_command`
        // analogue to `parse_rm_command` that splits per-invocation —
        // see git_safety_guard followup beads.
        //
        // STRICT shape: after `find <tmp-path>`, only allow more <tmp-path>
        // tokens or `-flag [value]` pairs whose value is NOT path-like
        // (i.e. doesn't start with `/`, `~`, or `$HOME`). This prevents
        //   find /tmp/foo /etc -delete
        // from short-circuiting through (the `/etc` would also be deleted).
        //
        // `-delete` must terminate the command (followed by end-of-string
        // or only more non-path flags).
        // -----------------------------------------------------------------
        safe_pattern!(
            "find-delete-tmp",
            r"^(?![^|;&]*[\\$`])find\s+/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-var-tmp",
            r"^(?![^|;&]*[\\$`])find\s+/var/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:/var/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        // -----------------------------------------------------------------
        // `unlink <file>` safe whitelist for temp directories.
        //
        // WHOLE-COMMAND ANCHOR: `^...$`. Same rationale as the find-delete
        // safe patterns — segment-aware safes shadow the destructive rule
        // across compound segments and re-open the bypass class.
        //
        // Trade-off accepted: `echo done; unlink /tmp/scratch` blocks (false
        // positive). Resolve via `dcg allow-once` for one-offs.
        // -----------------------------------------------------------------
        safe_pattern!(
            "unlink-tmp",
            r"^(?![^|;&]*[\\$`])unlink\s+(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-var-tmp",
            r"^(?![^|;&]*[\\$`])unlink\s+(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // unlink invoked with --help / --version is read-only.
        safe_pattern!("unlink-help", r"^unlink\s+(?:--help|--version)\s*$"),
        // -----------------------------------------------------------------
        // `truncate` safe whitelist.
        //
        // truncate has many flag forms:
        //   -s 0 <file>       --size=0 <file>      (zero out)
        //   -s -<N> <file>    --size=-N <file>     (shrink by N bytes — destructive)
        //   -s <N> <file>     --size=N <file>      (set absolute — could grow OR shrink)
        //   -s +<N> <file>    --size=+N <file>     (grow — non-destructive)
        //   -s <fmt><N> <file>                     (>, <, %, etc. — destructive variants exist)
        //
        // Approach: only allow truncate when the FIRST positional argument
        // looks like a +<N> grow operation OR the path is under /tmp etc.
        // Whole-command anchored. --help / --version are read-only.
        // -----------------------------------------------------------------
        safe_pattern!("truncate-help", r"^truncate\s+(?:--help|--version)\s*$"),
        // Growing operations: -s +<N>, --size=+<N> (pure growth — no
        // data destroyed). We only whitelist the explicit `+` form because
        // absolute sizes can shrink existing files. The `-s` short form
        // takes its value as a separate token (`-s +1G`); `--size=` packs
        // value into the same token (`--size=+1G`).
        safe_pattern!(
            "truncate-grow",
            r"^truncate\s+(?:-s\s+\+\S+|--size=\+\S+)\s+\S+\s*$"
        ),
        // Temp-directory truncate (any size).
        safe_pattern!(
            "truncate-tmp",
            r"^(?![^|;&]*[\\$`])truncate\s+(?:-s\s+\S+|--size=\S+)\s+(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-var-tmp",
            r"^(?![^|;&]*[\\$`])truncate\s+(?:-s\s+\S+|--size=\S+)\s+(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // -r/--reference <ref-file> <file> uses the size of ref-file.
        // This is a copy-size, not a destruction primitive — allowed when
        // both args are paths. We don't whitelist explicitly because the
        // destructive pattern only fires on `-s 0` / `-s -N` / `--size=0`
        // / `--size=-N`, leaving --reference invocations to the
        // default-allow path.
        // -----------------------------------------------------------------
        // `shred` safe whitelist.
        //
        // shred forms (all destructive when path is sensitive):
        //   shred <file>          — overwrite (file persists, content gone)
        //   shred -u <file>       — overwrite + unlink
        //   shred -fzu <file>     — force + zero-pass + unlink (most aggressive)
        //   shred --remove <file> — long form for -u
        //
        // Whole-command anchored. Allow temp dirs and --help/--version.
        // -----------------------------------------------------------------
        safe_pattern!("shred-help", r"^shred\s+(?:--help|--version)\s*$"),
        safe_pattern!(
            "shred-tmp",
            r"^(?![^|;&]*[\\$`])shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-var-tmp",
            r"^(?![^|;&]*[\\$`])shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        // -----------------------------------------------------------------
        // `tar --remove-files` safe whitelist.
        //
        // `tar --remove-files -cf <archive> <source>` archives sources
        // and then deletes them. The destructive pair is `--remove-files`
        // PLUS a sensitive source path; safe rescue requires the source
        // to be entirely under a temp directory.
        //
        // Pattern shape: anchored `^...$`, optional flags (each flag may
        // take a non-path-like value — that swallows the `-cf out.tar`
        // archive arg without falsely matching it as a sensitive path),
        // then the temp-dir source, then optional trailing flags. The
        // `(?=\s+[^|;&]*--remove-files\b)` lookahead requires the flag
        // to actually be present (otherwise the destructive rule wouldn't
        // fire and no rescue is needed).
        //
        // Trade-off accepted: a multi-source mixed command like
        // `tar --remove-files -cf out.tar /tmp/foo /etc/bar` will NOT
        // be rescued (there's a non-tmp positional after /tmp/foo, so
        // the trailing repetition fails to consume it) and the
        // destructive rule will fire correctly on the /etc/bar source.
        // -----------------------------------------------------------------
        safe_pattern!(
            "tar-remove-files-tmp",
            r"^(?![^|;&]*[\\$`])tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-var-tmp",
            r"^(?![^|;&]*[\\$`])tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        // -----------------------------------------------------------------
        // `dd` safe whitelist.
        //
        // `dd if=/dev/zero of=<file>` (or `if=/dev/urandom of=<file>`)
        // overwrites the file's content in place — the truncate-equivalent
        // for files. The destructive trigger is `of=` to a sensitive path
        // that is NOT under /dev (device-level dd is system.disk's
        // territory; this pack's dd rules exclude /dev entirely).
        //
        // Operand syntax: dd's positional arguments are all `key=value`
        // pairs (`if=`, `of=`, `bs=`, `count=`, `status=`, `conv=`, ...)
        // and can appear in any order. The flexible operand pattern below
        // matches any `letters=value` token plus optional --long-flags.
        //
        // Pattern shape: anchored `^...$`, optional operands/flags,
        // `of=/tmp/...`, optional trailing operands/flags. The
        // `(?=\s+[^|;&]*\bof=)` lookahead requires `of=` to actually be
        // present (otherwise no destruction trigger and no rescue needed).
        //
        // Trade-off accepted: a multi-of= command (extremely rare; dd
        // only reads the LAST of= operand per POSIX) is not specially
        // handled; the safe pattern fires if the LAST positional in the
        // command-line happens to be a tmp path.
        // -----------------------------------------------------------------
        safe_pattern!(
            "dd-tmp",
            r#"^(?![^|;&]*[\\$`])dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:(?!of=)[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-var-tmp",
            r#"^(?![^|;&]*[\\$`])dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:(?!of=)[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        // dd invoked with --help / --version is read-only.
        safe_pattern!("dd-help", r"^dd\s+(?:--help|--version)\s*$"),
        // -----------------------------------------------------------------
        // `mv` safe whitelist.
        //
        // The destructive `mv-sensitive-source-root-home` rule fires on
        // any mv whose command line mentions a sensitive path (source OR
        // destination) — the regex doesn't position-parse args because
        // mv supports `-t target sources...`, multi-source moves, and
        // various flag interleavings. False positives only happen for
        // /var/tmp (which contains the sensitive `/var` prefix); these
        // safe patterns rescue when ALL positional paths are under the
        // matching literal tmp variant. Pure /tmp moves don't even reach
        // the destructive rule (that prefix isn't sensitive), but the
        // explicit whitelist documents the supported safe form. TMPDIR is
        // caller-controlled and is handled by a fail-closed rule below.
        //
        // Pattern shape: anchored `^...$`, optional flags (each may take
        // a non-path-like value to swallow `-t target`-style args), then
        // one or more tmp-family paths separated by whitespace, then
        // optional trailing flags.
        // -----------------------------------------------------------------
        safe_pattern!(
            "mv-tmp",
            r"^(?![^|;&]*[\\$`])mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+(?:/private)?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-var-tmp",
            r"^(?![^|;&]*[\\$`])mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+(?:/private)?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // mv invoked with --help / --version is read-only.
        safe_pattern!("mv-help", r"^mv\s+(?:--help|--version)\s*$"),
        // -----------------------------------------------------------------
        // `mv` into the platform Trash directory (#244).
        //
        // dcg's own rm-rf remediation suggests "Move to trash instead:
        // mv path ~/.local/share/Trash/", so that exact soft-delete must
        // not then be blocked by `mv-sensitive-source-root-home` (whose
        // regex trips on the `~` in the destination). Sources are limited
        // to files *under* a home directory, tmp family, or relative
        // paths — never a bare `~`, a whole `/home/<user>` or
        // `/Users/<user>` root, or a sensitive system tree — and both
        // sides carry the standard `..`-traversal guard. Dynamic paths
        // (`$`, backticks, backslashes) fall through to the fail-closed
        // rules.
        // -----------------------------------------------------------------
        safe_pattern!(
            "mv-to-trash",
            r"^(?![^|;&]*[\\$`])mv(?:[ \t]+--?[a-zA-Z][a-zA-Z0-9-]*)*(?:[ \t]+(?:~/|/home/[^/\s]+/|/Users/[^/\s]+/|(?:/private)?(?:/var)?/tmp/|\./)?(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))[A-Za-z0-9._][^\s;|&]*)+[ \t]+(?:~/\.local/share/Trash|~/\.Trash)(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))[^\s;|&]*)?\s*$"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // Evaluated explicitly by the GNU sed semantic pass. The regex is
        // intentionally unsatisfiable so ordinary command matching cannot
        // manufacture this finding.
        destructive_pattern!(
            "sed-exec-unverified",
            r"(?!)",
            "GNU sed executes shell input that dcg cannot statically verify.",
            High,
            "Use a literal sed replacement or inspect the fully rendered shell command before allowing execution. Backreferences, '&', and an empty `e` command depend on runtime input."
        ),
        // ----- cross-segment sensitive propagation before rm fallbacks -----
        //
        // These patterns must run before the general rm rules below. Otherwise
        // the trailing `rm -rf /tmp/...` segment in the whole compound command
        // is attributed as a generic recursive delete before the propagation
        // chain can be classified.
        destructive_pattern!(
            "cp-sensitive-then-delete",
            r#"\bcp\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)"#,
            "archive copy of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS.",
            Critical,
            "`cp -al /etc /tmp/x && rm -rf /tmp/x` is a propagation variant of the \
             relocate-then-delete bypass: the copy segment is allowed, and the temp \
             delete segment is normally safe, but the compound command can destroy \
             sensitive content or hide irreversible deletion behind a temp path.\n\n\
             Safer alternatives:\n\
             - Copy beside the original or into a named backup path and verify with `diff -r`.\n\
             - Do not combine sensitive-source propagation and forced deletion in one command.\n\
             - Use `rm -ri` if a derived temp tree genuinely needs manual cleanup.",
            SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS
        ),
        destructive_pattern!(
            "ln-symlink-sensitive-then-delete",
            r#"\bln\b[^|;&]*\s-[A-Za-z]*s[A-Za-z]*[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)"#,
            "symlink from a sensitive path into temp followed by forced recursive deletion can traverse and destroy the target. EXTREMELY DANGEROUS.",
            Critical,
            "`ln -s /etc /tmp/x && rm -rf /tmp/x/.` can turn an apparently safe temp \
             cleanup into deletion through a symlink. The temp path does not make the \
             operation safe once it points back at a sensitive tree.\n\n\
             Safer alternatives:\n\
             - Inspect symlinks with `readlink` and `ls -la` before removing anything.\n\
             - Remove only the link itself with `unlink /tmp/<link>` when that is the intent.\n\
             - Avoid combining symlink creation and recursive deletion in one command.",
            SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS
        ),
        destructive_pattern!(
            "rsync-sensitive-then-delete",
            r#"\brsync\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)"#,
            "rsync archive of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS.",
            Critical,
            "`rsync -a /etc/ /tmp/dest/ && rm -rf /tmp/dest` is the rsync form of the \
             sensitive-source propagation bypass. Archive mode preserves enough structure \
             that the later temp cleanup should require human review.\n\n\
             Safer alternatives:\n\
             - Run rsync and inspect the destination in a separate step.\n\
             - Use `--dry-run` for rsync previews.\n\
             - Use `rm -ri` for manual cleanup of derived temp trees.",
            SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS
        ),
        // rm -rf on root or home paths (CRITICAL - catastrophic, never allow)
        // Target set covers:
        //   - literal `/` or `~` (optionally quoted/backslash-escaped)
        //   - `$HOME` and `${HOME}` (optionally quoted), which the shell
        //     expands to the user's home directory before rm sees it
        destructive_pattern!(
            "rm-rf-root-home",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+['"\\]?(?:[/~]|\$\{?HOME\b)"#,
            "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.",
            Critical,
            "This command would recursively delete files starting from the root filesystem (/) \
             or home directory (~). This is catastrophic and will destroy:\n\n\
             - Your entire operating system\n\
             - All installed applications and libraries\n\
             - All user data, documents, and configurations\n\
             - Boot files, making the system unbootable\n\n\
             There is NO recovery without backups. Even with backups, full restoration \
             takes hours to days.\n\n\
             dcg auto-allows recursive deletion only for literal temp paths:\n  \
             rm -rf /tmp/<subdir>/scratch\n\n\
             For any other directory, preview first and then delete interactively \
             (dcg allows the interactive form):\n  \
             find /path/to/directory -type f | head -20\n  \
             rm -ri /path/to/directory",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // Same root/home catastrophe but with SEPARATE flags (`rm -r -f /`,
        // `rm -f -r /`). The previous pattern only caught the combined `-rf`
        // form. Without this, `rm -r -f /` fell through to the general
        // `rm-r-f-separate` rule (High) instead of being attributed as
        // Critical root deletion.
        destructive_pattern!(
            "rm-r-f-separate-root-home",
            r#"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+['"\\]?(?:[/~]|\$\{?HOME\b)"#,
            "rm with separate -r -f flags targeting root or home is EXTREMELY DANGEROUS.",
            Critical,
            "Separate `-r -f` flags on `/` or `~` have identical effect to `rm -rf /`: \
             recursive, forced, silent deletion of the entire filesystem or home directory.\n\n\
             There is NO recovery without backups. Run only if truly intended.",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // Same root/home catastrophe but with LONG flags
        // (`rm --recursive --force /`, `rm --force --recursive /`).
        destructive_pattern!(
            "rm-recursive-force-root-home",
            r#"rm\s+.*--recursive.*--force\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+.*--force.*--recursive\s+['"\\]?(?:[/~]|\$\{?HOME\b)"#,
            "rm --recursive --force targeting root or home is EXTREMELY DANGEROUS.",
            Critical,
            "The long-flag form has identical effect to `rm -rf /`: recursive, forced, \
             silent deletion. Run only if truly intended.",
            RM_RF_ROOT_HOME_SUGGESTIONS
        ),
        // General rm -rf (caught after safe patterns) - High because temp paths are allowed
        destructive_pattern!(
            "rm-rf-general",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.",
            High,
            "rm -rf recursively removes files and directories without confirmation prompts. \
             The -f (force) flag suppresses all warnings, making accidental deletions \
             silent and immediate.\n\n\
             Why this is dangerous:\n\
             - Deleted files bypass the trash - they're gone immediately\n\
             - Typos in paths can delete unintended directories\n\
             - Wildcards can expand to match more than expected\n\
             - No undo mechanism exists\n\n\
             Safe alternatives:\n\
             - rm -ri: Interactive mode, confirms each file\n\
             - trash-cli: Moves files to trash instead of deleting\n\
             - rm -rf in literal /tmp or /var/tmp subdirectories: Allowed\n\
             - Variable-rooted paths such as $TMPDIR: Reviewed because the environment may point anywhere\n\n\
             Preview what would be deleted:\n  \
             find /path/to/delete -type f | wc -l  # Count files\n  \
             ls -la /path/to/delete               # List contents",
            RM_RF_GENERAL_SUGGESTIONS
        ),
        // Globbed rm under a home directory, with or without -r/-f (#247).
        //
        // From a data-loss standpoint the glob IS the recursion:
        // `rm -f ~/Downloads/*` destroys approximately the same file set as
        // the already-blocked `rm -rf ~/Downloads`, and unlike a named file
        // the *shell*, not the author, decides the file set at run time. An
        // unquoted glob is required — a quoted `"~/x/*.md"` never expands, so
        // the root alternation deliberately accepts no quote prefix. Bounded,
        // single-file deletes like `rm -f ~/Downloads/one-file.md` are
        // untouched.
        destructive_pattern!(
            "rm-glob-home",
            r"(?:^|[^\w-])rm\b[^|;&\n]*?[ \t](?:~|/Users|/home|\$\{?HOME\}?)/[^|;&\s]*[*?\[]",
            "rm with an unexpanded glob under a home directory deletes an unbounded, shell-chosen file set and requires human approval.",
            High,
            "The glob is expanded by the shell at execution time, so the author cannot \
             review the exact file set being deleted: `rm -f ~/Downloads/*.md` removes \
             every matching file, exactly like the already-blocked recursive forms.\n\n\
             Safer alternatives:\n\
             - Preview the expansion first: `ls ~/Downloads/*.md`\n\
             - Delete explicitly named files: `rm ~/Downloads/one-file.md`\n\
             - Move to trash instead: `mv ~/Downloads/*.md ~/.local/share/Trash/`",
            RM_RF_GENERAL_SUGGESTIONS
        ),
        // rm -r -f (separate flags)
        destructive_pattern!(
            "rm-r-f-separate",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval.",
            High,
            "rm with separate -r and -f flags has the same effect as rm -rf: recursive \
             forced deletion without confirmation.\n\n\
             Common variations that are all equivalent:\n\
             - rm -r -f path\n\
             - rm -f -r path\n\
             - rm -r -f -v path (verbose but still forced)\n\n\
             All carry the same risks as rm -rf: immediate, silent, irreversible deletion.\n\n\
             This rule matches the -r/-f flag PAIR, not a filesystem path, so it also \
             fires when `rm` is another tool's subcommand (`git rm -r -f`, \
             `bq rm -r -f`). The recursive-force semantics still apply, but to that \
             tool's objects — tracked files and index entries for git, a dataset and \
             everything in it for bq — not to a directory tree. Enable that tool's pack \
             for guidance written for it; this rule is the backstop when it is not.\n\n\
             Safer approach for temporary directories:\n\
             - rm -r -f /tmp/mydir    # Allowed - temp directories are safe\n\
             - Resolve and inspect $TMPDIR before using it as a deletion root\n\n\
             For other paths, prefer:\n  \
             rm -ri /path  # Interactive confirmation",
            RM_R_F_SEPARATE_SUGGESTIONS
        ),
        // rm --recursive --force (long flags)
        destructive_pattern!(
            "rm-recursive-force-long",
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval.",
            High,
            "rm --recursive --force is the long-form equivalent of rm -rf. While more \
             readable, it carries identical risks: silent, recursive, irreversible deletion.\n\n\
             The long flags may appear in:\n\
             - Scripts aiming for clarity\n\
             - Generated code from build tools\n\
             - Cross-platform compatibility scenarios\n\n\
             All standard rm -rf precautions apply:\n\
             - Verify the path before running\n\
             - Use absolute paths to avoid ambiguity\n\
             - Consider using trash-cli for recoverable deletion\n\n\
             Preview command:\n  \
             find /path --maxdepth 2 -ls | head -30",
            RM_RECURSIVE_FORCE_SUGGESTIONS
        ),
        // ----- `find ... -delete` (Critical: root/home target) -----
        //
        // `find <sensitive-path> -delete` recursively removes everything
        // under the path — bytewise-equivalent to `rm -rf <sensitive-path>`.
        // This rule exists to close the most common dcg-bypass pattern in
        // the wild: agents that learn `rm -rf` is blocked simply swap it
        // for `find -delete`. Without this rule, dcg's protection against
        // catastrophic root/home deletion is one Google search away from
        // useless.
        //
        // The regex matches `find` at any word boundary (so it fires
        // inside compound commands like `echo foo; find /etc -delete`,
        // and on path-prefixed binaries like `/usr/bin/find / -delete`),
        // then somewhere later a sensitive path token (root, common
        // system dirs, or home-like prefixes) preceded by whitespace or
        // `=`, then a `-delete` action flag terminated by whitespace,
        // end-of-string, or a shell separator (`;`, `&`, `|`). The
        // `(?:\s|$|[;&|])` end anchor — instead of `\b` — ensures
        // `-delete-this-not-a-flag` does NOT false-positive (the `-`
        // after `-delete` is not in our terminator set even though `\b`
        // would happily allow it).
        destructive_pattern!(
            "find-delete-root-home",
            // End anchor `(?:\s|$|[;&|)\n])` accepts shell separators,
            // newlines, and a subshell-close `)` after `-delete` so
            // `(find /etc -delete)` and `find /etc -delete | tee log`
            // both fire. Without `)` in the set, subshell forms
            // silently bypass.
            r#"\bfind\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)[^|;&]*?\s-delete(?:\s|$|[;&|)\n])"#,
            "find <sensitive-path> -delete is bytewise-equivalent to rm -rf on root/home and is EXTREMELY DANGEROUS. This command will NOT be executed.",
            Critical,
            "`find <path> -delete` is the bytewise-equivalent of `rm -rf <path>`: \
             it recursively removes every file and (when -depth is implied) every \
             directory matched by the predicate. Targeting `/`, `~`, `$HOME`, or any \
             top-level system directory (`/etc`, `/usr`, `/var`, `/home`, `/boot`, \
             `/dev`, `/proc`, `/sys`, `/lib`, `/lib64`, `/opt`, `/root`) destroys \
             the operating system or user data the same way `rm -rf` would.\n\n\
             There is NO recovery without backups.\n\n\
             If you only need to delete files matching a pattern, use a much more \
             specific path:\n  \
             find /path/to/specific/subdir -name '*.tmp' -delete\n\n\
             Always preview first:\n  \
             find /path -type f | head -20",
            FIND_DELETE_SUGGESTIONS
        ),
        // ----- `find ... -delete` (High: any other target) -----
        //
        // The general rule fires after the safe-pattern whitelist (which
        // allows only static paths under literal `/tmp/...` and
        // `/var/tmp/...`). Any other `find ... -delete` is an
        // unscoped destructive operation that should require human
        // approval, exactly like the parallel `rm-rf-general` rule.
        destructive_pattern!(
            "find-delete-general",
            // `\bfind\b` (not `^\s*find\b`) so the rule fires in compound
            // forms (`echo foo; find . -delete`, `(find . -delete)`) and
            // on path-prefixed binaries. `-delete(?:\s|$|[;&|)\n])` (not
            // `\b`) so `-delete-this-not-a-flag` — where `\b` happily
            // allows the following `-` — does NOT false-positive, while
            // shell separators and subshell-close are still accepted.
            r"\bfind\b[^|;&]*\s-delete(?:\s|$|[;&|)\n])",
            "find ... -delete is destructive (bytewise-equivalent to rm -rf on the matched tree) and requires human approval.",
            High,
            "`find ... -delete` recursively deletes every path matched by the find \
             expression. The action flag `-delete` implies `-depth` (so directories \
             are deleted after their contents). With no path predicate it deletes \
             the entire starting tree. Common pitfalls:\n\n\
             - `find . -delete` deletes the current working directory's contents.\n\
             - `find <path> -delete` with a wide -name glob matches more than expected.\n\
             - `-delete` errors are silent by default — failures don't stop the walk.\n\n\
             Safer alternatives:\n\
             - Drop -delete to preview: `find <path> ...` (just lists matches)\n\
             - Add -print -delete to log each deletion as it happens\n\
             - Use `find /tmp/<subdir> ... -delete` (allowed under temp dirs)\n\
             - For a few files: `find ... | xargs -t -p rm -i` for confirmation",
            FIND_DELETE_SUGGESTIONS
        ),
        // ----- `unlink <file>` (Critical: root/home/system target) -----
        //
        // `unlink <file>` is the raw POSIX unlink(2) primitive — semantic
        // equivalent of `rm <file>` (single file, no recursion). On a
        // sensitive target (`/etc/passwd`, `~/.ssh/id_*`, `$HOME/...`) it
        // is one-shot data destruction with no recovery and no recursion
        // budget to slow it down.
        //
        // The regex matches `unlink` at any word boundary (so it fires in
        // compound forms and after `sudo`/`env` wrappers, and on
        // path-prefixed binaries via PATH_NORMALIZER), then a sensitive
        // path token. Single argument only — multi-arg unlink isn't
        // standard.
        destructive_pattern!(
            "unlink-root-home",
            r#"\bunlink\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "unlink on a sensitive system or home path is one-shot data destruction with no recovery. EXTREMELY DANGEROUS.",
            Critical,
            "`unlink <file>` is the raw POSIX unlink(2) primitive: it removes a single \
             directory entry without prompting, without trash, without backup. On a \
             sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or \
             a home-directory key (`~/.ssh/id_ed25519`, `$HOME/.gnupg/...`) the result \
             is irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - `mv <file> <file>.deleted-YYYYMMDD` then verify nothing breaks, then\n\
               `unlink <file>.deleted-...` after a few days.\n\
             - `cp <file> <file>.bak && unlink <file>` to keep an explicit backup.\n\
             - `unlink /tmp/<subdir>/scratch` is allowed (temp dirs).",
            UNLINK_SUGGESTIONS
        ),
        // ----- `unlink <file>` (High: any other target) -----
        //
        // The general rule fires after the `unlink-tmp` safe whitelist.
        // Any unlink not under a temp dir requires human approval.
        destructive_pattern!(
            "unlink-general",
            r"\bunlink\s+\S",
            "unlink is destructive (POSIX equivalent of rm on a single file) and requires human approval.",
            High,
            "`unlink <file>` removes a single directory entry without confirmation, \
             without trash, without backup. While not as broad as `rm -rf`, a typo in \
             the target path destroys an unintended file.\n\n\
             Safer alternatives:\n\
             - Verify the path with `ls -la <file>` first.\n\
             - Make a backup: `cp <file> <file>.bak`.\n\
             - For temp scratch: `unlink /tmp/<subdir>/scratch` is allowed.\n\
             - Use `mv <file> /tmp/quarantine-<file>` if you want a delayed delete.",
            UNLINK_SUGGESTIONS
        ),
        // ----- destructive `truncate -s/--size` (Critical: root/home/system) -----
        //
        // `truncate -s 0 <file>` zeros the file in place — equivalent to
        // deleting all content. With a sensitive target (`/etc/passwd`,
        // `/etc/shadow`, `/etc/sudoers`, `~/.ssh/...`, `$HOME/.aws/...`)
        // this is irrecoverable data destruction.
        //
        // Every absolute size can shrink an existing file, and therefore
        // destroys data depending on runtime state. Only an explicit `+N`
        // relative growth is provably non-destructive and is rescued by the
        // `truncate-grow` safe pattern above.
        destructive_pattern!(
            "truncate-zero-root-home",
            r#"\btruncate\b[^|;&]*?(?:\s-s\s+(?!\+)\S+|\s--size=(?!\+)\S+)[^|;&]*?\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "truncate with a potentially shrinking size on a sensitive system or home path destroys data. EXTREMELY DANGEROUS.",
            Critical,
            "`truncate -s 0 <file>` zeros a file in place. `truncate -s -<N> <file>` \
             shrinks a file by N bytes (destroying the trailing data). On a sensitive \
             system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or a home-\
             directory key/credential the result is irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Make a backup first: `cp <file> <file>.bak && truncate -s 0 <file>`.\n\
             - For growth (NOT shrink): `truncate -s +<N>` is allowed (no data loss).\n\
             - For temp scratch: `truncate -s 0 /tmp/<subdir>/scratch` is allowed.",
            TRUNCATE_SUGGESTIONS
        ),
        // ----- destructive `truncate -s/--size` (High: any other target) -----
        destructive_pattern!(
            "truncate-zero-general",
            r"\btruncate\b[^|;&]*?(?:\s-s\s+(?!\+)\S+|\s--size=(?!\+)\S+)",
            "truncate with an absolute or shrinking size can destroy file content and requires human approval.",
            High,
            "`truncate -s 0 <file>` zeros a file in place; `truncate -s -<N> <file>` \
             shrinks it by N bytes. Both destroy data without confirmation, without \
             trash, without backup. While not as broad as `rm`, a typo in the target \
             path destroys an unintended file.\n\n\
             Safer alternatives:\n\
             - Verify the size first: `wc -c <file>`.\n\
             - Make a backup: `cp <file> <file>.bak && truncate -s 0 <file>`.\n\
             - For growth: `truncate -s +<N>` (allowed; non-destructive).\n\
             - For temp scratch: `truncate -s 0 /tmp/<subdir>/scratch` is allowed.",
            TRUNCATE_SUGGESTIONS
        ),
        // ----- `shred ...` (Critical: root/home/system) -----
        //
        // `shred` overwrites file content; `shred -u`/`--remove`/`-fzu`
        // additionally unlinks the file. On a sensitive target this is
        // beyond-recovery destruction (the very design intent of shred).
        //
        // Whether or not `-u` is present, a sensitive-path shred is
        // Critical: the file content is destroyed even if the inode
        // remains. The general (High-tier) rule below handles non-
        // sensitive paths.
        destructive_pattern!(
            "shred-root-home",
            r#"\bshred\b[^|;&]*?\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "shred on a sensitive system or home path destroys data beyond forensic recovery. EXTREMELY DANGEROUS.",
            Critical,
            "`shred` overwrites file content with random data (DoD-style multi-pass by \
             default). With `-u`/`--remove`/`-fzu` the file is also unlinked. On a \
             sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or a \
             home-directory key/credential the result is unrecoverable even with \
             specialised forensics — that is shred's entire design intent.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Verify the path with `ls -la <file>` first.\n\
             - Make a backup: `cp <file> <file>.bak && shred -u <file>`.\n\
             - For temp scratch: `shred -u /tmp/<subdir>/scratch` is allowed.\n\
             - For modern SSDs, single-pass is sufficient: `shred -n 1 -u <file>`.",
            SHRED_SUGGESTIONS
        ),
        // ----- `shred ...` (High: any other target) -----
        destructive_pattern!(
            "shred-general",
            r"\bshred\s+(?:-[a-zA-Z]+\s+|--[a-z\-]+\s+|--[a-z\-]+=\S+\s+)*\S",
            "shred destroys file content beyond recovery and requires human approval.",
            High,
            "`shred` overwrites file content with random data; `-u`/`--remove` adds an \
             unlink step. The whole point is that the data cannot be recovered. While \
             not as broad as `rm -rf`, a typo in the target path destroys an unintended \
             file with no possibility of undo.\n\n\
             Safer alternatives:\n\
             - Verify the path with `ls -la <file>` first.\n\
             - Make a backup: `cp <file> <file>.bak`.\n\
             - For temp scratch: `shred -u /tmp/<subdir>/scratch` is allowed.\n\
             - On modern SSDs `shred` may not actually overwrite the underlying flash \
               cells; use `cryptsetup erase` or vendor secure-erase utilities instead.",
            SHRED_SUGGESTIONS
        ),
        // ----- `tar --remove-files <sensitive>` (Critical: root/home) -----
        //
        // `tar --remove-files -cf <archive> <source>` archives the source
        // tree into <archive>, then deletes the originals — bytewise-
        // equivalent to `rm -rf <source>` once the archive is written.
        // With `-cf /dev/null` the archive is discarded entirely, making
        // it a pure delete. This is the sibling-bypass of the rm-rf-root-
        // home and find-delete-root-home rules: agents that learn `rm -rf`
        // and `find -delete` are blocked simply switch to
        // `tar --remove-files`.
        //
        // Order-agnostic match: `--remove-files` and the sensitive source
        // path can appear in either order (alternation arms below). Both
        // tokens must live inside the SAME shell command segment
        // (`[^|;&]*?`) so a benign tar elsewhere in a compound chain
        // does not taint a separate sensitive-path mention later.
        //
        // Known limitation: `tar --remove-files -cf /etc/foo.tar /tmp/x`
        // (writing the ARCHIVE into /etc, not deleting from it) trips
        // this rule because the regex doesn't position-parse `-cf`'s
        // argument. Accepted: writing tar archives to /etc is itself
        // suspicious and `dcg allow-once` covers the rare legitimate case.
        // Path-tail terminator set includes `)` (in addition to the
        // standard `\s|$|['"]`) so a subshell form like
        // `(tar --remove-files -cf out.tar /etc)` — where /etc is the
        // last token before the closing paren — still classifies as
        // Critical (root-home) rather than falling through to the
        // High-tier general rule. The other sibling rules (rm-rf,
        // find-delete, unlink, truncate-zero, shred) have the same
        // latent gap; closing it pack-wide is tracked separately.
        destructive_pattern!(
            "tar-remove-files-root-home",
            r#"\btar\b[^|;&]*?\s--remove-files\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)|\btar\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?\s--remove-files\b"#,
            "tar --remove-files on a sensitive system or home path is recursive deletion masquerading as an archive operation. EXTREMELY DANGEROUS.",
            Critical,
            "`tar --remove-files -cf <archive> <source>` first archives the source paths \
             into <archive>, then deletes the originals. With a sensitive source \
             (`/etc`, `/usr`, `/var`, `/home/<user>`, `~`, `$HOME`, ...) the result is \
             bytewise-equivalent to `rm -rf <source>`. With `-cf /dev/null` the archive \
             is discarded entirely, making this a pure recursive delete with no audit \
             trail.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Drop `--remove-files`: `tar -cf out.tar <source>` (sources preserved).\n\
             - Two-step with confirmation: `tar -cf out.tar <source> && rm -ri <source>`.\n\
             - Verify the source first: `ls -la <source>`.\n\
             - Allowed for temp dirs: `tar --remove-files -cf out.tar /tmp/<subdir>`.",
            TAR_REMOVE_FILES_SUGGESTIONS
        ),
        // ----- `tar --remove-files ...` (High: any other target) -----
        //
        // Fires after the safe-pattern whitelist (which allows the temp-
        // directory variants). Any other tar-with-remove-files invocation
        // is unscoped destruction that should require human approval, by
        // exact analogy with the parallel `rm-rf-general` /
        // `find-delete-general` rules.
        destructive_pattern!(
            "tar-remove-files-general",
            r"\btar\b[^|;&]*?\s--remove-files\b",
            "tar --remove-files deletes source paths after archiving and requires human approval.",
            High,
            "`tar --remove-files <source>` deletes the source paths once they have been \
             archived. While not as broad as `rm -rf`, a typo or wide glob in the source \
             list destroys files the agent did not intend to remove. With `-cf /dev/null` \
             the archive itself is discarded — the operation becomes a pure delete.\n\n\
             Safer alternatives:\n\
             - Drop `--remove-files` to preserve sources after archiving.\n\
             - Verify the source list with `ls -la` before running.\n\
             - For temp scratch: `tar --remove-files -cf out.tar /tmp/<subdir>` is allowed.",
            TAR_REMOVE_FILES_SUGGESTIONS
        ),
        // ----- `dd of=<sensitive>` (Critical: root/home/system) -----
        //
        // `dd if=/dev/zero of=<file>` (or `if=/dev/urandom of=<file>`)
        // overwrites the file's contents in place — the truncate-equivalent
        // for files. The destruction trigger is the `of=` operand pointing
        // at a sensitive non-/dev path. The `if=` operand is the SOURCE
        // (read-only); only `of=` matters for destruction.
        //
        // Scope: FILES only. Device-level dd (`of=/dev/sda`) is
        // system.disk's territory — `(?!/dev/)` excludes the entire
        // /dev path family from this rule, including /dev/null (which
        // is correctly read-as-discard, never destruction). When
        // system.disk is enabled, it owns device writes; nqhi.8 will
        // promote it to default-enabled.
        //
        // Path-tail terminator set includes `)` so subshell forms like
        // `(dd if=/dev/zero of=/etc/passwd)` still classify as Critical.
        destructive_pattern!(
            "dd-overwrite-root-home",
            r#"\bdd\b[^|;&]*?\bof=['"\\]?(?!/dev/)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
            "dd of=<sensitive-path> overwrites file contents in place. EXTREMELY DANGEROUS on a system or home file.",
            Critical,
            "`dd if=/dev/zero of=<file>` and `dd if=/dev/urandom of=<file>` overwrite the \
             file's contents in place — the `truncate -s 0` equivalent at the dd layer. \
             On a sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or \
             a home-directory key/credential the result is irrecoverable. Even without an \
             explicit input source (`dd of=<file>` reads from stdin), the file's content \
             is destroyed.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Make a backup first: `cp <file> <file>.bak && dd if=/dev/zero of=<file>`.\n\
             - For read-only verification: `dd if=<file> of=/dev/null` (output discarded).\n\
             - For temp scratch: `dd if=/dev/zero of=/tmp/<subdir>/scratch` is allowed.\n\n\
             Device-level dd (`dd of=/dev/sda`) is governed by the `system.disk` pack \
             — enable it for partition-table protection.",
            DD_OVERWRITE_SUGGESTIONS
        ),
        // ----- `dd of=<any-non-tmp>` (High: any other target) -----
        //
        // Fires after the safe-pattern whitelist (which allows the temp-
        // directory variants). `(?!/dev/)` excludes the entire /dev path
        // family (system.disk's scope). Any other dd-with-of= invocation
        // is unscoped destruction that should require human approval, by
        // analogy with `truncate-zero-general` and `shred-general`.
        destructive_pattern!(
            "dd-overwrite-general",
            r#"\bdd\b[^|;&]*?\bof=['"\\]?(?!/dev/)\S"#,
            "dd with of=<file> overwrites file contents and requires human approval.",
            High,
            "`dd of=<file>` overwrites the file's contents (with the input from `if=` \
             or stdin if no input source is given). While not as broad as `rm -rf`, a \
             typo in the target path destroys an unintended file with no possibility of \
             undo.\n\n\
             Safer alternatives:\n\
             - Verify the path first: `ls -la <file>`.\n\
             - Make a backup: `cp <file> <file>.bak && dd if=/dev/zero of=<file>`.\n\
             - Read-only verification: `dd if=<file> of=/dev/null`.\n\
             - For temp scratch: `dd if=/dev/zero of=/tmp/<subdir>/scratch` is allowed.\n\
             - For device writes: enable the `system.disk` pack.",
            DD_OVERWRITE_SUGGESTIONS
        ),
        // ----- `mv <sensitive>` (Critical: cross-segment bypass) -----
        //
        // Closes the canonical cross-segment recursive-force-delete
        // bypass: `mv /etc /tmp/x && rm -rf /tmp/x`. Each segment is
        // individually allowed (mv-to-tmp is benign on its own; rm-rf-
        // in-tmp is safe-pattern-rescued) but the pair destroys /etc.
        // The same shape applies to `mv /etc /dev/null`,
        // `mv /home/user /tmp/$$ && find /tmp/$$ -delete`, and any
        // future "move sensitive away from its semantic location, then
        // delete elsewhere" chain.
        //
        // Approach A from the bead's design: block ANY mv that mentions
        // a sensitive path (source OR destination). Position-parsing
        // mv's args is brittle (`-t target sources...`, multi-source,
        // mixed flags) so we taint the whole command on any sensitive
        // mention. Two consequences worth noting:
        //
        //   1. `mv /etc/hosts /etc/hosts.bak` (in-place rename inside
        //      /etc) blocks. Per the bead's v1 decision: rename within
        //      /etc is rare; allow-once covers legitimate cases.
        //   2. `mv ./build/foo /etc/local-config.bak` (write INTO /etc)
        //      blocks. Modifying /etc from a non-system source is
        //      itself a system change; conservative-block is correct.
        //
        // The sibling propagation rules below cover the three common
        // Approach B shapes (`cp -a`, `ln -s`, `rsync -a`) without trying
        // to become a full shell data-flow engine.
        //
        // /var/tmp false-positive trap: `/var` is in the sensitive set
        // so `mv /var/tmp/foo /var/tmp/bar` matches the destructive
        // regex. The `mv-var-tmp` safe pattern rescues. Same defense
        // applies to literal /tmp moves (which do not trip the destructive
        // regex). Dynamic TMPDIR paths are reviewed separately.
        // The optional-quote group `(?:['"\\]|\$['"])?` extends the
        // historical single-char quote prefix to accept Bash's
        // ANSI-C-quoted (`$'...'`) and locale-translated (`$"..."`)
        // path forms. Without these, `mv $'/etc' /tmp/x` slipped
        // through as a HIGH-impact bypass since mv has no general
        // tier to fall back on.
        destructive_pattern!(
            "mv-sensitive-source-root-home",
            r#"\bmv\b[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
            "mv touching a sensitive system or home path is the cross-segment recursive-force-delete bypass. EXTREMELY DANGEROUS.",
            Critical,
            "`mv /etc /tmp/x && rm -rf /tmp/x` is the canonical cross-segment bypass: \
             each segment is individually allowed (mv-to-tmp is benign; rm-rf-in-tmp \
             is safe) but the pair destroys `/etc`. The same shape closes via \
             `mv /etc /dev/null`, `mv $HOME /tmp/x`, or any \"relocate then delete\" chain.\n\n\
             Any mv that mentions a sensitive path (source OR destination — `/etc`, \
             `/usr`, `/var`, `/home`, `~`, `$HOME`, ...) blocks here, including \
             in-place renames within /etc.\n\n\
             Safer alternatives:\n\
             - Backup with copy + verify + delete:\n  \
               `cp -a <source> <source>.bak && diff -r <source> <source>.bak && rm -rf <source>`\n\
             - Soft-delete via in-place rename: `mv <file> <file>.deleted-YYYYMMDD` \
               (use `dcg allow-once` for the rename, then a follow-up `rm` after a soak period).\n\
             - Pure tmp-to-tmp moves: `mv /tmp/<a> /tmp/<b>` is allowed.",
            MV_SENSITIVE_SUGGESTIONS
        ),
        // Any shell-expanded mv path can resolve to `/`, `/etc`, or another
        // sensitive tree. `mv` intentionally has no broad general tier, so it
        // needs an explicit fail-closed rule for variables, command
        // substitutions, and backslash-obfuscated path traversal.
        destructive_pattern!(
            "mv-dynamic-path",
            r"\bmv\b[^|;&]*[\\$`]",
            "mv with a shell-expanded or escaped path cannot be verified before execution.",
            High,
            "Shell variables and command substitutions are controlled by the calling environment and may resolve to `/`, `/etc`, a home directory, or another persistent tree. Backslash escapes can also hide traversal from lexical path checks, so dcg cannot safely classify this move.\n\n\
             Safer alternatives:\n\
             - Resolve and inspect every path before moving it.\n\
             - Use an explicit literal `/tmp/<subdir>` or `/var/tmp/<subdir>` path.\n\
             - Use `dcg allow-once` only after verifying the resolved source and destination.",
            MV_DYNAMIC_SUGGESTIONS
        ),
        // ----- `> <sensitive>` (Critical: shell redirect truncate) -----
        //
        // Bash output redirection truncates the target file to zero
        // bytes before writing. `> /etc/passwd` (with no command) opens
        // /etc/passwd for write, immediately closes — net effect: file
        // contents destroyed. Same shape:
        //
        //   `> /etc/passwd`                — bare redirect
        //   `: > /etc/passwd`              — null builtin + redirect
        //   `echo > /etc/passwd`           — any command's stdout > path
        //   `cat /dev/null > /etc/passwd`  — pipe /dev/null
        //   `>| /etc/passwd`               — force-overwrite (ignores noclobber)
        //   `&> /etc/passwd`               — stdout+stderr to file
        //   `>& /etc/passwd`               — stdout+stderr to file
        //   `1>| /etc/passwd`              — fd1 force-overwrite
        //   `2> /etc/passwd`               — fd2 to file
        //
        // None of these touch any binary keyword the rest of dcg
        // recognises, so they bypass dcg entirely without this rule.
        // The negative lookbehind `(?<![<>])` excludes append-mode
        // (`>>`) which is non-destructive (only adds content) — the
        // bead's explicit allow-list. The lookbehind is fixed-width 1,
        // safe under fancy-regex.
        //
        // Per the bead's design recommendation (option a): only ship
        // the Critical root-home tier. A `-general` rule would block
        // legitimate workflows like `make > build.log` and `cargo test
        // > test.log`; that tension is not worth the false-positive
        // pain. File-level redirects to non-sensitive paths fall
        // through to default-allow.
        //
        // /tmp / /var/tmp redirects: /tmp isn't in the
        // sensitive set so they don't fire the regex at all; /var/tmp
        // would match /var but we don't bother with a safe rescue
        // because the bead's allow-list is explicit (`> /tmp/scratch`,
        // `: > /tmp/cache`) — those naturally fall through. /var/tmp
        // redirects ARE caught by the regex; if that becomes a real
        // pain we can add a safe pattern later.
        // Two carve-outs in the regex below worth understanding:
        //
        //   1. `(?!/dev/(?:null|zero|full|tty)\b)` — never fire on the
        //      genuinely write-safe character devices. `cmd > /dev/null` and
        //      `cmd 2>&1 > /dev/null` are the most common shell idioms in
        //      existence, and `/dev/null`, `/dev/zero`, `/dev/full`, and the
        //      controlling terminal `/dev/tty` are ALWAYS character devices —
        //      opening them with O_TRUNC cannot destroy persistent data
        //      (#324). `/dev/stdout`, `/dev/stderr`, and `/dev/fd/N` are
        //      deliberately NOT carved out: they are symlinks to whatever fd
        //      0/1/2/N currently point at, which may be a regular file (e.g.
        //      after `exec > logfile` or an inherited redirect), where
        //      O_TRUNC truncates that real file. The #324 carve-out for them
        //      rested on a false premise (that they are always character
        //      devices) and reopened a data-loss path; the guard's
        //      zero-false-negatives posture blocks them instead. The `\b`
        //      keeps `/dev/tty0`..`/dev/ttyN` (consoles / other terminals)
        //      blocked as before.
        //
        //   2. `(?:['"\\]|\$['"])?` — extends the historical optional
        //      single-char quote prefix to also accept the two-byte
        //      Bash quoting introducers `$'` (ANSI-C) and `$"`
        //      (locale-translated). Without this, an attacker could
        //      bypass with `> $'/etc/passwd'` or `> $"/etc/passwd"`.
        destructive_pattern!(
            "redirect-truncate-root-home",
            r#"(?<![<>])(?:&>|>&|\*>|(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?>\|?)\s*(?:['"\\]|\$['"])?(?!/dev/(?:null|zero|full|tty)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
            "shell truncating redirect (including arbitrary numeric, named, and PowerShell all-stream forms) to a sensitive system or home path destroys the previous file contents. EXTREMELY DANGEROUS.",
            Critical,
            "`> /etc/passwd` (or `: > /etc/passwd`, `echo > /etc/passwd`, etc.) opens \
             the target file with O_WRONLY|O_CREAT|O_TRUNC — the contents are destroyed \
             before any write happens. This applies equally to `>|` (force-overwrite), \
             `&>` / `>&` (stdout+stderr to file), and numbered FD forms (`1>`, `2>`, `1>|`, \
             `2>|`). All of these are silent, immediate, irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Use append (`>>`) to preserve existing content: `echo line >> <file>`.\n\
             - Make a backup, then write via a temp file:\n  \
               `cp <file> <file>.bak && echo data > /tmp/<subdir>/out && cp -f /tmp/<subdir>/out <file>`\n  \
               (a truncating redirect straight back onto a home/system path is denied \
               by this same rule).\n\
             - For temp scratch: `> /tmp/<subdir>/scratch` is allowed.\n\
             - Read redirects (`< <file>`) are not affected — they don't truncate.",
            REDIRECT_TRUNCATE_SUGGESTIONS
        ),
        // The shell expands redirect targets at runtime. A variable, command
        // substitution, or backslash-obfuscated suffix can therefore resolve
        // outside an apparent temp path before O_TRUNC opens the file.
        destructive_pattern!(
            "redirect-truncate-dynamic-path",
            r#"(?<![<>])(?:&>|>&|\*>|(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?>\|?)\s*(?:[^|;&\s]*[\\$`]|~[A-Za-z_][^|;&\s]*|(?!(?:/tmp|/var/tmp)(?:/|(?=[\s|;&]|$)))/[^|;&\s]*['"?*\[][^|;&\s]*|[%!][^|;&\s]*|\^(?!(?:/tmp|/var/tmp)(?:/|(?=[\s|;&]|$)))[^|;&\s]+)"#,
            "shell redirect to a dynamic or escaped path may truncate a sensitive file and requires human approval.",
            High,
            "The redirect target is expanded by the shell at runtime, so dcg cannot prove where it points before the file is opened with O_TRUNC.\n\n\
             Safer alternatives:\n\
             - Resolve and inspect the target path first.\n\
             - Use a literal `/tmp/<subdir>/scratch` path for disposable output.\n\
             - Use append (`>>`) when preserving existing content is acceptable.",
            REDIRECT_TRUNCATE_SUGGESTIONS
        ),
        // Classic fork bomb: a no-argument function whose body pipes itself
        // into itself in the background, immediately invoked
        // (`:(){ :|:& };:` and word-named variants). The backreferences
        // enforce that all three identifiers are the same, which is what
        // separates a fork bomb from an ordinary function definition — this
        // deliberately selects the backtracking engine. Differently shaped
        // bombs (`while true; do (x) & done`) are out of scope: the regex
        // crate family cannot enforce those without unbounded false
        // positives, and the canonical form is the one agents actually
        // reproduce (issue #302).
        destructive_pattern!(
            "fork-bomb",
            r"([A-Za-z0-9_:]+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*;?\s*\}\s*;\s*\1",
            "This is a fork bomb: it recursively spawns processes until the system is unusable.",
            Critical,
            "A fork bomb defines a function that pipes itself into itself in the \
             background and then calls it. Process count grows exponentially until \
             the kernel can no longer schedule anything; the machine typically \
             needs a hard reboot, losing all unsaved work in every application.\n\n\
             There is no legitimate reason to run this shape. If you are testing \
             process limits, use `ulimit -u` in a disposable VM or container."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn dequote_rm_flag_token_collapses_balanced_quotes() {
        // bd-5xgt: balanced quotes inside a flag are shell concatenation.
        for (input, want) in [
            ("-r'f'", "-rf"),
            ("-'r'f", "-rf"),
            ("-r\"f\"", "-rf"),
            ("'-r'f", "-rf"),
            ("'-rf'", "-rf"),
            ("-rf''", "-rf"),
            ("'-'r'f'", "-rf"),
            ("-r\\f", "-rf"),
            ("--recursive", "--recursive"),
            ("-rf", "-rf"),
        ] {
            assert_eq!(
                dequote_rm_flag_token(input).as_ref(),
                want,
                "input {input:?}"
            );
        }
        // An unbalanced quote is a syntax error: leave it opaque so it matches
        // no flag (never "repair" it into a destructive one).
        for opaque in ["-r'f", "-r\"f", "-rf\\"] {
            assert_eq!(
                dequote_rm_flag_token(opaque).as_ref(),
                opaque,
                "unbalanced {opaque:?} must stay opaque"
            );
        }
        // A token with no quotes is borrowed unchanged.
        assert!(matches!(
            dequote_rm_flag_token("-rf"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// Issue #302: the canonical fork bomb and word-named variants are
    /// blocked; ordinary function definitions that merely pipe two different
    /// commands are not. Evaluator-level reachability is handled by
    /// `filesystem_semantic_scan_required` (an empty paren pair forces the
    /// pack), not by a pack keyword — see the empty_paren_pair tests and the
    /// evaluator's `fork_bomb_denies_through_full_pipeline_issue_302`.
    #[test]
    fn fork_bomb_is_blocked_issue_302() {
        let pack = create_pack();
        // The fork-bomb rule spans shell separators, so it is matched
        // whole-command (never through `Pack::check`, which is keyword-gated
        // and per-segment). Test the compiled regex and the force check
        // directly; the end-to-end deny is in the evaluator test.
        let fork_bomb = pack
            .destructive_patterns
            .iter()
            .find(|p| p.name == Some("fork-bomb"))
            .expect("fork-bomb rule must exist");
        for bomb in [
            ":(){ :|:& };:",
            "bomb(){ bomb|bomb& };bomb",
            ": () { : | : & ; } ; :",
            "b(){ b|b&;};b",
            // Spaced paren pair — the literal `()` keyword missed this; the
            // space-tolerant force check reaches it.
            ":( ){ :|:& };:",
        ] {
            assert!(
                filesystem_semantic_scan_required(bomb, ShellDialect::Posix),
                "fork bomb must force the pack via semantic scan: {bomb}"
            );
            assert!(
                fork_bomb.regex.is_match(bomb),
                "fork-bomb regex must match: {bomb}"
            );
        }
        // Same-shape functions piping two DIFFERENT commands are not bombs.
        for benign in [
            "serve(){ python|tee & };logs",
            "f(){ a|b& };f",
            "retry(){ curl -s x|jq . ; };retry",
        ] {
            assert!(
                !fork_bomb.regex.is_match(benign),
                "non-self-referential function must not match fork-bomb: {benign}"
            );
        }
    }

    /// The space-tolerant empty-paren detector that gives the fork-bomb rule
    /// its evaluator reachability (issue #302).
    #[test]
    fn empty_paren_pair_detection_issue_302() {
        for present in [":(){ :;}", "foo() {}", ":( ){ }", "x(  )", "arr=()", "$()"] {
            assert!(
                command_contains_empty_paren_pair(present),
                "empty paren pair expected: {present}"
            );
        }
        for absent in [
            "echo hi", "(ls)", "foo(bar)", "$(date)", "$((1+1))", "a || b",
        ] {
            assert!(
                !command_contains_empty_paren_pair(absent),
                "no empty paren pair expected: {absent}"
            );
        }
    }

    /// The `-r`/`-f` rules match the FLAG PAIR, not an argv0, so they also
    /// cover `rm` used as another tool's subcommand. That is deliberate and
    /// load-bearing: `core.filesystem` is always on, whereas the packs that
    /// would otherwise own these commands are opt-in (`database.bigquery`) or
    /// nonexistent (there is no `git rm` rule in `core.git`). Scoping these
    /// rules to `executables = ["rm"]` would read as a clean attribution fix
    /// and silently turn all three of these into ALLOW.
    ///
    /// If you are here because you want that scoping (bead bd-pwvp), first add
    /// the replacement coverage — otherwise this test is the record that you
    /// removed a backstop.
    #[test]
    fn subcommand_rm_stays_covered_by_the_flag_pair_rules() {
        let pack = create_pack();
        for command in [
            "rm -r -f /var/data/old",
            "git rm -r -f src/legacy",
            "bq rm -r -f my_project:my_dataset",
        ] {
            assert!(
                pack.check(command).is_some(),
                "core.filesystem must keep covering `{command}` — it is the \
                 always-on backstop for recursive-force deletion"
            );
        }

        // NOTE on layering: these regexes are `rm\s+...` with no argv0 anchor,
        // so at the PACK level they also match inside a longer word —
        // `pack.check("charm -r -f build")` returns Some. End to end those are
        // correctly ALLOWED, because the evaluator resolves argv0 before the
        // denial stands. Asserting `is_none()` here would therefore be
        // testing the wrong layer, which is exactly the mistake that produced
        // a false positive in the bigquery pack until its regexes were
        // anchored. Tracked separately as a defense-in-depth cleanup.
    }

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "core.filesystem");
        assert_eq!(pack.name, "Core Filesystem");
        assert!(pack.keywords.contains(&"rm"));
        // Required for the find -delete bypass family — see
        // `find-delete-root-home` / `find-delete-general` patterns.
        assert!(pack.keywords.contains(&"find"));
        // Required for phase-1 cross-segment propagation coverage.
        assert!(pack.keywords.contains(&"cp"));
        assert!(pack.keywords.contains(&"ln"));
        assert!(pack.keywords.contains(&"rsync"));
    }

    // ---------- find -delete: closes the rm -rf bypass ----------

    #[test]
    fn find_delete_blocks_root_critical() {
        let pack = create_pack();
        // The historical bypass: agent learns rm -rf is blocked, swaps
        // for the bytewise-equivalent `find -delete`.
        for cmd in [
            "find / -delete",
            "find /etc -delete",
            "find /usr -delete",
            "find /home -delete",
            "find /var -delete",
            "find /boot -delete",
            "find /lib -delete",
            "find /lib64 -delete",
            "find /root -delete",
            "find /sys -delete",
            "find /proc -delete",
            "find /dev -delete",
            "find /opt -delete",
            "find ~ -delete",
            "find $HOME -delete",
            "find ${HOME} -delete",
            // With predicates / extra flags before -delete:
            "find / -depth -delete",
            "find / -type f -delete",
            "find /etc -name '*.conf' -delete",
            "find /home -mindepth 1 -delete",
            // Quoted paths
            "find \"/\" -delete",
            "find '/etc' -delete",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn find_delete_blocks_general_high() {
        let pack = create_pack();
        // Anything that's not under a temp dir and not root/home should
        // still be blocked (High severity, mirrors rm-rf-general).
        for cmd in [
            "find . -delete",
            "find ./node_modules -delete",
            "find . -name '*.pyc' -delete",
            "find /data -delete",
            "find /workspace/build -delete",
            "find ./target -type f -delete",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn find_delete_under_tmp_is_allowed() {
        let pack = create_pack();
        // Mirrors the rm -rf temp whitelist. Critical: only the FIRST
        // path argument matters; safe pattern must NOT short-circuit if
        // a second argument is sensitive (test below).
        for cmd in [
            "find /tmp -delete",
            "find /tmp/foo -delete",
            "find /tmp/foo -name '*.log' -delete",
            "find /var/tmp -delete",
            "find /var/tmp/dir -type f -delete",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn find_delete_with_secondary_sensitive_path_still_blocks() {
        let pack = create_pack();
        // Important: the safe-temp pattern must require EVERY path to be
        // temp-rooted. Without that, an attacker could write
        //   find /tmp/foo /etc -delete
        // and short-circuit through the safe pattern even though /etc
        // would also be deleted. The current safe regex tightly restricts
        // post-find tokens to more temp paths or `-flag [non-path-value]`
        // pairs, so the secondary `/etc` argument fails the safe match
        // and the destructive root-home rule fires. We assert Critical
        // because /etc is in the sensitive-path list.
        let cases = [
            "find /tmp/foo /etc -delete",
            "find /tmp /usr -delete",
            "find /var/tmp/foo /home/user -delete",
            "find $TMPDIR / -delete",
        ];
        for cmd in cases {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn find_without_delete_is_not_blocked() {
        let pack = create_pack();
        // Plain find without the -delete action is read-only.
        for cmd in [
            "find . -name '*.rs'",
            "find / -type f -name passwd",
            "find /etc -ls",
            "find . -print",
            // -exec without rm is not destructive
            "find . -exec cat {} +",
            // -delete is a SUBSTRING of -delete-this-arg; the explicit
            // `(?:\s|$|[;&|])` terminator (instead of `\b`) prevents a
            // false positive here.
            "find . -name -delete-this-not-a-flag",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn find_delete_blocks_in_compound_commands() {
        let pack = create_pack();
        // Regression: the original `^\s*find\b` anchor only matched at the
        // start of the whole sanitized command. Compound forms like
        //   echo foo; find /etc -delete
        //   true && find / -delete
        //   ; find /etc -delete
        // dropped through entirely. Fixed by switching to `\bfind\b` so
        // the destructive rule fires on the embedded `find` invocation.
        for cmd in [
            "true; find / -delete",
            "echo done; find /etc -delete",
            "true && find /etc -delete",
            "false || find /etc -delete",
            "(find /etc -delete)",
            "find /tmp -delete; find /etc -delete", // 2nd segment dangerous
        ] {
            assert_blocks(&pack, cmd, "find");
        }
    }

    #[test]
    fn find_delete_blocks_with_terminating_separator() {
        let pack = create_pack();
        // `-delete;` and `-delete &&` and `-delete |` must terminate the
        // -delete flag. The `(?:\s|$|[;&|])` end set allows shell
        // separators, not just whitespace and end-of-string.
        for cmd in [
            "find /etc -delete; echo done",
            "find /etc -delete && echo done",
            "find /etc -delete | tee log",
            "find /etc -delete&& echo done", // no space before &&
        ] {
            assert_blocks(&pack, cmd, "find");
        }
    }

    #[test]
    fn find_delete_path_prefixed_normalizes_to_bare_find() {
        // PATH_NORMALIZER's capture group includes `find` so
        // `/usr/bin/find / -delete` is normalized to `find / -delete`
        // before the destructive regex runs. This test pins the
        // normalizer contract — if `find` is dropped from the
        // capture, this will fail and downstream pack matching will
        // miss path-prefixed bypasses.
        use crate::normalize::normalize_command;
        for (input, expected_substring) in [
            ("/usr/bin/find / -delete", "find / -delete"),
            ("/usr/local/bin/find /etc -delete", "find /etc -delete"),
            ("/bin/find /home -delete", "find /home -delete"),
            ("/sbin/find /etc -delete", "find /etc -delete"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected_substring),
                "PATH_NORMALIZER did not strip `{input}` to expected form `{expected_substring}` (got `{normalized}`)"
            );
        }
    }

    #[test]
    fn find_temp_compound_blocks_conservatively() {
        let pack = create_pack();
        // The safe pattern is whole-command anchored (`^...$`), NOT
        // segment-aware. Compound forms with a temp `find -delete` are
        // BLOCKED rather than allowed — this is a deliberate
        // false-positive trade-off to prevent the bypass:
        //   find /tmp -delete; find /etc -delete
        // (a segment-aware safe would shadow the whole pack's destructive
        // rules for the second segment, allowing /etc deletion).
        //
        // Users hitting this can `dcg allow-once <code>` for one-offs
        // or add a temporary allowlist entry for recurring scripts.
        for cmd in [
            "echo done; find /tmp -delete",
            "true && find /tmp -delete",
            "echo done; find /tmp/foo -delete",
            "echo done; find $TMPDIR -delete",
        ] {
            assert_blocks(&pack, cmd, "find");
        }
    }

    #[test]
    fn find_temp_safe_only_when_whole_command() {
        let pack = create_pack();
        // The safe pattern fires only on a clean, single-command
        // invocation. This is the intended trade-off (see
        // find_temp_compound_blocks_conservatively for rationale).
        for cmd in [
            "find /tmp -delete",
            "find /tmp/foo -delete",
            "find /tmp -name '*.log' -delete",
            "find /tmp/foo -name '*.tmp' -delete",
            "find /var/tmp -delete",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    // ---------- unlink (nqhi.3) ----------

    #[test]
    fn unlink_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            "unlink /etc/passwd",
            "unlink /etc/shadow",
            "unlink /etc/sudoers",
            "unlink /usr/bin/sudo",
            "unlink /boot/vmlinuz",
            "unlink ~/.bashrc",
            "unlink ~/.ssh/id_ed25519",
            "unlink $HOME/.gnupg/secring.gpg",
            "unlink ${HOME}/.aws/credentials",
            "unlink \"/etc/passwd\"",
            "unlink '/etc/shadow'",
            // Compound forms.
            "echo done; unlink /etc/passwd",
            "true && unlink /etc/passwd",
            "(unlink /etc/passwd)",
            // Wrappers.
            "sudo unlink /etc/passwd",
            "env FOO=bar unlink /etc/passwd",
            // Path-prefixed (PATH_NORMALIZER strips it).
            "/usr/bin/unlink /etc/passwd",
            "/bin/unlink /etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn unlink_blocks_general_high() {
        let pack = create_pack();
        // Anything outside temp dirs — High severity, mirrors rm-rf-general.
        for cmd in [
            "unlink ./important.db",
            "unlink ./build/output.bin",
            "unlink secrets.txt",
            "unlink /data/important",
            "unlink /workspace/build/critical.bin",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn unlink_under_tmp_is_allowed() {
        let pack = create_pack();
        // Whole-command anchor — single invocation only.
        for cmd in [
            "unlink /tmp/scratch",
            "unlink /tmp/foo/bar",
            "unlink /var/tmp/cache",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn unlink_help_is_allowed() {
        let pack = create_pack();
        // unlink --help / --version are read-only.
        for cmd in ["unlink --help", "unlink --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn unlink_path_traversal_in_tmp_is_blocked() {
        let pack = create_pack();
        // The safe regex's negative lookahead rejects `..` traversal.
        for cmd in [
            "unlink /tmp/../etc/passwd",
            "unlink /tmp/foo/../../etc/shadow",
            "unlink $TMPDIR/../etc/passwd",
        ] {
            // Path-traversal should NOT match the safe pattern. The
            // command falls through to destructive evaluation. Whether
            // it lands on root-home or general depends on the literal
            // sensitive substring; we only assert it blocks SOMEHOW.
            assert_blocks(&pack, cmd, "unlink");
        }
    }

    #[test]
    fn unlink_compound_with_temp_blocks_conservatively() {
        let pack = create_pack();
        // Same trade-off as find-delete: compound forms block even when
        // the unlink target is /tmp. Users `dcg allow-once` for the
        // legitimate cases.
        for cmd in [
            "echo done; unlink /tmp/scratch",
            "true && unlink /tmp/scratch",
        ] {
            assert_blocks(&pack, cmd, "unlink");
        }
    }

    #[test]
    fn unlink_no_false_positive_substring_traps() {
        let pack = create_pack();
        // `unlink` substring inside other paths/commands must NOT trip.
        for cmd in [
            "cat /etc/unlink-script.sh",
            "ls unlink-foo.txt",
            "echo unlink",
            // unlink without an argument doesn't match (regex requires \S).
            "unlink",
            "unlink ",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn unlink_path_prefixed_normalizes_to_bare() {
        // PATH_NORMALIZER strips `/usr/bin/unlink` to bare `unlink`.
        // Pin the contract — if `unlink` is dropped from the capture,
        // path-prefixed bypasses re-open.
        use crate::normalize::normalize_command;
        for (input, expected) in [
            ("/usr/bin/unlink /etc/passwd", "unlink /etc/passwd"),
            ("/bin/unlink /etc/shadow", "unlink /etc/shadow"),
            ("/usr/local/bin/unlink /etc/sudoers", "unlink /etc/sudoers"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- truncate (nqhi.1) ----------

    #[test]
    fn truncate_blocks_zero_root_critical() {
        let pack = create_pack();
        for cmd in [
            "truncate -s 0 /etc/passwd",
            "truncate -s 0 /etc/shadow",
            "truncate -s 0 /etc/sudoers",
            "truncate -s 1 /etc/passwd",
            "truncate --size=1 /etc/shadow",
            "truncate -s 0 /usr/bin/sudo",
            "truncate -s 0 /boot/vmlinuz",
            "truncate -s 0 ~/.bashrc",
            "truncate -s 0 $HOME/.aws/credentials",
            "truncate -s 0 ${HOME}/.gnupg/secring.gpg",
            "truncate --size=0 /etc/passwd",
            // shrink form
            "truncate -s -100 /etc/passwd",
            "truncate -s -1024 /etc/hosts",
            "truncate --size=-100 /etc/passwd",
            // compound forms
            "echo done; truncate -s 0 /etc/passwd",
            "true && truncate -s 0 /etc/passwd",
            "(truncate -s 0 /etc/passwd)",
            // wrappers
            "sudo truncate -s 0 /etc/passwd",
            "env FOO=bar truncate -s 0 /etc/passwd",
            // path-prefixed
            "/usr/bin/truncate -s 0 /etc/passwd",
            "/bin/truncate --size=0 /etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn truncate_blocks_zero_general_high() {
        let pack = create_pack();
        for cmd in [
            "truncate -s 0 ./important.db",
            "truncate -s 1 ./important.db",
            "truncate --size=1 build/output.bin",
            "truncate -s 0 build/output.bin",
            "truncate --size=0 secrets.txt",
            "truncate -s -100 ./large.log",
            "truncate -s 0 /data/important",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn truncate_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "truncate -s 0 /tmp/scratch.bin",
            "truncate -s 1G /tmp/sparse-file.bin",
            "truncate -s 0 /var/tmp/cache.bin",
            "truncate -s 100M /var/tmp/test.img",
            "truncate -s -100 /tmp/log.txt",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn truncate_grow_is_allowed_anywhere() {
        let pack = create_pack();
        // Pure-growth `+N` does not destroy data — allowed everywhere.
        for cmd in [
            "truncate -s +1024 ./output.bin",
            "truncate -s +1G /var/log/sparse",
            "truncate --size=+100M ./preallocated",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn truncate_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["truncate --help", "truncate --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn truncate_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat /etc/truncate-readme.txt",
            "ls truncate-script.sh",
            "echo truncate",
            // no -s 0 / shrink → no destructive match. truncate WITHOUT
            // a destructive size operand falls through to default-allow.
            "truncate -r ref.bin out.bin",
            "truncate --reference=ref.bin out.bin",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn truncate_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            (
                "/usr/bin/truncate -s 0 /etc/passwd",
                "truncate -s 0 /etc/passwd",
            ),
            (
                "/bin/truncate --size=0 /etc/shadow",
                "truncate --size=0 /etc/shadow",
            ),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- shred (nqhi.2) ----------

    #[test]
    fn shred_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            "shred /etc/passwd",
            "shred -u /etc/passwd",
            "shred -fzu /etc/shadow",
            "shred --remove /etc/hosts",
            "shred -n 3 -u /etc/passwd",
            "shred -u ~/.ssh/id_ed25519",
            "shred -u $HOME/.aws/credentials",
            "shred -u ${HOME}/.gnupg/secring.gpg",
            "shred -fzu /usr/bin/sudo",
            "shred -u /boot/vmlinuz",
            // compound forms
            "echo done; shred -u /etc/passwd",
            "true && shred -u /etc/passwd",
            "(shred -u /etc/passwd)",
            // wrappers
            "sudo shred -u /etc/passwd",
            "env FOO=bar shred -u /etc/passwd",
            // path-prefixed
            "/usr/bin/shred -fzu /etc/passwd",
            "/bin/shred -u /etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
        }
    }

    #[test]
    fn shred_blocks_general_high() {
        let pack = create_pack();
        for cmd in [
            "shred ./important.db",
            "shred -u ./secrets.txt",
            "shred -fzu build/output.bin",
            "shred -u /data/private",
            "shred --remove /workspace/build/critical.bin",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
        }
    }

    #[test]
    fn shred_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "shred -u /tmp/scratch.bin",
            "shred -fzu /tmp/foo/cache",
            "shred -u /var/tmp/cache.bin",
            "shred -n 1 -u /tmp/scratch",
            "shred /tmp/foo/output",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn shred_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["shred --help", "shred --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn shred_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat /etc/shred-readme.txt",
            "ls shred-script.sh",
            "echo shred",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn shred_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            ("/usr/bin/shred -u /etc/passwd", "shred -u /etc/passwd"),
            ("/bin/shred -fzu /etc/shadow", "shred -fzu /etc/shadow"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- tar --remove-files: archive-then-delete bypass family ----------

    #[test]
    fn tar_remove_files_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            // Flag before source.
            "tar --remove-files -cf out.tar /etc",
            "tar --remove-files -czf out.tar.gz /home/user",
            "tar --remove-files -cf out.tar /usr/local",
            // Source before flag.
            "tar -cf out.tar --remove-files /etc",
            "tar -cf out.tar /etc --remove-files",
            // Delete-only (discarded archive).
            "tar --remove-files -cf /dev/null /etc",
            // Quoted sensitive paths.
            "tar --remove-files -cf out.tar \"/etc\"",
            "tar --remove-files -cf out.tar '/etc'",
            // Home variants.
            "tar --remove-files -cf out.tar ~/.ssh",
            "tar --remove-files -cf out.tar $HOME/.aws",
            "tar --remove-files -cf out.tar ${HOME}/.gnupg",
            // Compound forms (\btar\b matches at any boundary).
            "echo done; tar --remove-files -cf out.tar /etc",
            "true && tar --remove-files -cf out.tar /etc",
            "(tar --remove-files -cf out.tar /etc)",
            // Wrappers.
            "sudo tar --remove-files -cf out.tar /etc",
            "env FOO=bar tar --remove-files -cf out.tar /etc",
            // Path-prefixed (PATH_NORMALIZER).
            "/usr/bin/tar --remove-files -cf out.tar /etc",
            "/bin/tar --remove-files -cf out.tar /etc",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "tar-remove-files-root-home");
        }
    }

    #[test]
    fn tar_remove_files_blocks_general_high() {
        let pack = create_pack();
        for cmd in [
            "tar --remove-files -cf out.tar ./build",
            "tar --remove-files -cf out.tar important.db",
            "tar --remove-files -cf out.tar ./workspace",
            "tar -cf out.tar --remove-files data.json",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
            assert_blocks_with_pattern(&pack, cmd, "tar-remove-files-general");
        }
    }

    #[test]
    fn tar_remove_files_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "tar --remove-files -cf out.tar /tmp/scratch",
            "tar -cf out.tar --remove-files /tmp/foo",
            "tar --remove-files -czf out.tar.gz /var/tmp/cache",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn tar_without_remove_files_is_allowed() {
        let pack = create_pack();
        // No --remove-files = pure archive/extract/list — destructive
        // pattern requires the flag, so these fall through to default-allow.
        for cmd in [
            "tar -cf out.tar /etc",
            "tar -czf out.tar.gz /home/user",
            "tar -xf in.tar",
            "tar -xzf in.tar.gz -C /tmp",
            "tar -tf in.tar",
            "tar --help",
            "tar --version",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn tar_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat tar-readme.md",
            "ls /etc/tar-config",
            "echo --remove-files",
            // Bare --remove-files appears (e.g. as a documented flag),
            // but no `tar` invocation: must not match.
            "grep --remove-files docs/",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn tar_remove_files_mixed_sources_blocks_via_general() {
        // `tar --remove-files -cf out.tar /tmp/foo /etc/bar` — the safe
        // /tmp/foo source does NOT rescue because /etc/bar is a sensitive
        // co-source. The root-home rule must fire.
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "tar --remove-files -cf out.tar /tmp/foo /etc/bar",
            "tar-remove-files-root-home",
        );
    }

    #[test]
    fn tar_remove_files_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            (
                "/usr/bin/tar --remove-files -cf out.tar /etc",
                "tar --remove-files -cf out.tar /etc",
            ),
            (
                "/bin/tar --remove-files -cf out.tar /home/user",
                "tar --remove-files -cf out.tar /home/user",
            ),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- dd of=: file-level overwrite (truncate-equivalent) ----------

    #[test]
    fn dd_overwrite_blocks_root_critical() {
        let pack = create_pack();
        for cmd in [
            // Canonical form.
            "dd if=/dev/zero of=/etc/passwd",
            "dd if=/dev/urandom of=/etc/shadow",
            "dd if=/dev/zero of=/etc/sudoers",
            // With bs/count operands.
            "dd if=/dev/zero of=/etc/passwd bs=1M count=10",
            "dd if=/dev/urandom of=/etc/shadow bs=4096 count=1",
            // Operand order swapped (of= first).
            "dd of=/etc/passwd if=/dev/zero",
            "dd of=/etc/passwd if=/dev/zero bs=1M",
            // No if= operand (reads from stdin — still destroys content).
            "dd of=/etc/passwd",
            // Quoted paths.
            "dd if=/dev/zero of=\"/etc/passwd\"",
            "dd if=/dev/zero of='/etc/shadow'",
            // Home variants.
            "dd if=/dev/zero of=~/.ssh/id_ed25519",
            "dd if=/dev/zero of=$HOME/.aws/credentials",
            "dd if=/dev/zero of=${HOME}/.gnupg/secring.gpg",
            // Other system roots.
            "dd if=/dev/zero of=/usr/bin/sudo",
            "dd if=/dev/zero of=/boot/vmlinuz",
            // Compound forms.
            "echo done; dd if=/dev/zero of=/etc/passwd",
            "true && dd if=/dev/zero of=/etc/passwd",
            "(dd if=/dev/zero of=/etc/passwd)",
            // Wrappers.
            "sudo dd if=/dev/zero of=/etc/passwd",
            "env FOO=bar dd if=/dev/zero of=/etc/passwd",
            // Path-prefixed.
            "/usr/bin/dd if=/dev/zero of=/etc/passwd",
            "/bin/dd if=/dev/zero of=/etc/shadow",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "dd-overwrite-root-home");
        }
    }

    #[test]
    fn dd_overwrite_blocks_general_high() {
        let pack = create_pack();
        for cmd in [
            "dd if=/dev/zero of=./important.db",
            "dd if=/dev/urandom of=secrets.txt",
            "dd if=/dev/zero of=build/output.bin bs=1M count=10",
            "dd of=workspace/critical.bin",
            "dd if=/dev/zero of=/data/important",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::High);
            assert_blocks_with_pattern(&pack, cmd, "dd-overwrite-general");
        }
    }

    #[test]
    fn dd_to_dev_null_is_allowed() {
        // Read-only dd with output discarded — this is the canonical
        // way to test read speed of a sensitive file. Must NOT block.
        // The pack's destructive regex excludes /dev/ entirely, so
        // these fall through to default-allow without needing a safe
        // pattern.
        let pack = create_pack();
        for cmd in [
            "dd if=/etc/passwd of=/dev/null",
            "dd if=/etc/shadow of=/dev/null bs=1M",
            "dd if=/dev/sda of=/dev/null count=1024",
            "dd if=/etc/sudoers of=/dev/zero",
            "dd if=/etc/passwd of=/dev/full",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn dd_to_device_falls_through_to_system_disk() {
        // Out of scope per bead: device-level dd (`of=/dev/sda`) is
        // governed by the system.disk pack, not core.filesystem. The
        // `(?!/dev/)` lookahead in our regex excludes /dev entirely.
        let pack = create_pack();
        for cmd in [
            "dd if=/dev/zero of=/dev/sda",
            "dd if=/dev/urandom of=/dev/sdb1",
            "dd of=/dev/loop0 if=/tmp/img",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn dd_backup_to_tmp_from_sensitive_is_allowed() {
        // `dd if=/etc/passwd of=/tmp/passwd.bak` — backup (READ from
        // sensitive, WRITE to tmp). The destructive trigger is `of=`,
        // not `if=`; since `of=/tmp/...` matches the safe whitelist,
        // this is NOT destruction.
        let pack = create_pack();
        for cmd in [
            "dd if=/etc/passwd of=/tmp/passwd.bak",
            "dd if=/etc/shadow of=/tmp/shadow.backup",
            "dd if=/home/user/.ssh/id_ed25519 of=/tmp/keybackup",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn dd_under_tmp_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "dd if=/dev/zero of=/tmp/scratch.bin bs=1M count=10",
            "dd if=/dev/urandom of=/tmp/random.bin bs=4096 count=1",
            "dd if=/dev/zero of=/var/tmp/cache.bin",
            "dd of=/tmp/out.bin",
            "dd of=/tmp/out.bin if=/dev/zero",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn dd_only_the_final_output_operand_determines_safety() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "dd if=/dev/zero of=/tmp/scratch of=/etc/passwd",
            Severity::Critical,
        );
        assert_safe_pattern_matches(&pack, "dd if=/dev/zero of=/etc/passwd of=/tmp/scratch");
    }

    #[test]
    fn dd_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["dd --help", "dd --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn dd_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            // `dd` is a 2-char common substring. Word-boundary `\bdd\b`
            // must reject these.
            "echo address",
            "ls add-ons.txt",
            "cat odd.log",
            "echo dd-script",
            "ls dd-readme.md",
            // `dd` alone (no `of=` operand).
            "dd",
            "dd if=/dev/zero",
            "dd if=/etc/passwd",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn dd_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            (
                "/usr/bin/dd if=/dev/zero of=/etc/passwd",
                "dd if=/dev/zero of=/etc/passwd",
            ),
            (
                "/bin/dd if=/dev/urandom of=/etc/shadow",
                "dd if=/dev/urandom of=/etc/shadow",
            ),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- mv: cross-segment recursive-force-delete bypass ----------

    #[test]
    fn mv_sensitive_source_blocks_critical() {
        let pack = create_pack();
        for cmd in [
            // Canonical bypass shape (only the mv portion is asserted;
            // the && rm -rf /tmp/x second segment is independently
            // safe-rescued by rm-rf-tmp).
            "mv /etc /tmp/x",
            "mv /etc/passwd /tmp/passwd-deleted",
            "mv /home/user /tmp/relocated",
            "mv $HOME /tmp/x",
            "mv ${HOME} /tmp/x",
            "mv ~/.ssh /tmp/keys",
            "mv /usr/local /tmp/x",
            "mv /var/log /tmp/log-relocated",
            // /dev/null silent destruction.
            "mv /etc /dev/null",
            "mv /home/user /dev/null",
            // Destination is sensitive (writing INTO /etc).
            "mv ./build/foo /etc/local-config.bak",
            "mv ./key.pem /home/user/.ssh/id_rsa",
            // In-place rename within /etc — bead's v1 decision: BLOCK.
            "mv /etc/hosts /etc/hosts.bak",
            "mv /etc/passwd /etc/passwd.old",
            // With flags.
            "mv -v /etc /tmp/x",
            "mv -f /etc /tmp/x",
            "mv -t /tmp/x /etc",
            "mv --backup=numbered /etc /tmp/x",
            // Quoted paths.
            "mv \"/etc\" /tmp/x",
            "mv '/etc' /tmp/x",
            // Compound forms.
            "echo done; mv /etc /tmp/x",
            "true && mv /etc /tmp/x",
            "(mv /etc /tmp/x)",
            // Wrappers.
            "sudo mv /etc /tmp/x",
            "env FOO=bar mv /etc /tmp/x",
            // Path-prefixed.
            "/usr/bin/mv /etc /tmp/x",
            "/bin/mv /etc /tmp/x",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "mv-sensitive-source-root-home");
        }
    }

    #[test]
    fn mv_no_sensitive_path_is_allowed() {
        let pack = create_pack();
        // No sensitive path in source OR dest → destructive rule doesn't
        // fire → default-allow.
        for cmd in [
            "mv ./old.txt ./new.txt",
            "mv build/output.bin dist/",
            "mv foo.log foo.log.1",
            "mv ./src/a.rs ./src/b.rs",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn sensitive_propagation_then_delete_blocks_critical() {
        let pack = create_pack();
        for (cmd, pattern) in [
            (
                "cp -al /etc /tmp/x && rm -rf /tmp/x",
                "cp-sensitive-then-delete",
            ),
            (
                "cp --archive /etc/passwd /tmp/passwd && rm -fr /tmp/passwd",
                "cp-sensitive-then-delete",
            ),
            (
                "sudo cp -a /home/user/.ssh /var/tmp/keys && rm --recursive --force /var/tmp/keys",
                "cp-sensitive-then-delete",
            ),
            (
                "ln -s /etc /tmp/x && rm -rf /tmp/x/.",
                "ln-symlink-sensitive-then-delete",
            ),
            (
                "ln -sf $HOME /tmp/home && rm -rf /tmp/home/.",
                "ln-symlink-sensitive-then-delete",
            ),
            (
                "rsync -a /etc/ /tmp/dest/ && rm -rf /tmp/dest",
                "rsync-sensitive-then-delete",
            ),
            (
                "rsync --archive /home/user/ /var/tmp/home/ && rm -f -r /var/tmp/home",
                "rsync-sensitive-then-delete",
            ),
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, pattern);
        }
    }

    #[test]
    fn sensitive_propagation_without_delete_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "cp -a /etc /tmp/x",
            "cp --archive /etc/passwd /tmp/passwd",
            "ln -s /etc /tmp/x",
            "rsync -a /etc/ /tmp/dest/",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn non_sensitive_propagation_then_delete_is_allowed() {
        let pack = create_pack();
        for cmd in [
            "cp -al /tmp/a /tmp/b && rm -rf /tmp/b",
            "cp --archive ./build /tmp/build && rm -fr /tmp/build",
            "ln -s /tmp/a /tmp/b && rm -rf /tmp/b/.",
            "rsync -a ./target/ /tmp/target/ && rm -rf /tmp/target",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "non-sensitive temp propagation should be allowed: {cmd}",
            );
        }
    }

    #[test]
    fn mv_under_tmp_is_allowed() {
        let pack = create_pack();
        // All tmp-family moves are rescued by the explicit safe patterns
        // (mv-tmp / mv-var-tmp). For /var/tmp
        // the safe pattern is load-bearing because /var is sensitive and
        // would otherwise trip the destructive rule. Variable-rooted paths
        // are deliberately excluded because TMPDIR is caller-controlled.
        for cmd in [
            "mv /tmp/foo /tmp/bar",
            "mv /tmp/foo /tmp/sub/bar",
            "mv -v /tmp/foo /tmp/bar",
            "mv /var/tmp/foo /var/tmp/bar",
            "mv /var/tmp/dir1 /var/tmp/dir2",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn ambient_tmpdir_roots_are_not_automatically_safe() {
        let pack = create_pack();
        for cmd in [
            "find $TMPDIR -delete",
            "find ${TMPDIR}/work -delete",
            "unlink $TMPDIR/file",
            "truncate -s 0 ${TMPDIR}/cache.bin",
            "shred -u $TMPDIR/file",
            "tar --remove-files -cf out.tar ${TMPDIR}/scratch",
            "dd if=/dev/zero of=$TMPDIR/cache.bin",
            "mv $TMPDIR/foo $TMPDIR/bar",
            "mv ${TMPDIR}/foo ${TMPDIR}/bar",
            "export TMPDIR=/; find $TMPDIR/etc -delete",
            "TMPDIR=/etc; unlink $TMPDIR/passwd",
            "find /tmp/$TARGET -delete",
            "unlink /tmp/$TARGET",
            "truncate -s 0 /tmp/$TARGET",
            "shred -u /tmp/$TARGET",
            "tar --remove-files -cf out.tar /tmp/$TARGET",
            "dd if=/dev/zero of=/tmp/$TARGET",
            "mv /tmp/$SOURCE /tmp/$DESTINATION",
            r"unlink /tmp/.\./etc/passwd",
        ] {
            assert!(
                pack.check(cmd).is_some(),
                "dynamic temp-root command must be reviewed: {cmd}"
            );
        }
    }

    #[test]
    fn mv_help_is_allowed() {
        let pack = create_pack();
        for cmd in ["mv --help", "mv --version"] {
            assert_safe_pattern_matches(&pack, cmd);
        }
    }

    #[test]
    fn mv_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            "cat mv-script.sh",
            "ls mv-readme.md",
            "echo mv",
            "echo amv-tools",
            // No `mv` invocation at all — sensitive paths in unrelated
            // commands must not falsely match.
            "ls /etc",
            "cat /etc/passwd",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn mv_path_prefixed_normalizes_to_bare() {
        use crate::normalize::normalize_command;
        for (input, expected) in [
            ("/usr/bin/mv /etc /tmp/x", "mv /etc /tmp/x"),
            ("/bin/mv /home/user /tmp/x", "mv /home/user /tmp/x"),
        ] {
            let normalized = normalize_command(input);
            assert!(
                normalized.contains(expected),
                "PATH_NORMALIZER did not strip `{input}` to `{expected}` (got `{normalized}`)"
            );
        }
    }

    // ---------- redirect-truncate: shell-syntax truncate-equivalent ----------

    #[test]
    fn redirect_truncate_blocks_critical() {
        let pack = create_pack();
        for cmd in [
            // Bare redirect (no command).
            "> /etc/passwd",
            ">/etc/passwd",
            // Null builtin + redirect (common idiom).
            ": > /etc/passwd",
            ": >/etc/shadow",
            // Any command stdout > sensitive.
            "echo > /etc/passwd",
            "echo \"x\" > /etc/passwd",
            "cat /dev/null > /etc/passwd",
            "printf foo > /etc/sudoers",
            // Force-overwrite (>|).
            ">| /etc/passwd",
            "echo x >| /etc/passwd",
            // stdout+stderr (&> / >&).
            "&> /etc/passwd",
            "make &> /etc/log",
            ">& /etc/passwd",
            "make >& /etc/log",
            "make >&/etc/log",
            // Numbered FDs.
            "echo x 1> /etc/passwd",
            "echo x 2> /etc/passwd",
            "echo x 0> /etc/passwd",
            "echo x 3> /etc/passwd",
            "echo x 17>| /etc/passwd",
            "echo x 1>| /etc/passwd",
            "echo x 2>| /etc/passwd",
            // Bash named descriptors and PowerShell's all-stream redirect.
            "echo x {audit}> /etc/passwd",
            "Write-Output x *> /etc/passwd",
            // Home variants.
            "echo x > ~/.ssh/id_ed25519",
            "echo x > $HOME/.aws/credentials",
            "echo x > ${HOME}/.gnupg/secring.gpg",
            // Other system roots.
            "echo x > /usr/bin/sudo",
            "echo x > /boot/vmlinuz",
            // Quoted sensitive paths.
            "echo x > \"/etc/passwd\"",
            "echo x > '/etc/shadow'",
            // Compound forms.
            "echo done; > /etc/passwd",
            "true && > /etc/passwd",
            "(> /etc/passwd)",
            // Wrappers.
            "sudo bash -c '> /etc/passwd'",
            // Leading whitespace (script formatting / heredoc bodies).
            "  > /etc/passwd",
            "\t> /etc/passwd",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_append_is_allowed() {
        // `>>` is append (non-destructive); the destructive regex's
        // negative lookbehind `(?<![<>])` excludes it. Even on
        // sensitive paths, append must NOT block.
        let pack = create_pack();
        for cmd in [
            "echo line >> /etc/syslog",
            "echo line >> ~/.bashrc",
            "make >> build.log",
            "echo line >> /etc/passwd",
            "echo line >> /etc/shadow",
            "command >> /usr/local/log",
            "echo x &>> /etc/log",
            "echo x 1>> /etc/passwd",
            "echo x 2>> /etc/passwd",
            "echo x 17>> /etc/passwd",
            "echo x {audit}>> /etc/passwd",
            "Write-Output x *>> /etc/passwd",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_to_non_sensitive_is_allowed() {
        // No `-general` tier (per bead's option-a recommendation):
        // these legitimate workflows must NOT block.
        let pack = create_pack();
        for cmd in [
            "make > build.log",
            "cargo test > test.log",
            "echo x > ./output.txt",
            "echo x > foo.log",
            "ls > files.txt",
            "command > /tmp/scratch",
            "echo x >| build.log",
            "echo x &> build.log",
            "echo x >& build.log",
            "echo x 2> err.log",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_truncate_to_dynamic_path_is_blocked() {
        let pack = create_pack();
        for cmd in [
            "echo data > $TMPDIR/passwd",
            "echo data > ${TMPDIR}/passwd",
            "echo data > ${TMPDIR:-/tmp}/passwd",
            "echo data > /tmp/$TARGET",
            "echo data>$LOG_FILE",
            r"echo data > /tmp/.\./etc/passwd",
            "echo data 2> `dynamic-path`",
            ": > ~root/.ssh/authorized_keys",
            ": > /e''tc/passwd",
            ": > /e\"tc\"/passwd",
            ": > /et?/passwd",
            "echo x >%TARGET%",
            "echo x >!TARGET!",
            "echo x >^/etc/passwd",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-dynamic-path");
        }

        for cmd in [
            r#": > "/tmp/literal""#,
            ": > '/tmp/literal'",
            ": > /tmp/e''tc/passwd",
            ": > /tmp/et?/passwd",
            "echo x >^/tmp/output",
            "echo x >>%TARGET%",
            "echo x <>%TARGET%",
            "echo x 3>&1",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_read_is_allowed() {
        // Read redirects (`<`, `<<`, `<<<`) don't truncate anything.
        let pack = create_pack();
        for cmd in [
            "cat < /etc/passwd",
            "wc -l < /etc/hosts",
            "sort < /etc/passwd > /tmp/sorted",
            "while read line; do echo $line; done < /etc/hosts",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_fd_is_allowed() {
        // `1>&2` and `2>&1` redirect FD-to-FD, not file truncation.
        // The regex's `\s*['"]?<sensitive>` clause requires `/`/`~`/
        // `$HOME` next, which fd numbers and `-` don't satisfy.
        let pack = create_pack();
        for cmd in [
            "echo x 1>&2",
            "echo x 2>&1",
            "command 2>&1 | tee log.txt",
            "echo x >&2",
            "exec >&-",
            "echo x 3>&1",
            "echo x {audit}>&1",
            "Write-Output x *>&1",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_no_false_positive_substring_traps() {
        let pack = create_pack();
        for cmd in [
            // Comparison operators in unrelated commands.
            "test 5 > 3",
            "[ \"a\" \\> \"b\" ]",
            // No redirect at all.
            "ls /etc",
            "cat /etc/passwd",
            // Not a `>` redirect (heredoc indicator, not output redirect).
            "cat <<EOF",
            "cat <<<\"input\"",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_dev_null_zero_full_is_allowed_universally() {
        // Regression guard for the most common shell idiom: discarding
        // output to /dev/null. The `(?!/dev/(?:null|zero|full)\b)`
        // lookahead in `redirect-truncate-root-home` exempts these
        // sinks; without it, every script that suppresses output (which
        // is essentially every script) would be blocked.
        let pack = create_pack();
        for cmd in [
            "command > /dev/null",
            "command >/dev/null",
            "command 2>&1 > /dev/null",
            "command > /dev/null 2>&1",
            "command 2> /dev/null",
            "command &> /dev/null",
            "cat /etc/passwd > /dev/null",
            "find . > /dev/null 2>&1",
            "make > /dev/zero",
            "echo test > /dev/full",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_dev_devices_still_blocks() {
        // The write-safe-device carve-out must NOT relax actual device
        // destruction (`> /dev/sda` etc.) — only the safe sinks. This
        // includes near-misses of the #324 carve-out: `/dev/st0` is a
        // TAPE device (truncate-adjacent name, real data), `/dev/tty0`
        // and `/dev/ttys002` are other terminals/consoles, and
        // `/dev/fd/N` for N > 2 can dup a regular-file descriptor where
        // O_TRUNC truncates a real file.
        let pack = create_pack();
        for cmd in [
            "> /dev/sda",
            "echo zero > /dev/sda1",
            "command > /dev/sdb",
            "echo > /dev/nvme0n1",
            "echo > /dev/st0",
            "echo > /dev/tty0",
            "echo > /dev/ttys002",
            "echo x > /dev/fd/3",
            "echo x > /dev/fd/7",
            "echo x > /dev/fd/12",
            "echo x > /dev/stdouts",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_to_controlling_terminal_is_allowed() {
        // `/dev/tty` is the controlling terminal — always a character
        // device, never a regular file — so opening it with O_TRUNC cannot
        // destroy persistent data. It stays carved out alongside
        // /dev/null|zero|full.
        let pack = create_pack();
        for cmd in [
            "echo prompt > /dev/tty",
            "read -p x < /dev/tty > /dev/tty",
            "echo x > /dev/null",
            "echo x > /dev/zero",
            "echo x > /dev/full",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_to_std_stream_symlinks_blocks() {
        // `/dev/stdout`, `/dev/stderr`, and `/dev/fd/N` are symlinks to
        // whatever fd 0/1/2/N currently point at — which may be a regular
        // file (after `exec > logfile`, or an inherited redirect). Opening
        // them with O_TRUNC then truncates that real file, so the #324
        // carve-out for them was unsound and is removed: the guard blocks
        // them under its zero-false-negatives posture.
        let pack = create_pack();
        for cmd in [
            "gh pr view 204 --json number,title > /dev/stdout",
            "command > /dev/stdout",
            "command >/dev/stdout",
            "command > /dev/stderr",
            "echo warn 1> /dev/stderr",
            "echo warn 2> /dev/stdout",
            "command &> /dev/stdout",
            "echo x > /dev/fd/0",
            "echo x > /dev/fd/1",
            "echo x >/dev/fd/2",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_truncate_macos_home_spelling_blocks() {
        // #325: tools hand agents absolute resolved paths, so the macOS
        // home spelling `/Users/<user>/...` is what a truncating
        // redirect actually names in practice. The rm family already
        // treated /Users as sensitive; the redirect rule must agree
        // with it or the guard blocks the uncertain form
        // (`> $D/.zshrc`) while allowing the exactly-named one.
        let pack = create_pack();
        for cmd in [
            "echo x > /Users/jemanuel/.zshrc",
            "echo x >/Users/jemanuel/.zshrc",
            ": > /Users/jemanuel/.zshrc",
            "echo x >| /Users/jemanuel/.zshrc",
            "echo x 2> /Users/jemanuel/.zshrc",
            "echo x &> /Users/jemanuel/.zshrc",
            "printf x > /Users/jemanuel/.ssh/config",
            "echo x > \"/Users/jemanuel/.zshrc\"",
            "echo x > /Users",
            "echo x > /Users/Shared/notes.txt",
        ] {
            assert_blocks_with_severity(&pack, cmd, Severity::Critical);
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }

        // `/Users` must only match as a complete path component.
        for cmd in ["echo x > /Usersland/file.txt", "echo x > ./Users/file.txt"] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn mv_sensitive_source_macos_home_spelling_blocks() {
        // #325 sibling: mv-sensitive-source-root-home shares the
        // sensitive-path alternation and must carry the macOS spelling
        // too (platform parity with the Linux `/home` posture).
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "mv /Users/jemanuel/.zshrc /tmp/x",
            "mv-sensitive-source-root-home",
        );
        assert_blocks_with_pattern(
            &pack,
            "mv /home/user/.zshrc /tmp/x",
            "mv-sensitive-source-root-home",
        );
    }

    #[test]
    fn redirect_glued_operator_blocks_destructive() {
        // Bypass attempt: glue the operator to the path with no space.
        // The dcg tokenizer keeps `data>/etc/passwd` as a single token,
        // and previously the args-data masking would erase the whole
        // thing. The `glued_redirect_split_position` helper now masks
        // only the prefix and leaves operator+target visible.
        let pack = create_pack();
        for cmd in [
            "echo data>/etc/passwd",
            "printf data>/etc/passwd",
            "echo data>~/.ssh/id_rsa",
            "echo data>$HOME/.aws/credentials",
            "echo \"data\">/etc/passwd",
            "echo data>'/etc/passwd'",
            "echo data>\"/etc/passwd\"",
            "echo x 2>/etc/passwd",
            "echo x 1>/etc/passwd",
            "echo x &>/etc/passwd",
            "echo x >|/etc/passwd",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn redirect_glued_operator_to_non_sensitive_is_allowed() {
        // The glued-redirect-split heuristic must NOT cause new false
        // positives on tokens where `>` is followed by a path-like char
        // but the path itself isn't sensitive.
        let pack = create_pack();
        for cmd in [
            "echo data>./local.txt",
            "echo data>build.log",
            "echo data>/tmp/scratch",
            "echo data>/dev/null",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn redirect_ansi_c_and_locale_quoted_paths_block() {
        // Bash ANSI-C (`$'...'`) and locale (`$"..."`) quoting forms
        // must not bypass. The optional-quote group in the regex now
        // accepts both `\$'` and `\$"` as quote prefixes.
        let pack = create_pack();
        for cmd in [
            "> $'/etc/passwd'",
            "> $\"/etc/passwd\"",
            ": > $'/etc/shadow'",
            "echo > $'/etc/passwd'",
            "echo > $\"/etc/passwd\"",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
    }

    #[test]
    fn mv_ansi_c_and_locale_quoted_sources_block() {
        // Same ANSI-C / locale quoting bypass for the mv rule. Without
        // the fix, `mv $'/etc' /tmp/x` slipped past as a HIGH-impact
        // gap (mv has no general tier to fall back on).
        let pack = create_pack();
        for cmd in [
            "mv $'/etc' /tmp/x",
            "mv $\"/etc\" /tmp/x",
            "mv $'/etc/passwd' /tmp/passwd",
            "mv $\"/home/user\" /tmp/relocated",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "mv-sensitive-source-root-home");
        }
    }

    #[test]
    fn echo_quoted_data_args_with_arrow_no_path_dont_falsely_match() {
        // Plain-data quoted args where `>` is followed by a non-path
        // character must NOT trigger the
        // `glued_redirect_split_position` heuristic, so they stay
        // masked through the full sanitize. (Tokens whose `>` is
        // followed by `/`, `~`, `$`, or a quote DO get split — that's
        // the bypass-fix path tested separately via the e2e harness
        // since `assert_no_match` operates on the raw command and
        // can't observe sanitize behavior.)
        let pack = create_pack();
        for cmd in [
            "echo \"5 > 3\"",
            "echo \"user>admin\"",
            "echo \"<html><body>\"",
        ] {
            assert_no_match(&pack, cmd);
        }
    }

    #[test]
    fn test_rm_rf_root_critical() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -rf /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /home", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ~/", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /tmp/cache /etc", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -rf /", "rm-rf-root-home");
        // Quoted / or ~ — shell evaluates to / or ~; must still block.
        assert_blocks_with_severity(&pack, "rm -rf \"/\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf '/'", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \"~/\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf '/etc'", Severity::Critical);
    }

    #[test]
    fn private_tmp_is_equivalent_to_tmp_on_macos() {
        // Regression for #244 part A: /tmp and /var/tmp are symlinks to
        // /private/tmp and /private/var/tmp on macOS, so the canonical form
        // must enjoy the same literal-temp allowance.
        let pack = create_pack();
        for cmd in [
            "rm -rf /private/tmp/some/subdir/file",
            "rm -fr /private/tmp/build",
            "rm -r -f /private/tmp/scratch",
            "rm -rf /private/var/tmp/build",
            "rm --recursive --force /private/tmp/cache",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "macOS-canonical private tmp path must be allowed: {cmd}"
            );
        }
        // Traversal out of the private tmp tree stays blocked.
        assert!(pack.check("rm -rf /private/tmp/../etc").is_some());
        assert!(pack.check("rm -rf /private/etc").is_some());
    }

    #[test]
    fn windows_user_temp_subpaths_are_equivalent_to_tmp() {
        // Regression for #285: the per-user Windows temp directory is the
        // platform's /tmp, in both the native drive spelling and the Git
        // Bash / MSYS2 spelling Claude Code's Bash tool emits on Windows.
        // Windows paths are case-insensitive.
        let pack = create_pack();
        for cmd in [
            r"rm -rf /c/Users/u/AppData/Local/Temp/some/subdir/file",
            r"rm -rf /C/users/U/appdata/local/temp/x",
            r"rm -rf C:\Users\u\AppData\Local\Temp\some\file",
            r"rm -rf C:\Users\u\AppData\Local\TEMP\build",
            r#"rm -rf "C:\Users\u\AppData\Local\Temp\x""#,
            r"rm -fr /c/Users/u/AppData/Local/Temp/build",
            r"rm -r -f C:/Users/u/AppData/Local/Temp/scratch",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "literal per-user Windows temp subpath must be allowed: {cmd}"
            );
        }
        // The carve-out must stay bounded: the temp root itself, non-temp
        // user paths, prefix confusion, traversal, multi-target smuggling,
        // the machine-wide C:\Windows\Temp, and dynamic roots (the $TMPDIR
        // policy) all stay blocked.
        for cmd in [
            r"rm -rf C:\Users\u\AppData\Local\Temp",
            r"rm -rf /c/Users/u/Documents/x",
            r"rm -rf /c/Users/u/AppData/Local/Tempx/y",
            r"rm -rf C:\Users\u\AppData\Local\Temp\..\..\Documents",
            r"rm -rf C:\Users\u\AppData\Local\Temp\x /etc",
            r"rm -rf C:\Windows\Temp\x",
            r#"rm -rf "$TEMP/some/subdir/file""#,
            r"rm -rf $TMP/build",
            r"rm -rf $env:TEMP\x",
        ] {
            assert!(
                pack.check(cmd).is_some(),
                "Windows temp carve-out must stay bounded: {cmd}"
            );
        }
    }

    #[test]
    fn windows_user_temp_carve_out_rejects_dot_and_trailing_dot_components() {
        // The component filter must reject every dot-only component, not just
        // `.` and `..`: cmd resolves `...` as repeated parent traversal in
        // some contexts, so it can leave the temp subtree. Win32 also strips
        // trailing dots and spaces from a component, so `Temp.` and `Temp `
        // name a different directory than the one the carve-out proved.
        for path in [
            r"C:\Users\u\AppData\Local\Temp\...\...\...\...\Windows\System32",
            r"C:\Users\u\AppData\Local\Temp\....\x",
            r"/c/Users/u/AppData/Local/Temp/.../.../.../.../Windows/System32",
            r"C:\Users\u\AppData\Local\Temp.\x",
            r"C:\Users\u\AppData\Local\Temp \x",
            r"C:\Users\u\AppData\Local\Temp\sub.\x",
            r"C:\Users\u\AppData\Local\Temp\sub \x",
            r"C:\Users.\u\AppData\Local\Temp\x",
        ] {
            assert!(
                !windows_literal_user_temp_subpath(path),
                "dot-only or trailing dot/space component must not be carved out: {path}"
            );
        }
        // A dot inside a component is ordinary and stays carved out.
        for path in [
            r"C:\Users\u\AppData\Local\Temp\build.tmp\x",
            r"/c/Users/u/AppData/Local/Temp/a.b/c",
        ] {
            assert!(
                windows_literal_user_temp_subpath(path),
                "an interior dot must keep the carve-out: {path}"
            );
        }

        let pack = create_pack();
        for cmd in [
            r"rm -rf C:\Users\u\AppData\Local\Temp\...\...\...\...\Windows\System32",
            r"rm -rf /c/Users/u/AppData/Local/Temp/.../.../.../.../Windows/System32",
            r"rm -rf C:\Users\u\AppData\Local\Temp\sub.\x",
        ] {
            assert!(
                pack.check(cmd).is_some(),
                "dot-component temp path must stay blocked: {cmd}"
            );
        }
        assert!(matches!(
            parse_powershell_remove_item_segment(
                r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\...\...\...\...\Windows\System32",
                false,
            ),
            RmParseDecision::Deny(_)
        ));
    }

    #[test]
    fn powershell_remove_item_literal_user_temp_subpath_is_allowed() {
        // #285, PowerShell dialect: Remove-Item with every proven target a
        // literal per-user temp subpath is temp cleanup, like rm -rf /tmp/x.
        for cmd in [
            r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\some\subdir\file",
            r"Remove-Item -Recurse c:\users\u\appdata\local\TEMP\x",
            r"Remove-Item -Recurse -Force 'C:\Users\u\AppData\Local\Temp\x'",
            r"Remove-Item -Recurse -Force -Path:C:\Users\u\AppData\Local\Temp\x",
        ] {
            assert!(
                matches!(
                    parse_powershell_remove_item_segment(cmd, false),
                    RmParseDecision::Allow
                ),
                "literal temp Remove-Item must be allowed: {cmd}"
            );
        }
        // Dynamic roots keep the $TMPDIR review policy, and non-temp or
        // mixed targets stay denied.
        for cmd in [
            r"Remove-Item -Recurse -Force $env:TEMP\some\subdir\file",
            r"Remove-Item -Recurse -Force C:\Users\u",
            r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp",
            r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\x C:\Windows\System32",
            r"Remove-Item -Recurse -Force C:\Users\u\AppData\Local\Temp\x,C:\Windows",
            r"Remove-Item -Recurse -Force C:\Windows\Temp\x",
        ] {
            assert!(
                matches!(
                    parse_powershell_remove_item_segment(cmd, false),
                    RmParseDecision::Deny(_)
                ),
                "Remove-Item outside the literal temp carve-out must stay denied: {cmd}"
            );
        }
    }

    #[test]
    fn mv_to_trash_is_allowed_and_stays_bounded() {
        // Regression for #244 part B: dcg's own rm-rf remediation suggests
        // moving files into the Trash, so that exact command must be allowed.
        let pack = create_pack();
        for cmd in [
            "mv /private/tmp/some/subdir/file ~/.local/share/Trash/",
            "mv /tmp/scratch.txt ~/.local/share/Trash/",
            "mv ~/Downloads/junk.md ~/.local/share/Trash/",
            "mv ~/Downloads/junk.md ~/.Trash/",
            "mv /Users/alice/Downloads/old.pdf ~/.Trash/",
            "mv /home/alice/notes/old.txt ~/.local/share/Trash/files/",
            "mv report.bak ~/.Trash",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "move into the platform Trash must be allowed: {cmd}"
            );
        }
        // The carve-out must not become a general bypass: whole homes,
        // sensitive system trees, traversal, and dynamic paths stay blocked.
        for cmd in [
            "mv /etc ~/.local/share/Trash/",
            "mv ~/ ~/.Trash/",
            "mv /Users/alice/ ~/.Trash/",
            "mv /tmp/../etc ~/.Trash/",
            "mv ~/Downloads/x ~/.Trash/../../etc",
            "mv \"$f\" ~/.local/share/Trash/",
            // A shell separator hidden inside a whitespace-free token must
            // not let the whole-command safe match rescue a sensitive
            // sibling segment.
            "mv /etc;x ~/.Trash/",
        ] {
            assert!(
                pack.check(cmd).is_some(),
                "Trash carve-out must stay bounded: {cmd}"
            );
        }
    }

    #[test]
    fn globbed_rm_under_home_is_blocked() {
        // Regression for #247: the glob IS the recursion. `rm -f ~/x/*`
        // destroys approximately the same file set as `rm -rf ~/x`, but only
        // the latter was caught.
        let pack = create_pack();
        for cmd in [
            "rm -f /Users/kaitaylor/Downloads/*.md",
            "rm -f /Users/kaitaylor/Downloads/*",
            "rm -f /Users/kaitaylor/*.md",
            "rm /Users/kaitaylor/Documents/*.pdf",
            "rm -f /home/alice/reports/*.csv",
            "rm ~/Downloads/*.md",
            "rm -f ~/notes/draft?.txt",
            "rm $HOME/Downloads/*.md",
            "rm -f /Users/*/Downloads/junk.md",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "rm-glob-home");
        }
        // Bounded single-file deletes and quoted (non-expanding) globs are
        // untouched, and the walker must not bridge a newline from a benign
        // rm on one line into a home glob on a later line.
        for cmd in [
            "rm -f /Users/kaitaylor/Downloads/one-file.md",
            "rm ~/Downloads/specific.md",
            "rm -f \"/Users/kaitaylor/Downloads/*.md\"",
            "rm -f ./build/*.o",
            "rm -f /tmp/scratch.txt\nls ~/Downloads/*.md",
            "docker run --rm -v ~/data/*.json:/data img",
        ] {
            assert!(
                pack.check(cmd).is_none(),
                "bounded or non-expanding delete must stay allowed: {cmd}"
            );
        }
    }

    #[test]
    fn test_rm_separate_and_long_flag_root_is_critical() {
        // Previously only the combined `-rf` form produced Critical severity
        // on root/home targets. `-r -f /` and `--recursive --force /` were
        // attributed to the general High-severity rules, understating the
        // catastrophic nature of wiping the root filesystem.
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -r -f /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -f -r /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f ~/", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -r -f /", "rm-r-f-separate-root-home");

        assert_blocks_with_severity(&pack, "rm --recursive --force /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --force --recursive /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force /etc", Severity::Critical);
        assert_blocks_with_pattern(
            &pack,
            "rm --recursive --force /",
            "rm-recursive-force-root-home",
        );

        // Quoted forms too
        assert_blocks_with_severity(&pack, "rm -r -f \"/\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force '/'", Severity::Critical);
        // Backslash-escaped root: shell unescapes \/ to / and \~ to ~.
        assert_blocks_with_severity(&pack, "rm -rf \\/", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \\~", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f \\/", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force \\/", Severity::Critical);
        // $HOME variants: shell expands to the user's home directory.
        assert_blocks_with_severity(&pack, "rm -rf $HOME", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \"$HOME\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ${HOME}", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf \"${HOME}\"", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -r -f $HOME", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm --recursive --force $HOME", Severity::Critical);

        // Non-root targets retain their existing (High) severity, so we don't
        // accidentally upgrade innocuous cleanup commands.
        assert_blocks_with_severity(&pack, "rm -r -f ./build", Severity::High);
        assert_blocks_with_severity(&pack, "rm --recursive --force ./build", Severity::High);
    }

    #[test]
    fn test_rm_rf_general_high() {
        let pack = create_pack();
        // Outside safe dirs, general rule catches it
        assert_blocks_with_severity(&pack, "rm -rf ./build", Severity::High);
        assert_blocks_with_pattern(&pack, "rm -rf ./build", "rm-rf-general");
    }

    /// Regression for #120: trailing shell redirections must not turn a
    /// safe `rm -rf /tmp/...` invocation into a critical "rm-rf-root-home"
    /// flag. Previously `rm -rf /tmp/foo 2>/dev/null` was denied because
    /// the rm parser added `2>/dev/null` to its path list, the safe-path
    /// determination failed (it isn't a `/tmp/...` path), and the
    /// regex-based rm-rf-root-home rule matched the leading `/` in
    /// `/tmp/...`.
    ///
    /// The fix in `parse_rm_segment` skips tokens recognised by
    /// `starts_with_shell_redirection` rather than treating them as
    /// rm-target paths.
    #[test]
    fn test_rm_rf_tmp_with_trailing_redirections_is_safe() {
        let pack = create_pack();
        let safe_cases = [
            "rm -rf /tmp/sigtest* 2>/dev/null",
            "rm -rf /tmp/sigtest* /tmp/tardis-test /tmp/tardis-bench 2>/dev/null",
            "rm -rf /tmp/foo > /tmp/log.txt",
            "rm -rf /tmp/foo > /tmp/log.txt 2>&1",
            "rm -rf /tmp/foo &>/dev/null",
            "rm -rf /tmp/foo &>> /tmp/audit.log",
            "rm -rf /var/tmp/foo 2>/dev/null",
            "rm -r -f /tmp/foo 2>/dev/null",
            "rm -f -r /tmp/foo 2>/dev/null",
            "rm --recursive --force /tmp/foo 2>/dev/null",
        ];
        for cmd in safe_cases {
            assert!(
                pack.check(cmd).is_none(),
                "rm -rf with trailing redirection on /tmp/* must not be blocked; cmd={cmd}"
            );
        }

        // The trailing-redirection skip must not let a dangerous path
        // sneak through. /etc still wins over the redirection.
        let unsafe_cases = [
            "rm -rf /etc 2>/dev/null",
            "rm -rf /tmp/ok /etc 2>/dev/null",
            "rm -rf / 2>/dev/null",
        ];
        for cmd in unsafe_cases {
            assert!(
                pack.check(cmd).is_some(),
                "rm -rf targeting root/etc must still be blocked even with a trailing redirection; cmd={cmd}"
            );
        }
    }

    #[test]
    fn test_rm_flags_ordering() {
        let pack = create_pack();
        assert_blocks(&pack, "rm -r -f ./build", "separate -r -f flags");
        assert_blocks(&pack, "rm -f -r ./build", "separate -r -f flags");
        assert_blocks(
            &pack,
            "rm --recursive --force ./build",
            "rm --recursive --force is destructive",
        );
        assert_blocks(
            &pack,
            "rm --force --recursive ./build",
            "rm --recursive --force is destructive",
        );
    }

    #[test]
    fn test_safe_rm_tmp() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -rf /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -rf /var/tmp/stuff");
        assert!(!pack.matches_safe("rm -rf $TMPDIR/junk"));
        assert!(!pack.matches_safe("rm -rf ${TMPDIR}/junk"));
    }

    #[test]
    fn test_tmpdir_brace_requires_exact_var_name() {
        let pack = create_pack();
        assert!(!pack.matches_safe("rm -rf ${TMPDIR_NOT}/junk"));
        assert_rm_parser_denies(
            "rm -rf ${TMPDIR_NOT}/junk",
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_safe_rm_variants() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rm -fr /tmp/test");
        assert_safe_pattern_matches(&pack, "rm -r -f /tmp/test");
        assert_safe_pattern_matches(&pack, "rm --recursive --force /tmp/test");
    }

    #[test]
    fn test_path_traversal_blocked() {
        let pack = create_pack();
        // Should NOT match safe patterns (so it falls through to destructive)
        assert!(!pack.matches_safe("rm -rf /tmp/../etc"));
        assert!(!pack.matches_safe("rm -rf /var/tmp/../etc"));

        // And should be blocked by destructive rules
        assert_blocks(&pack, "rm -rf /tmp/../etc", "rm -rf on root or home paths");
    }

    fn assert_rm_parser_allows(command: &str) {
        let decision = parse_rm_command(command);
        assert!(
            matches!(decision, RmParseDecision::Allow),
            "Expected rm parser to allow '{command}', got {decision:?}",
        );
    }

    fn assert_rm_parser_denies(command: &str, expected_rule: &str, expected_severity: Severity) {
        match parse_rm_command(command) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(
                    hit.pattern_name, expected_rule,
                    "Unexpected rule for '{command}'"
                );
                assert_eq!(
                    hit.severity, expected_severity,
                    "Unexpected severity for '{command}'"
                );
            }
            other => unreachable!("Expected rm parser to deny '{command}', got {other:?}"),
        }
    }

    fn assert_rm_parser_no_match(command: &str) {
        match parse_rm_command(command) {
            RmParseDecision::NoMatch => {}
            other => {
                unreachable!("Expected rm parser to return NoMatch for '{command}', got {other:?}")
            }
        }
    }

    #[test]
    fn test_rm_parser_rejects_variable_tmpdir_roots() {
        assert_rm_parser_denies(
            r#"rm -rf "$TMPDIR/foo""#,
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm -rf "${TMPDIR}/foo""#,
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(r"rm -rf $TMPDIR/foo", RM_RF_GENERAL_NAME, Severity::High);
        assert_rm_parser_denies(
            r"rm -rf ${TMPDIR:-/tmp}/foo",
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(r"rm -rf '$TMPDIR/foo'", RM_RF_GENERAL_NAME, Severity::High);
        assert_rm_parser_denies(
            r#"rm -r -f "$TMPDIR/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm -r -f "${TMPDIR}/foo""#,
            RM_R_F_SEPARATE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --recursive --force "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "$TMPDIR/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"rm --force --recursive "${TMPDIR}/foo""#,
            RM_RECURSIVE_FORCE_NAME,
            Severity::High,
        );
        assert_rm_parser_denies(
            r#"export TMPDIR=/; rm -rf "$TMPDIR/etc""#,
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_rm_parser_allows_literal_tmp_double_quoted() {
        assert_rm_parser_allows(r#"rm -rf "/tmp/foo""#);
        assert_rm_parser_allows(r#"rm -rf "/tmp/build/artifacts""#);
        assert_rm_parser_allows(r#"rm -rf "/var/tmp/cache""#);
        assert_rm_parser_allows(r#"rm -rf "/tmp/{literal}""#);
        assert_rm_parser_allows(r#"rm -rf "/tmp/O'Reilly""#);
        assert_rm_parser_allows(r#"rm -rf "/tmp/.\./etc""#);

        assert_rm_parser_denies(
            r#"rm -rf "/tmp/../etc""#,
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );

        for command in [
            r#"rm -rf "/tmp/$TARGET""#,
            r#"rm -rf "/tmp/$(printf ../etc)""#,
            r"rm -rf /tmp/{cache,../etc}",
            r"rm -rf /tmp/''../etc",
            r"rm -rf /tmp/.\./etc",
        ] {
            assert!(
                matches!(parse_rm_command(command), RmParseDecision::Deny(_)),
                "expanded or quote-concatenated temp path must be denied: {command}"
            );
        }
    }

    #[test]
    fn test_rm_parser_handles_compound_segments() {
        assert_rm_parser_allows("cp -al /tmp/a /tmp/b && rm -rf /tmp/b");
        assert_rm_parser_denies(
            "echo ok && rm -rf ./build",
            RM_RF_GENERAL_NAME,
            Severity::High,
        );
    }

    #[test]
    fn test_rm_parser_traversal_blocked() {
        assert_rm_parser_denies(
            "rm -rf /tmp/../etc",
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );
    }

    #[test]
    fn test_rm_parser_option_terminator() {
        assert_rm_parser_no_match("rm -- -rf /tmp/safe");
        assert_rm_parser_denies("rm -rf -- /tmp/safe", RM_RF_GENERAL_NAME, Severity::High);
        assert_rm_parser_denies("rm -rf -- /", RM_RF_ROOT_HOME_NAME, Severity::Critical);
        assert_rm_parser_denies(
            "rm -r -f -- /",
            RM_R_F_SEPARATE_ROOT_HOME_NAME,
            Severity::Critical,
        );
        assert_rm_parser_denies(
            "rm --recursive --force -- /",
            RM_RECURSIVE_FORCE_ROOT_HOME_NAME,
            Severity::Critical,
        );
    }

    #[test]
    fn test_rm_parser_blocks_recursive_only_deletion() {
        for command in [
            "rm -r ./build",
            "rm -R Desktop",
            "rm --recursive ./tree",
            "rm --rec ./tree",
            "rm ./build -r",
            "rm -rv ./build",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_GENERAL_NAME, Severity::High);
        }

        for command in [
            "rm -r /",
            "rm -R /etc",
            "rm --recursive ~/Documents",
            "rm -r $HOME",
            "rm -r /Users/alice/Desktop",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_ROOT_HOME_NAME, Severity::Critical);
        }
    }

    #[test]
    fn test_rm_parser_preserves_force_rule_ids() {
        for command in ["rm -rf ./build", "rm -fr ./build", "rm -rvf ./build"] {
            assert_rm_parser_denies(command, RM_RF_GENERAL_NAME, Severity::High);
        }
        for command in [
            "rm -r -f ./build",
            "rm -f -R ./build",
            "rm -r --force ./build",
            "rm --recursive -f ./build",
        ] {
            assert_rm_parser_denies(command, RM_R_F_SEPARATE_NAME, Severity::High);
        }
        for command in [
            "rm --recursive --force ./build",
            "rm --force --recursive ./build",
            "rm --rec --fo ./build",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_FORCE_NAME, Severity::High);
        }
    }

    #[test]
    fn test_rm_parser_interactive_and_force_are_order_sensitive() {
        for command in [
            "rm -r -i ./build",
            "rm -r -I ./build",
            "rm -rfi ./build",
            "rm -rfI ./build",
            "rm -r -f --interactive=once ./build",
            "rm -r --force --interactive=always ./build",
            "rm -r --interactive ./build",
            "rm -r --interactive=o ./build",
            "rm -r --interactive=y ./build",
            "rm ./build -r -i",
        ] {
            assert_rm_parser_allows(command);
        }

        for command in ["rm -rif ./build", "rm -rIf ./build"] {
            assert_rm_parser_denies(command, RM_RF_GENERAL_NAME, Severity::High);
        }
        for command in [
            "rm -r -i --force ./build",
            "rm -r --interactive=once -f ./build",
            "rm -r -i -f ./build",
            "rm -r -I --force ./build",
            "rm -r --interactive=always -f ./build",
        ] {
            assert_rm_parser_denies(command, RM_R_F_SEPARATE_NAME, Severity::High);
        }
        for command in [
            "rm -r --interactive=never ./build",
            "rm -r --interactive=no ./build",
            "rm -r --interactive=none ./build",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_GENERAL_NAME, Severity::High);
        }
    }

    #[test]
    fn test_rm_parser_recursive_only_temp_and_non_execution_forms() {
        for command in [
            "rm -r /tmp/build",
            "rm -R /var/tmp/cache",
            r#"rm --recursive "/tmp/build artifacts""#,
        ] {
            assert_rm_parser_allows(command);
        }

        for command in [
            "rm -r",
            "rm --recursive",
            "rm ./build --version -r",
            "rm --recursive-x ./build",
            "rm --v ./build -r",
            "rm -rz ./build",
        ] {
            assert_rm_parser_no_match(command);
        }

        assert_rm_parser_denies(
            "rm -r -- /tmp/build",
            RM_RECURSIVE_GENERAL_NAME,
            Severity::High,
        );
        assert_rm_parser_no_match("rm -- -r ./build");
    }

    #[test]
    fn test_rm_parser_models_apple_option_stop_after_first_operand() {
        // GNU getopt permutes these trailing tokens into options: --help and
        // --version terminate, while -i/--interactive enable prompts. Apple's
        // getopt stops at the first operand, so the same tokens are additional
        // paths and the preceding recursive deletion still executes.
        let pack = create_pack();
        for (command, expected_rule) in [
            ("rm -r ./build --help", RM_RECURSIVE_GENERAL_NAME),
            ("rm -r ./build --version", RM_RECURSIVE_GENERAL_NAME),
            ("rm -r ./build -i", RM_RECURSIVE_GENERAL_NAME),
            ("rm -r ./build -I", RM_RECURSIVE_GENERAL_NAME),
            ("rm -rf ./build -i", RM_RF_GENERAL_NAME),
            (
                "rm -r ./build --interactive=always",
                RM_RECURSIVE_GENERAL_NAME,
            ),
            ("rm -r /tmp/build --help", RM_RECURSIVE_GENERAL_NAME),
        ] {
            assert_rm_parser_denies(command, expected_rule, Severity::High);
            assert!(pack.check(command).is_some(), "pack must deny: {command}");
        }

        assert_rm_parser_denies(
            "rm -r /etc -i",
            RM_RECURSIVE_ROOT_HOME_NAME,
            Severity::Critical,
        );
        assert_rm_parser_denies(
            "rm -rf $HOME --interactive=always",
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );

        // Neither supported grammar deletes recursively here: GNU reaches a
        // terminal option, while Apple stopped scanning before it ever saw -r.
        for command in [
            "rm ./build --help -r",
            "rm ./build --version -R",
            "rm --recursive ./build --help",
        ] {
            assert_rm_parser_no_match(command);
        }

        // Both grammars retain a real prompt, even though only GNU sees the
        // recursive flag that follows the first operand.
        assert_rm_parser_allows("rm -i ./build -r");
    }

    #[test]
    fn test_rm_parser_temp_exception_requires_real_subdirectory() {
        let pack = create_pack();
        let root_only_paths = [
            "/tmp/",
            "/tmp//",
            "/tmp/./",
            "/var/tmp/",
            "/var/tmp//",
            "/var/tmp/./",
            r#""/tmp/""#,
            r#""/tmp//""#,
            r#""/tmp/./""#,
            r#""/var/tmp/""#,
            r#""/var/tmp//""#,
            r#""/var/tmp/./""#,
        ];

        for flags in ["-r", "-rf"] {
            for path in root_only_paths {
                let command = format!("rm {flags} {path}");
                assert!(
                    matches!(parse_rm_command(&command), RmParseDecision::Deny(_)),
                    "temp root without a real subdirectory must be denied: {command}"
                );
                assert!(
                    pack.check(&command).is_some(),
                    "pack must deny temp root without a real subdirectory: {command}"
                );
            }
        }

        for command in [
            "rm -r /tmp/foo",
            "rm -r /var/tmp/foo",
            r#"rm -r "/tmp/foo""#,
            r#"rm -r "/var/tmp/foo""#,
            "rm -rf /tmp/foo",
            "rm -rf /var/tmp/foo",
            r#"rm -rf "/tmp/foo""#,
            r#"rm -rf "/var/tmp/foo""#,
        ] {
            assert_rm_parser_allows(command);
            assert!(
                pack.check(command).is_none(),
                "literal temp subdirectory must remain allowed: {command}"
            );
        }
    }

    #[test]
    fn test_rm_parser_interactive_prompts_require_terminal_stdin() {
        for command in [
            "yes | rm -r -i ./tree",
            "yes | rm -rI ./tree",
            "printf 'y\\n' | rm --recursive --interactive=always ./tree",
            "rm -ri ./tree < answers.txt",
            "rm -rI ./tree <<< y",
            "rm --recursive --interactive=always ./tree 0<answers.txt",
            "< answers.txt rm -ri ./tree",
            "0<answers.txt rm -rI ./tree",
            "yes | { rm -ri ./tree; }",
            "yes | ( rm -ri ./tree )",
            "yes | { echo ready; rm -ri ./tree; }",
            "yes | while true; do rm -ri ./tree; break; done",
            "yes | if true; then rm -ri ./tree; fi",
            "yes | { # }\n rm -ri ./tree; }",
            "exec < answers.txt; rm -ri ./tree",
            "exec 0<answers.txt; rm -rI ./tree",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_GENERAL_NAME, Severity::High);
        }

        let heredoc_group = "yes | { cat <<'EOF'\n}\nEOF\nrm -ri ./tree; }";
        let rm_start = heredoc_group
            .find("rm -ri")
            .expect("test command contains rm segment");
        assert!(rm_segment_receives_automated_stdin(
            heredoc_group,
            rm_start,
            ShellDialect::Posix,
        ));

        for command in [
            "rm -ri ./tree",
            "rm -rI ./tree",
            "rm --recursive --interactive=always ./tree",
            "printf 'y\\n' | { cat; }; rm -ri ./tree",
            "(exec < answers.txt; true); rm -ri ./tree",
            "exec 3<answers.txt; rm -ri ./tree",
            "exec <> answers.txt; rm -ri ./tree",
        ] {
            assert_rm_parser_allows(command);
        }
    }

    #[test]
    fn test_rm_parser_normalizes_segment_local_wrappers_and_executables() {
        for command in [
            "echo ok; sudo rm -r ./tree",
            "yes | env rm -ri ./tree",
            "yes | FOO=bar rm -ri ./tree",
            "command rm -r ./tree",
            r"\rm -r ./tree",
            "exec rm -r ./tree",
            "nohup rm -r ./tree",
            "time rm -r ./tree",
            "/bin/rm -r ./tree",
            r#""/bin/rm" -r ./tree"#,
            r"'/usr/bin/rm' -r ./tree",
            "nice rm -r ./tree",
            "nice -n 5 sudo rm -r ./tree",
            "ionice -c 3 rm -r ./tree",
            "ionice -tc3 /bin/rm -r ./tree",
            "setsid -fw rm -r ./tree",
            "timeout --signal KILL 10 rm -r ./tree",
            "timeout -k5 10 nice rm -r ./tree",
            "/bin/busybox rm -r ./tree",
            "busybox nice rm -r ./tree",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_GENERAL_NAME, Severity::High);
        }
    }

    #[test]
    fn test_rm_parser_skips_leading_posix_assignments_before_executable() {
        for command in [
            "FOO=bar rm -r ./tree",
            "FOO=bar /bin/rm -r ./tree",
            "FOO=bar sudo rm -r ./tree",
            "x=$(printf ok) rm -r ./tree",
            "FOO=bar x=$(printf ok) command rm -r ./tree",
            "x=$(rm -r /tmp/cache) rm -r ./tree",
        ] {
            assert_rm_parser_denies(command, RM_RECURSIVE_GENERAL_NAME, Severity::High);
        }

        for command in [
            "FOO=bar rm -r /tmp/foo",
            "x=$(printf ok) /bin/rm -r /var/tmp/foo",
            r#"FOO="a b" sudo rm -r "/tmp/foo""#,
        ] {
            assert_rm_parser_allows(command);
        }
    }

    #[test]
    fn test_rm_parser_wrapper_normalization_preserves_safe_controls() {
        for command in [
            "echo ok; sudo rm -r /tmp/foo",
            "env rm -r /var/tmp/foo",
            r#""/bin/rm" -r "/tmp/foo""#,
            "nice -n 5 rm -r /tmp/foo",
            "ionice -c3 rm -r /var/tmp/foo",
            "setsid rm -r /tmp/foo",
            "timeout 10 rm -r /var/tmp/foo",
            "busybox rm -r /tmp/foo",
        ] {
            assert_rm_parser_allows(command);
        }

        for command in [
            "command -v rm",
            "command -V rm",
            "echo 'sudo rm -r ./tree'",
            "echo FOO=bar rm -r ./tree",
            r#"echo "/bin/rm -r ./tree""#,
            "printf '%s\\n' 'yes | rm -ri ./tree'",
        ] {
            assert_rm_parser_no_match(command);
        }
    }

    #[test]
    fn test_rm_parser_follows_explicit_xargs_and_find_exec_argv() {
        for command in [
            "printf './tree\\n' | xargs rm -r",
            "xargs -0 -n 1 /bin/rm -r",
            "xargs nice rm -r",
            "xargs rm",
            r#"xargs "$cmd" -r"#,
            r"find ./root -exec rm -r {} \;",
            "find ./root -exec /bin/rm -r {} +",
            r"find ./root -execdir sudo rm -r {} \;",
            r#"find ./root -exec "$cmd" -r {} \;"#,
            r"find /bin/rm -maxdepth 0 -exec {} -r ./tree \;",
            r"find /bin/rm -maxdepth 0 -execdir {} -r ./tree +",
            r"find /bin/rm -maxdepth 0 -exec \{\} -r ./tree \;",
            r"find /bin/rm -maxdepth 0 -exec '{''}' -r ./tree \;",
        ] {
            assert!(
                matches!(parse_rm_command(command), RmParseDecision::Deny(_)),
                "explicit argv frontend must preserve recursive rm detection: {command}"
            );
        }

        for command in [
            "printf './tree\\n' | xargs echo 'rm -r ./tree'",
            "xargs rm --",
            r"find ./root -exec rm -r /tmp/foo \;",
            r"find ./root -exec /bin/rm -r /var/tmp/foo \;",
            r"find ./root -exec echo 'rm -r ./tree' \;",
            r"find ./root -exec echo \{\} -r ./tree \;",
        ] {
            assert_rm_parser_no_match(command);
        }

        for command in [
            r"find /bin/rm -maxdepth 0 -exec {} -r ./tree \;",
            r"find /bin/rm -maxdepth 0 -execdir {} -r ./tree +",
        ] {
            match parse_rm_command(command) {
                RmParseDecision::Deny(hit) => {
                    assert_eq!(hit.pattern_name, RM_RECURSIVE_UNVERIFIED_NAME);
                    assert_eq!(hit.severity, Severity::High);
                }
                other => unreachable!(
                    "placeholder executable must be attributed as unverified: {command}: {other:?}"
                ),
            }
        }
    }

    #[test]
    fn test_rm_parser_dialect_aware_dynamic_executable_seam() {
        for (command, dialect) in [
            (r"r$x -r ./tree", ShellDialect::Posix),
            (r#""$cmd" -r ./tree"#, ShellDialect::Posix),
            (r"$(printf rm) -r ./tree", ShellDialect::Posix),
            (r"%DELETE_CMD% -r ./tree", ShellDialect::Cmd),
            (r"& $cmd -r ./tree", ShellDialect::PowerShell),
            (r"& ('r'+'m') -r ./tree", ShellDialect::PowerShell),
            (r"& $('rm') -r ./tree", ShellDialect::PowerShell),
            (
                r"& @('noop', ('r'+'m'))[1] -r ./tree",
                ShellDialect::PowerShell,
            ),
        ] {
            match parse_rm_command_segment_in_dialect(command, false, dialect) {
                RmParseDecision::Deny(hit) => {
                    assert_eq!(hit.pattern_name, RM_RECURSIVE_UNVERIFIED_NAME);
                    assert_eq!(hit.severity, Severity::High);
                }
                other => unreachable!(
                    "dynamic executable with recursive rm argv must be denied: {command}: {other:?}"
                ),
            }
        }

        for (command, dialect) in [
            (r"not$x -r ./tree", ShellDialect::Posix),
            (r"'$cmd' -r ./tree", ShellDialect::Posix),
            (r#"echo "$cmd" -r ./tree"#, ShellDialect::Posix),
            (r#"rm -- "$cmd" -r ./tree"#, ShellDialect::Posix),
            (r#""$cmd" -r /tmp/foo"#, ShellDialect::Posix),
            (r"echo %DELETE_CMD% -r ./tree", ShellDialect::Cmd),
            (r"& '$cmd' -r ./tree", ShellDialect::PowerShell),
            (r"& @('echo', 'printf')[1] ./tree", ShellDialect::PowerShell),
            (r"$cmd = 'rm'", ShellDialect::PowerShell),
            ("$text = @'\n@params\n'@", ShellDialect::PowerShell),
            (r"${global:cmd} += 'rm'", ShellDialect::PowerShell),
        ] {
            assert!(
                matches!(
                    parse_rm_command_segment_in_dialect(command, false, dialect),
                    RmParseDecision::NoMatch
                ),
                "inert, impossible, post-terminator, or temp-safe dynamic data must not deny: {command}"
            );
        }

        assert_eq!(
            rm_executable_certainty("rm", ShellDialect::Posix),
            RmExecutableCertainty::Exact
        );
        assert_eq!(
            rm_executable_certainty(r"r$x", ShellDialect::Posix),
            RmExecutableCertainty::MayBeRm
        );
        assert_eq!(
            rm_executable_certainty(r"not$x", ShellDialect::Posix),
            RmExecutableCertainty::Other
        );
    }

    #[test]
    fn test_powershell_remove_item_recurse_is_dialect_correct() {
        for command in [
            "rm -Recurse ./tree",
            "ri -r ./tree",
            "Remove-Item -Recurse ./tree",
            "REMOVE-ITEM ./tree -Rec",
            "Remove-Item -Path ./tree -Recurse",
            "rm -r /tmp/dcg-powershell-tree",
            "Remove`-Item -Recurse ./tree",
            "Remove-Item -Rec`urse ./tree",
            "r`m -R ./tree",
            "Remove-Item -Recurse -Path (Resolve-Path ./tree)",
            "Remove-Item -Recurse (Get-Item ./tree)",
        ] {
            match parse_rm_command_segment_in_dialect(
                command,
                command.contains('|'),
                ShellDialect::PowerShell,
            ) {
                RmParseDecision::Deny(hit) => {
                    assert_eq!(hit.pattern_name, POWERSHELL_REMOVE_ITEM_RECURSIVE_NAME);
                    assert_eq!(hit.severity, Severity::Critical);
                }
                other => unreachable!(
                    "PowerShell recursive Remove-Item must be denied: {command}: {other:?}"
                ),
            }
        }

        match parse_rm_command_segment_in_dialect(
            "Remove-Item -Recurse",
            true,
            ShellDialect::PowerShell,
        ) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(hit.pattern_name, POWERSHELL_REMOVE_ITEM_RECURSIVE_NAME);
            }
            other => unreachable!(
                "pipeline-fed PowerShell Remove-Item must be denied without a positional path: {other:?}"
            ),
        }

        for command in [
            "Remove-Item -Recurse ./tree -WhatIf",
            "rm -r ./tree -WhatIf:$true",
            "ri -Recurse -Path ./tree -WhatIf",
        ] {
            let decision =
                parse_rm_command_segment_in_dialect(command, false, ShellDialect::PowerShell);
            assert!(
                matches!(decision, RmParseDecision::Allow),
                "proven PowerShell WhatIf must remain a non-executing preview: {command}: {decision:?}"
            );
        }

        for command in [
            "Remove-Item -Recurse ./tree -WhatIf:$false",
            "rm -r ./tree -WhatIf:$value",
            "ri -WhatIf ./tree -Recurse -WhatIf:$false",
        ] {
            assert!(
                matches!(
                    parse_rm_command_segment_in_dialect(command, false, ShellDialect::PowerShell),
                    RmParseDecision::Deny(_)
                ),
                "disabled or unproven WhatIf must not rescue recursive deletion: {command}"
            );
        }

        assert!(matches!(
            parse_rm_command_segment_in_dialect(
                "Remove-Item ./one.txt",
                false,
                ShellDialect::PowerShell
            ),
            RmParseDecision::NoMatch
        ));

        match parse_rm_command_segment_in_dialect(
            "Remove-Item @params",
            false,
            ShellDialect::PowerShell,
        ) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(hit.pattern_name, RM_RECURSIVE_UNVERIFIED_NAME);
            }
            other => unreachable!(
                "PowerShell splatting must fail closed because it can inject -Recurse and -Path: {other:?}"
            ),
        }
    }

    #[test]
    fn test_dialect_escaped_rm_command_words_and_candidate_signal() {
        match parse_rm_command_segment_in_dialect("r^m -r ./tree", false, ShellDialect::Cmd) {
            RmParseDecision::Deny(hit) => {
                assert_eq!(hit.pattern_name, RM_RECURSIVE_GENERAL_NAME);
                assert_eq!(hit.severity, Severity::High);
            }
            other => unreachable!("Cmd caret-decoded rm must be denied: {other:?}"),
        }

        for (command, dialect) in [
            ("r`m -R ./tree", ShellDialect::PowerShell),
            ("Remove`-Item -Recurse ./tree", ShellDialect::PowerShell),
            ("& ('r'+'m') -r ./tree", ShellDialect::PowerShell),
            ("Remove-Item @params", ShellDialect::PowerShell),
            ("r^m -r ./tree", ShellDialect::Cmd),
            ("%DELETE_CMD% -r ./tree", ShellDialect::Cmd),
            ("echo x >%TARGET%", ShellDialect::Cmd),
        ] {
            assert!(
                filesystem_semantic_scan_required(command, dialect),
                "dialect-obfuscated rm must force core.filesystem candidate selection: {command}"
            );
        }

        for (command, dialect) in [
            ("Write-Output 'r`m -r ./tree'", ShellDialect::PowerShell),
            ("echo r^m -r ./tree", ShellDialect::Cmd),
            ("rm -r ./tree", ShellDialect::Posix),
        ] {
            assert!(
                !filesystem_semantic_scan_required(command, dialect),
                "inert data or ordinary POSIX syntax must not require a dialect fallback scan: {command}"
            );
        }
    }

    #[test]
    fn test_filesystem_keyword_candidate_requires_command_word_boundaries() {
        for command in [
            "rm -rf ./tree",
            "/usr/bin/find . -delete",
            r#""C:\Tools\cp.exe" -a /etc /tmp/etc"#,
            "echo ready && rsync -a /etc/ /tmp/etc/",
            "echo data > /etc/passwd",
            "ECHO data 2> C:\\logs\\error.txt",
            "CP --help",
        ] {
            assert!(
                filesystem_keyword_candidate(command),
                "real filesystem command or redirect must remain a candidate: {command}"
            );
        }

        for command in [
            "scp report.csv analyst@external.example:/incoming/",
            "pscp report.csv analyst@external.example:/incoming/",
            "winscp.exe /help",
            "echo xcp",
            "printf 'carpet'",
        ] {
            assert!(
                !filesystem_keyword_candidate(command),
                "embedded keyword substring must not initialize core.filesystem: {command}"
            );
        }
    }

    #[test]
    fn test_interactive_recursive_rm_does_not_shadow_destructive_redirect() {
        let pack = create_pack();
        for command in [
            "rm -ri ./tree <> /etc/passwd",
            "rm -ri ./tree 0<> /etc/passwd",
            "rm -r /tmp/foo <> /etc/passwd",
            "rm -r /var/tmp/foo 0<> /etc/passwd",
            "rm -ri ./tree 3>/etc/passwd",
            "rm -ri ./tree 0> /etc/passwd",
            "rm -ri ./tree *> /etc/passwd",
            "rm -ri ./tree {audit}> /etc/passwd",
        ] {
            assert_rm_parser_allows(command);
        }
        assert_rm_parser_denies(
            "rm -r ./tree <> /etc/passwd",
            RM_RECURSIVE_GENERAL_NAME,
            Severity::High,
        );

        assert_blocks_with_pattern(
            &pack,
            "rm -rfi ./build > /etc/passwd",
            "redirect-truncate-root-home",
        );
        assert_blocks_with_pattern(
            &pack,
            r#"rm -r -i ./build > "$HOME/.profile""#,
            "redirect-truncate-root-home",
        );
        for command in [
            "rm -ri ./tree 3>/etc/passwd",
            "rm -ri ./tree 0> /etc/passwd",
            "rm -ri ./tree *> /etc/passwd",
            "rm -ri ./tree {audit}> /etc/passwd",
        ] {
            assert_blocks_with_pattern(&pack, command, "redirect-truncate-root-home");
        }
    }
}

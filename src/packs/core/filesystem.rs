//! Core filesystem patterns - protections against destructive rm commands.
//!
//! This includes patterns for:
//! - rm -rf outside temp directories (blocked)
//! - rm -rf in /tmp, /var/tmp, $TMPDIR (allowed)

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
        "rm -rf /path/to/specific/subdirectory",
        "Use explicit, specific paths instead of root or home",
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
        "rm -r -f $TMPDIR/{subdir}",
        "Use system temp directory (allowed without confirmation)",
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
    PatternSuggestion::new(
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
    PatternSuggestion::new(
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
    PatternSuggestion::new(
        "cp {path} {path}.bak && truncate -s 0 {path}",
        "Make a backup before zeroing the file",
    ),
    PatternSuggestion::new("wc -c {path}", "Check current size before shrinking"),
    PatternSuggestion::new(
        "truncate -s 0 /tmp/{subdir}/scratch",
        "Safe temp-directory truncate (allowed without confirmation)",
    ),
    PatternSuggestion::new(
        "head -c <N> {path} > {path}.head && mv {path}.head {path}",
        "Keep the first N bytes instead of dropping data blindly",
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
    PatternSuggestion::new(
        "cp {path} {path}.bak && shred -u {path}",
        "Make a backup first if you might need the data",
    ),
    PatternSuggestion::new(
        "shred -u /tmp/{subdir}/scratch",
        "Safe temp-directory shred (allowed without confirmation)",
    ),
    PatternSuggestion::new(
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
    PatternSuggestion::new(
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
    PatternSuggestion::new(
        "mv {path} {path}.deleted-YYYYMMDD",
        "In-place rename for soft-delete (no cross-segment hop, easy to undo)",
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
        "cp {path} {path}.bak && echo data > {path}",
        "Make a backup first if you might need the previous content",
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
use crate::{normalize::NormalizeTokenKind, normalize::tokenize_for_normalization};
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

pub(crate) fn is_pre_rm_propagation_rule(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "cp-sensitive-then-delete"
                | "ln-symlink-sensitive-then-delete"
                | "rsync-sensitive-then-delete"
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RmFlagState {
    style: RmFlagStyle,
    span: Option<Range<usize>>,
    saw_terminator: bool,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct RmFlagTracker {
    combined_span: Option<Range<usize>>,
    seen_r: bool,
    r_span: Option<Range<usize>>,
    seen_f: bool,
    f_span: Option<Range<usize>>,
    seen_long_recursive: bool,
    recursive_span: Option<Range<usize>>,
    seen_long_force: bool,
    force_span: Option<Range<usize>>,
    saw_terminator: bool,
}

impl RmFlagTracker {
    fn resolve(self) -> Option<RmFlagState> {
        if let Some(span) = self.combined_span {
            return Some(RmFlagState {
                style: RmFlagStyle::Combined,
                span: Some(span),
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_r && self.seen_f {
            return Some(RmFlagState {
                style: RmFlagStyle::Separate,
                span: self.r_span.or(self.f_span),
                saw_terminator: self.saw_terminator,
            });
        }

        if self.seen_long_recursive && self.seen_long_force {
            return Some(RmFlagState {
                style: RmFlagStyle::Long,
                span: self.recursive_span.or(self.force_span),
                saw_terminator: self.saw_terminator,
            });
        }

        None
    }
}

pub(crate) fn parse_rm_command(command: &str) -> RmParseDecision {
    let segments = crate::packs::split_command_segments(command);
    if segments.len() > 1 {
        let mut saw_allow = false;
        for segment in segments {
            match parse_rm_command_segment(segment) {
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

    parse_rm_command_segment(command)
}

fn parse_rm_command_segment(command: &str) -> RmParseDecision {
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
            return parse_rm_segment(command, &tokens, i + 1);
        }

        // Skip to the next separator before scanning for another command word.
        i += 1;
        while i < tokens.len() && tokens[i].kind != NormalizeTokenKind::Separator {
            i += 1;
        }
    }

    RmParseDecision::NoMatch
}

#[allow(clippy::too_many_lines)]
fn parse_rm_segment(
    command: &str,
    tokens: &[crate::normalize::NormalizeToken],
    start_idx: usize,
) -> RmParseDecision {
    let mut options_ended = false;
    let mut flags = RmFlagTracker::default();

    let mut paths: Vec<PathToken<'_>> = Vec::new();

    for token in tokens.iter().skip(start_idx) {
        if token.kind == NormalizeTokenKind::Separator {
            break;
        }

        let Some(text) = token.text(command) else {
            continue;
        };

        if !options_ended {
            if text == "--" {
                options_ended = true;
                flags.saw_terminator = true;
                continue;
            }

            if text.starts_with('-') && text != "-" {
                if text.starts_with("--") {
                    if text.starts_with("--recursive") {
                        flags.seen_long_recursive = true;
                        if flags.recursive_span.is_none() {
                            flags.recursive_span = Some(token.byte_range.clone());
                        }
                    }
                    if text.starts_with("--force") {
                        flags.seen_long_force = true;
                        if flags.force_span.is_none() {
                            flags.force_span = Some(token.byte_range.clone());
                        }
                    }
                } else {
                    let flag_text = text.trim_start_matches('-');
                    if !flag_text.is_empty() {
                        let has_r = flag_text.chars().any(|c| c == 'r' || c == 'R');
                        let has_f = flag_text.chars().any(|c| c == 'f');
                        if has_r && has_f {
                            if flags.combined_span.is_none() {
                                flags.combined_span = Some(token.byte_range.clone());
                            }
                        } else {
                            if has_r && !flags.seen_r {
                                flags.seen_r = true;
                                flags.r_span = Some(token.byte_range.clone());
                            }
                            if has_f && !flags.seen_f {
                                flags.seen_f = true;
                                flags.f_span = Some(token.byte_range.clone());
                            }
                        }
                    }
                }

                continue;
            }
        }

        // Skip trailing shell redirections (`> log`, `2>/dev/null`,
        // `2>&1`, `&>>file`, …). These are not arguments to `rm` and
        // must not count as paths the rm parser checks against the
        // safe-path list (#120). Without this guard the safe-path
        // determination silently fails on commands like
        //   rm -rf /tmp/foo /tmp/bar 2>/dev/null
        // because the trailing redirection token is treated as a third
        // path, which doesn't match any rm-rf-tmp safe pattern, and the
        // whole command ends up flagged as rm-rf-root-home.
        if crate::normalize::starts_with_shell_redirection(text) {
            // Mark options-ended so a later non-redirect token isn't
            // re-interpreted as a flag, but DO NOT add to paths.
            options_ended = true;
            continue;
        }

        options_ended = true;
        let (quote, unquoted) = strip_outer_quotes(text);
        paths.push(PathToken {
            unquoted,
            quote,
            range: token.byte_range.clone(),
        });
    }

    let flag_state = flags.resolve();
    let Some(flag_state) = flag_state else {
        return RmParseDecision::NoMatch;
    };

    let safe_paths = !paths.is_empty()
        && !flag_state.saw_terminator
        && paths
            .iter()
            .all(|path| path_is_safe_for_style(path, flag_state.style));

    if safe_paths {
        return RmParseDecision::Allow;
    }

    let is_critical = paths
        .iter()
        .any(|path| path_is_root_home(path) && !path_is_safe_for_style(path, flag_state.style));

    let (pattern_name, reason, severity) = if is_critical {
        match flag_state.style {
            RmFlagStyle::Combined => (
                RM_RF_ROOT_HOME_NAME,
                RM_RF_ROOT_HOME_REASON,
                Severity::Critical,
            ),
            RmFlagStyle::Separate => (
                RM_R_F_SEPARATE_ROOT_HOME_NAME,
                RM_R_F_SEPARATE_ROOT_HOME_REASON,
                Severity::Critical,
            ),
            RmFlagStyle::Long => (
                RM_RECURSIVE_FORCE_ROOT_HOME_NAME,
                RM_RECURSIVE_FORCE_ROOT_HOME_REASON,
                Severity::Critical,
            ),
        }
    } else {
        match flag_state.style {
            RmFlagStyle::Combined => (RM_RF_GENERAL_NAME, RM_RF_GENERAL_REASON, Severity::High),
            RmFlagStyle::Separate => (RM_R_F_SEPARATE_NAME, RM_R_F_SEPARATE_REASON, Severity::High),
            RmFlagStyle::Long => (
                RM_RECURSIVE_FORCE_NAME,
                RM_RECURSIVE_FORCE_REASON,
                Severity::High,
            ),
        }
    };

    let span = flag_state
        .span
        .or_else(|| paths.first().map(|path| path.range.clone()));

    RmParseDecision::Deny(RmParseMatch {
        pattern_name,
        reason,
        severity,
        span,
    })
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

fn path_is_safe_unquoted(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("/var/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    false
}

fn path_is_safe_double_quoted(path: &str) -> bool {
    // Literal /tmp and /var/tmp are unchanged by double quotes (bash quoting
    // only affects expansion and word splitting, not literal path text). Without
    // parity with path_is_safe_unquoted, `rm -rf "/tmp/foo"` falsely trips the
    // CRITICAL root/home rule while `rm -rf /tmp/foo` is allowed.
    if let Some(rest) = path.strip_prefix("/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("/var/tmp/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("$TMPDIR/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR}/") {
        return !has_dotdot_segment(rest);
    }
    // Handle shell default value syntax: ${TMPDIR:-/tmp} and ${TMPDIR:-/var/tmp}
    // These always expand to a safe temp directory.
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    if let Some(rest) = path.strip_prefix("${TMPDIR:-/var/tmp}/") {
        return !has_dotdot_segment(rest);
    }
    false
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
        description: "Protects against dangerous rm -rf commands and equivalent destruction (find -delete, unlink) outside temp directories",
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
            "1>", "2>",
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
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf in /var/tmp (combined flags)
        safe_pattern!(
            "rm-rf-var-tmp",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-var-tmp",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with $TMPDIR (combined flags)
        safe_pattern!(
            "rm-rf-tmpdir",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with ${TMPDIR} (braced form)
        safe_pattern!(
            "rm-rf-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace",
            r"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -rf with quoted $TMPDIR
        safe_pattern!(
            "rm-rf-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$TMPDIR/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -rf with quoted ${TMPDIR}
        safe_pattern!(
            "rm-rf-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace-quoted",
            r#"^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$\{TMPDIR\}/(?!(?:[^"]*/)?\.\.(?:/|"))[^"]*"(?:\s+|$))+$"#
        ),
        // rm -r -f (separate flags) in /tmp
        safe_pattern!(
            "rm-r-f-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) in /var/tmp
        safe_pattern!(
            "rm-r-f-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-var-tmp",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with $TMPDIR
        safe_pattern!(
            "rm-r-f-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm -r -f (separate flags) with ${TMPDIR}
        safe_pattern!(
            "rm-r-f-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir-brace",
            r"^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /tmp
        safe_pattern!(
            "rm-recursive-force-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) in /var/tmp
        safe_pattern!(
            "rm-recursive-force-var-tmp",
            r"^rm\s+.*--recursive.*--force\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-var-tmp",
            r"^rm\s+.*--force.*--recursive\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with $TMPDIR
        safe_pattern!(
            "rm-recursive-force-tmpdir",
            r"^rm\s+.*--recursive.*--force\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir",
            r"^rm\s+.*--force.*--recursive\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        // rm --recursive --force (long flags) with ${TMPDIR}
        safe_pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"^rm\s+.*--recursive.*--force\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"^rm\s+.*--force.*--recursive\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*(?:\s+|$))+$"
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
            r"^find\s+/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-var-tmp",
            r"^find\s+/var/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:/var/tmp(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-tmpdir",
            r"^find\s+\$TMPDIR(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:\$TMPDIR(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
        ),
        safe_pattern!(
            "find-delete-tmpdir-brace",
            r"^find\s+\$\{TMPDIR\}(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?(?:\s+(?:\$\{TMPDIR\}(?:/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$"
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
            r"^unlink\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-var-tmp",
            r"^unlink\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-tmpdir",
            r"^unlink\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "unlink-tmpdir-brace",
            r"^unlink\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
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
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-var-tmp",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-tmpdir",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "truncate-tmpdir-brace",
            r"^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
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
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-var-tmp",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-tmpdir",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "shred-tmpdir-brace",
            r"^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
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
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-var-tmp",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-tmpdir",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
        ),
        safe_pattern!(
            "tar-remove-files-tmpdir-brace",
            r"^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$"
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
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-var-tmp",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-tmpdir",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
        ),
        safe_pattern!(
            "dd-tmpdir-brace",
            r#"^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s+of=['"]?\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9\-]*(?:=\S+)?))*\s*$"#
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
        // matching tmp variant. Pure /tmp / $TMPDIR moves don't even
        // reach the destructive rule (those prefixes aren't sensitive)
        // but we whitelist them for symmetry and discoverability.
        //
        // Pattern shape: anchored `^...$`, optional flags (each may take
        // a non-path-like value to swallow `-t target`-style args), then
        // one or more tmp-family paths separated by whitespace, then
        // optional trailing flags.
        // -----------------------------------------------------------------
        safe_pattern!(
            "mv-tmp",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-var-tmp",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-tmpdir",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        safe_pattern!(
            "mv-tmpdir-brace",
            r"^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z\-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s+)+\$\{TMPDIR\}/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))\S+\s*$"
        ),
        // mv invoked with --help / --version is read-only.
        safe_pattern!("mv-help", r"^mv\s+(?:--help|--version)\s*$"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // ----- cross-segment sensitive propagation before rm fallbacks -----
        //
        // These patterns must run before the general rm rules below. Otherwise
        // the trailing `rm -rf /tmp/...` segment in the whole compound command
        // is attributed as a generic recursive delete before the propagation
        // chain can be classified.
        destructive_pattern!(
            "cp-sensitive-then-delete",
            r#"\bcp\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)"#,
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
            r#"\bln\b[^|;&]*\s-[A-Za-z]*s[A-Za-z]*[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)"#,
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
            r#"\brsync\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/tmp/|/var/tmp/|\$TMPDIR/|\$\{TMPDIR\}/)"#,
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
             If you need to delete specific files, use explicit paths:\n  \
             rm -rf /path/to/specific/directory\n\n\
             Always preview what would be deleted first:\n  \
             find /path/to/directory -type f | head -20",
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
             - rm -rf in /tmp, /var/tmp, $TMPDIR: Allowed (safe temp directories)\n\n\
             Preview what would be deleted:\n  \
             find /path/to/delete -type f | wc -l  # Count files\n  \
             ls -la /path/to/delete               # List contents",
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
             Safer approach for temporary directories:\n\
             - rm -r -f /tmp/mydir    # Allowed - temp directories are safe\n\
             - rm -r -f $TMPDIR/mydir # Allowed - uses system temp dir\n\n\
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
            r#"\bfind\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)[^|;&]*?\s-delete(?:\s|$|[;&|)\n])"#,
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
        // allows `find /tmp/...`, `/var/tmp/...`, `$TMPDIR/...`, and
        // `${TMPDIR}/...`). Any other `find ... -delete` is an
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
            r#"\bunlink\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
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
        // ----- `truncate -s 0|--size=0|-s -N` (Critical: root/home/system) -----
        //
        // `truncate -s 0 <file>` zeros the file in place — equivalent to
        // deleting all content. With a sensitive target (`/etc/passwd`,
        // `/etc/shadow`, `/etc/sudoers`, `~/.ssh/...`, `$HOME/.aws/...`)
        // this is irrecoverable data destruction.
        //
        // Variants caught by the regex (size operand may have leading `=`):
        //   -s 0
        //   -s -<N>      (shrink by N bytes — destructive)
        //   --size=0
        //   --size=-<N>
        //
        // Variants NOT caught (intentionally — non-destructive):
        //   -s +<N>      (grow — pure append of zeros, no data loss)
        //   -s <N>       (absolute size; could shrink, but the safe path
        //                  is to whitelist via temp dir or restructure)
        //
        // The destructive size operand is `0`, `-<digits>...` (with unit
        // suffix), or `--size=0`/`--size=-...`.
        destructive_pattern!(
            "truncate-zero-root-home",
            r#"\btruncate\b[^|;&]*?(?:\s-s\s+(?:0\b|-\d+)|\s--size=(?:0\b|-\d+))[^|;&]*?\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
            "truncate -s 0|-N on a sensitive system or home path destroys data. EXTREMELY DANGEROUS.",
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
        // ----- `truncate -s 0|--size=0|-s -N` (High: any other target) -----
        destructive_pattern!(
            "truncate-zero-general",
            r"\btruncate\b[^|;&]*?(?:\s-s\s+(?:0\b|-\d+)|\s--size=(?:0\b|-\d+))",
            "truncate -s 0|-N is destructive (zeroes or shrinks file content) and requires human approval.",
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
            r#"\bshred\b[^|;&]*?\s+['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=\s|$|['"]))|/(?=\s|$|['"])|~(?=\s|$|/)|\$\{?HOME\b)"#,
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
            r#"\btar\b[^|;&]*?\s--remove-files\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)|\btar\b[^|;&]*?(?:\s|=)['"\\]?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)[^|;&]*?\s--remove-files\b"#,
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
            r#"\bdd\b[^|;&]*?\bof=['"\\]?(?!/dev/)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
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
        // applies to /tmp / $TMPDIR moves (those don't even trip the
        // destructive regex but are whitelisted for symmetry).
        // The optional-quote group `(?:['"\\]|\$['"])?` extends the
        // historical single-char quote prefix to accept Bash's
        // ANSI-C-quoted (`$'...'`) and locale-translated (`$"..."`)
        // path forms. Without these, `mv $'/etc' /tmp/x` slipped
        // through as a HIGH-impact bypass since mv has no general
        // tier to fall back on.
        destructive_pattern!(
            "mv-sensitive-source-root-home",
            r#"\bmv\b[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
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
        // /tmp / /var/tmp / $TMPDIR redirects: /tmp isn't in the
        // sensitive set so they don't fire the regex at all; /var/tmp
        // would match /var but we don't bother with a safe rescue
        // because the bead's allow-list is explicit (`> /tmp/scratch`,
        // `: > /tmp/cache`) — those naturally fall through. /var/tmp
        // redirects ARE caught by the regex; if that becomes a real
        // pain we can add a safe pattern later.
        // Two carve-outs in the regex below worth understanding:
        //
        //   1. `(?!/dev/(?:null|zero|full)\b)` — never fire on the
        //      universal "discard output" sinks. `cmd > /dev/null` and
        //      `cmd 2>&1 > /dev/null` are the most common shell idioms
        //      in existence; without this carve-out the `dev` element
        //      of the sensitive set would block essentially every
        //      script that suppresses output.
        //
        //   2. `(?:['"\\]|\$['"])?` — extends the historical optional
        //      single-char quote prefix to also accept the two-byte
        //      Bash quoting introducers `$'` (ANSI-C) and `$"`
        //      (locale-translated). Without this, an attacker could
        //      bypass with `> $'/etc/passwd'` or `> $"/etc/passwd"`.
        destructive_pattern!(
            "redirect-truncate-root-home",
            r#"(?<![<>])(?:&>|>&|[12]?>\|?)\s*(?:['"\\]|\$['"])?(?!/dev/(?:null|zero|full)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:/|(?=[\s\)'"]|$))|/(?=[\s\)'"]|$)|~(?=\s|$|/|\))|\$\{?HOME\b)"#,
            "shell redirect (>, >|, &>, >&, 1>, 2>) to a sensitive system or home path truncates the file to zero bytes. EXTREMELY DANGEROUS.",
            Critical,
            "`> /etc/passwd` (or `: > /etc/passwd`, `echo > /etc/passwd`, etc.) opens \
             the target file with O_WRONLY|O_CREAT|O_TRUNC — the contents are destroyed \
             before any write happens. This applies equally to `>|` (force-overwrite), \
             `&>` / `>&` (stdout+stderr to file), and numbered FD forms (`1>`, `2>`, `1>|`, \
             `2>|`). All of these are silent, immediate, irrecoverable.\n\n\
             There is NO recovery without backups.\n\n\
             Safer alternatives:\n\
             - Use append (`>>`) to preserve existing content: `echo line >> <file>`.\n\
             - Make a backup: `cp <file> <file>.bak && echo data > <file>`.\n\
             - For temp scratch: `> /tmp/<subdir>/scratch` is allowed.\n\
             - Read redirects (`< <file>`) are not affected — they don't truncate.",
            REDIRECT_TRUNCATE_SUGGESTIONS
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
            "find $TMPDIR -delete",
            "find $TMPDIR/work -name '*.tmp' -delete",
            "find ${TMPDIR} -delete",
            "find ${TMPDIR}/work -delete",
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
            "find $TMPDIR -delete",
            "find ${TMPDIR} -delete",
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
            "unlink $TMPDIR/file",
            "unlink ${TMPDIR}/file",
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
            "truncate -s 0 $TMPDIR/cache.bin",
            "truncate --size=0 ${TMPDIR}/scratch",
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
            "shred -u $TMPDIR/file",
            "shred -u ${TMPDIR}/file",
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
            "tar --remove-files -cf out.tar $TMPDIR/scratch",
            "tar --remove-files -cf out.tar ${TMPDIR}/scratch",
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
            "dd if=/dev/zero of=$TMPDIR/cache.bin",
            "dd if=/dev/zero of=${TMPDIR}/scratch",
            "dd of=/tmp/out.bin",
            "dd of=/tmp/out.bin if=/dev/zero",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
        }
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
        // (mv-tmp / mv-var-tmp / mv-tmpdir / mv-tmpdir-brace). For /var/tmp
        // the safe pattern is load-bearing because /var is sensitive and
        // would otherwise trip the destructive rule; for /tmp / $TMPDIR
        // the safe pattern is whitelisted for symmetry/discoverability —
        // those prefixes aren't sensitive so the destructive rule
        // wouldn't fire either way, but the explicit allow makes the
        // intent clearer to anyone reading explain output.
        for cmd in [
            "mv /tmp/foo /tmp/bar",
            "mv /tmp/foo /tmp/sub/bar",
            "mv -v /tmp/foo /tmp/bar",
            "mv /var/tmp/foo /var/tmp/bar",
            "mv /var/tmp/dir1 /var/tmp/dir2",
            "mv $TMPDIR/foo $TMPDIR/bar",
            "mv ${TMPDIR}/foo ${TMPDIR}/bar",
        ] {
            assert_safe_pattern_matches(&pack, cmd);
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
            "echo x 1>| /etc/passwd",
            "echo x 2>| /etc/passwd",
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
            "command > $TMPDIR/scratch",
            "command > ${TMPDIR}/scratch",
            "echo x >| build.log",
            "echo x &> build.log",
            "echo x >& build.log",
            "echo x 2> err.log",
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
        // The /dev/{null,zero,full} carve-out must NOT relax actual
        // device destruction (`> /dev/sda` etc.) — only the safe sinks.
        let pack = create_pack();
        for cmd in [
            "> /dev/sda",
            "echo zero > /dev/sda1",
            "command > /dev/sdb",
            "echo > /dev/nvme0n1",
        ] {
            assert_blocks_with_pattern(&pack, cmd, "redirect-truncate-root-home");
        }
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
            "echo data>$LOG_FILE",
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
        assert_safe_pattern_matches(&pack, "rm -rf $TMPDIR/junk");
        assert_safe_pattern_matches(&pack, "rm -rf ${TMPDIR}/junk");
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
    fn test_rm_parser_allows_tmpdir_quotes() {
        assert_rm_parser_allows(r#"rm -rf "$TMPDIR/foo""#);
        assert_rm_parser_allows(r#"rm -rf "${TMPDIR}/foo""#);
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
    }

    #[test]
    fn test_rm_parser_allows_literal_tmp_double_quoted() {
        // Regression for #201: double quotes around /tmp and /var/tmp are
        // shell-transparent (bash quoting only affects expansion and word
        // splitting, not literal text). `rm -rf "/tmp/foo"` must have parity
        // with `rm -rf /tmp/foo` — previously the quoted form was falsely
        // classified as a CRITICAL root/home deletion.
        assert_rm_parser_allows(r#"rm -rf "/tmp/foo""#);
        assert_rm_parser_allows(r#"rm -rf "/tmp/build/artifacts""#);
        assert_rm_parser_allows(r#"rm -rf "/var/tmp/cache""#);

        // Dot-dot traversal inside the quoted path must still deny (parity
        // with the unquoted `has_dotdot_segment` guard).
        assert_rm_parser_denies(
            r#"rm -rf "/tmp/../etc""#,
            RM_RF_ROOT_HOME_NAME,
            Severity::Critical,
        );
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
}

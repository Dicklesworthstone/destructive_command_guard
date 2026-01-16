//! Core filesystem patterns - protections against destructive rm commands.
//!
//! This includes patterns for:
//! - rm -rf outside temp directories (blocked)
//! - rm -rf in /tmp, /var/tmp, $TMPDIR (allowed)

use crate::packs::{DestructivePattern, Pack, SafePattern, Severity};
use crate::{destructive_pattern, safe_pattern};
use crate::{normalize::NormalizeTokenKind, normalize::tokenize_for_normalization};
use std::ops::Range;

const RM_RF_ROOT_HOME_NAME: &str = "rm-rf-root-home";
const RM_RF_ROOT_HOME_REASON: &str = "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.";
const RM_RF_GENERAL_NAME: &str = "rm-rf-general";
const RM_RF_GENERAL_REASON: &str = "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.";
const RM_R_F_SEPARATE_NAME: &str = "rm-r-f-separate";
const RM_R_F_SEPARATE_REASON: &str =
    "rm with separate -r -f flags is destructive and requires human approval.";
const RM_RECURSIVE_FORCE_NAME: &str = "rm-recursive-force-long";
const RM_RECURSIVE_FORCE_REASON: &str =
    "rm --recursive --force is destructive and requires human approval.";

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

    let first_path = paths.first();
    let is_critical = flag_state.style == RmFlagStyle::Combined
        && !flag_state.saw_terminator
        && first_path.is_some_and(path_is_root_home);

    let (pattern_name, reason, severity) = if is_critical {
        (
            RM_RF_ROOT_HOME_NAME,
            RM_RF_ROOT_HOME_REASON,
            Severity::Critical,
        )
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
    if path.quote != QuoteKind::None {
        return false;
    }

    let text = path.unquoted;
    text.starts_with('/') || text.starts_with('~')
}

/// Create the core filesystem pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "core.filesystem".to_string(),
        name: "Core Filesystem",
        description: "Protects against dangerous rm -rf commands outside temp directories",
        keywords: &["rm"],
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
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // rm -rf on root or home paths (CRITICAL - catastrophic, never allow)
        destructive_pattern!(
            "rm-rf-root-home",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+[/~]|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+[/~]",
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
             find /path/to/directory -type f | head -20"
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
             ls -la /path/to/delete               # List contents"
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
             rm -ri /path  # Interactive confirmation"
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
             find /path --maxdepth 2 -ls | head -30"
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
    }

    #[test]
    fn test_rm_rf_root_critical() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "rm -rf /", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /etc", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf /home", Severity::Critical);
        assert_blocks_with_severity(&pack, "rm -rf ~/", Severity::Critical);
        assert_blocks_with_pattern(&pack, "rm -rf /", "rm-rf-root-home");
    }

    #[test]
    fn test_rm_rf_general_high() {
        let pack = create_pack();
        // Outside safe dirs, general rule catches it
        assert_blocks_with_severity(&pack, "rm -rf ./build", Severity::High);
        assert_blocks_with_pattern(&pack, "rm -rf ./build", "rm-rf-general");
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
    }
}

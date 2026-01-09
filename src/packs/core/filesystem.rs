//! Core filesystem patterns - protections against destructive rm commands.
//!
//! This includes patterns for:
//! - rm -rf outside temp directories (blocked)
//! - rm -rf in /tmp, /var/tmp, $TMPDIR (allowed)
//!
//! # Build Directory Cleanup
//!
//! For safe deletion of build directories (target/, dist/, `node_modules`/, etc.),
//! enable the `safe.cleanup` pack. See [`crate::packs::safe::cleanup`] for details.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

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
    }
}

#[allow(clippy::too_many_lines)]
fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // rm -rf in /tmp (combined flags)
        safe_pattern!(
            "rm-rf-tmp",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-fr-tmp",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -rf in /var/tmp (combined flags)
        safe_pattern!(
            "rm-rf-var-tmp",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-fr-var-tmp",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -rf with $TMPDIR (combined flags)
        safe_pattern!(
            "rm-rf-tmpdir",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-fr-tmpdir",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -rf with ${TMPDIR} (braced form)
        safe_pattern!(
            "rm-rf-tmpdir-brace",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace",
            r"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -rf with quoted $TMPDIR
        safe_pattern!(
            "rm-rf-tmpdir-quoted",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-quoted",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        // rm -rf with quoted ${TMPDIR}
        safe_pattern!(
            "rm-rf-tmpdir-brace-quoted",
            r#"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+"\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        safe_pattern!(
            "rm-fr-tmpdir-brace-quoted",
            r#"rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+"\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"#
        ),
        // rm -r -f (separate flags) in /tmp
        safe_pattern!(
            "rm-r-f-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-f-r-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -r -f (separate flags) in /var/tmp
        safe_pattern!(
            "rm-r-f-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-f-r-var-tmp",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -r -f (separate flags) with $TMPDIR
        safe_pattern!(
            "rm-r-f-tmpdir",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm -r -f (separate flags) with ${TMPDIR}
        safe_pattern!(
            "rm-r-f-tmpdir-brace",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-f-r-tmpdir-brace",
            r"rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm --recursive --force (long flags) in /tmp
        safe_pattern!(
            "rm-recursive-force-tmp",
            r"rm\s+.*--recursive.*--force\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-force-recursive-tmp",
            r"rm\s+.*--force.*--recursive\s+/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm --recursive --force (long flags) in /var/tmp
        safe_pattern!(
            "rm-recursive-force-var-tmp",
            r"rm\s+.*--recursive.*--force\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-force-recursive-var-tmp",
            r"rm\s+.*--force.*--recursive\s+/var/tmp/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm --recursive --force (long flags) with $TMPDIR
        safe_pattern!(
            "rm-recursive-force-tmpdir",
            r"rm\s+.*--recursive.*--force\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir",
            r"rm\s+.*--force.*--recursive\s+\$TMPDIR/(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        // rm --recursive --force (long flags) with ${TMPDIR}
        safe_pattern!(
            "rm-recursive-force-tmpdir-brace",
            r"rm\s+.*--recursive.*--force\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
        ),
        safe_pattern!(
            "rm-force-recursive-tmpdir-brace",
            r"rm\s+.*--force.*--recursive\s+\$\{TMPDIR(?!\.\.(?:/|\s|$)|[^\s]*/\.\.(?:/|\s|$))"
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
            Critical
        ),
        // General rm -rf (caught after safe patterns) - High because temp paths are allowed
        destructive_pattern!(
            "rm-rf-general",
            r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]",
            "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.",
            High
        ),
        // rm -r -f (separate flags)
        destructive_pattern!(
            "rm-r-f-separate",
            r"rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]",
            "rm with separate -r -f flags is destructive and requires human approval.",
            High
        ),
        // rm --recursive --force (long flags)
        destructive_pattern!(
            "rm-recursive-force-long",
            r"rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive",
            "rm --recursive --force is destructive and requires human approval.",
            High
        ),
    ]
}

//! Core git patterns - protections against destructive git commands.
//!
//! This includes patterns for:
//! - Work destruction (reset --hard, checkout --, restore)
//! - History rewriting (push --force, branch -D)
//! - Stash destruction (stash drop, stash clear)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Branch creation is safe
        safe_pattern!("checkout-new-branch", r"git\s+checkout\s+-b\s+"),
        safe_pattern!("checkout-orphan", r"git\s+checkout\s+--orphan\s+"),
        // restore --staged only affects index, not working tree
        safe_pattern!(
            "restore-staged-long",
            r"git\s+restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        safe_pattern!(
            "restore-staged-short",
            r"git\s+restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        // clean dry-run just previews, doesn't delete
        safe_pattern!("clean-dry-run-short", r"git\s+clean\s+-[a-z]*n[a-z]*"),
        safe_pattern!("clean-dry-run-long", r"git\s+clean\s+--dry-run"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Severity levels:
    // - Critical: Most dangerous, irreversible, high-confidence detections
    // - High: Dangerous but more context-dependent (default)
    // - Medium: Warn by default
    // - Low: Log only

    vec![
        // checkout -- discards uncommitted changes
        destructive_pattern!(
            "checkout-discard",
            r"git\s+checkout\s+--\s+",
            "git checkout -- discards uncommitted changes permanently. Use 'git stash' first.",
            High
        ),
        destructive_pattern!(
            "checkout-ref-discard",
            r"git\s+checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
            "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first.",
            High
        ),
        // restore without --staged affects working tree
        destructive_pattern!(
            "restore-worktree",
            r"git\s+restore\s+(?!--staged\b)(?!-S\b)",
            "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first.",
            High
        ),
        destructive_pattern!(
            "restore-worktree-explicit",
            r"git\s+restore\s+.*(?:--worktree|-W\b)",
            "git restore --worktree/-W discards uncommitted changes permanently.",
            High
        ),
        // reset --hard destroys uncommitted work (CRITICAL - extremely common mistake)
        destructive_pattern!(
            "reset-hard",
            r"git\s+reset\s+--hard",
            "git reset --hard destroys uncommitted changes. Use 'git stash' first.",
            Critical
        ),
        destructive_pattern!(
            "reset-merge",
            r"git\s+reset\s+--merge",
            "git reset --merge can lose uncommitted changes.",
            High
        ),
        // clean -f deletes untracked files (CRITICAL - permanently removes files)
        destructive_pattern!(
            "clean-force",
            r"git\s+clean\s+-[a-z]*f",
            "git clean -f removes untracked files permanently. Review with 'git clean -n' first.",
            Critical
        ),
        // force push can destroy remote history (CRITICAL - affects shared history)
        destructive_pattern!(
            "push-force-long",
            r"git\s+push\s+.*--force(?![-a-z])",
            "Force push can destroy remote history. Use --force-with-lease if necessary.",
            Critical
        ),
        destructive_pattern!(
            "push-force-short",
            r"git\s+push\s+.*-f\b",
            "Force push (-f) can destroy remote history. Use --force-with-lease if necessary.",
            Critical
        ),
        // branch -D force deletes without merge check
        destructive_pattern!(
            "branch-force-delete",
            r"git\s+branch\s+-D\b",
            "git branch -D force-deletes without merge check. Use -d for safety.",
            High
        ),
        // stash destruction
        destructive_pattern!(
            "stash-drop",
            r"git\s+stash\s+drop",
            "git stash drop permanently deletes stashed changes. List stashes first.",
            High
        ),
        // stash clear destroys ALL stashes (CRITICAL)
        destructive_pattern!(
            "stash-clear",
            r"git\s+stash\s+clear",
            "git stash clear permanently deletes ALL stashed changes.",
            Critical
        ),
    ]
}

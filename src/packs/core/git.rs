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

#[cfg(test)]
mod tests {
    //! Unit tests for core.git pack using the `test_helpers` framework.
    //!
    //! This module serves as an example of how to use the pack testing
    //! infrastructure. See `docs/pack-testing-guide.md` for details.

    use super::*;
    use crate::packs::test_helpers::*;
    use crate::packs::Severity;

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
        assert_blocks(&pack, "git reset --hard origin/main", "destroys uncommitted");
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
        assert_blocks(&pack, "git push origin main --force", "destroy remote history");
        assert_blocks(&pack, "git push --force origin main", "destroy remote history");
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

    #[test]
    fn test_restore_worktree_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git restore file.txt", Severity::High);
        assert_blocks(&pack, "git restore --worktree file.txt", "discards uncommitted");
    }

    #[test]
    fn test_branch_force_delete_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git branch -D feature", Severity::High);
        assert_blocks_with_pattern(&pack, "git branch -D feature", "branch-force-delete");
    }

    #[test]
    fn test_stash_drop_high() {
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git stash drop", Severity::High);
        assert_blocks(&pack, "git stash drop stash@{0}", "permanently deletes");
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

        test_batch_allows(&pack, &[
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
            "git push",  // Without --force
            "git add .",
            "git commit -m 'message'",
            "git branch -d feature",  // Safe delete with -d
        ]);
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
}

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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Branch creation is safe
        safe_pattern!("checkout-new-branch", r"git\s+(?:\S+\s+)*checkout\s+-b\s+"),
        safe_pattern!(
            "checkout-orphan",
            r"git\s+(?:\S+\s+)*checkout\s+--orphan\s+"
        ),
        // restore --staged only affects index, not working tree
        safe_pattern!(
            "restore-staged-long",
            r"git\s+(?:\S+\s+)*restore\s+--staged\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        safe_pattern!(
            "restore-staged-short",
            r"git\s+(?:\S+\s+)*restore\s+-S\s+(?!.*--worktree)(?!.*-W\b)"
        ),
        // clean dry-run just previews, doesn't delete
        safe_pattern!(
            "clean-dry-run-short",
            r"git\s+(?:\S+\s+)*clean\s+-[a-z]*n[a-z]*"
        ),
        safe_pattern!("clean-dry-run-long", r"git\s+(?:\S+\s+)*clean\s+--dry-run"),
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
        // checkout -- discards uncommitted changes
        destructive_pattern!(
            "checkout-discard",
            r"git\s+(?:\S+\s+)*checkout\s+--\s+",
            "git checkout -- discards uncommitted changes permanently. Use 'git stash' first.",
            High,
            "git checkout -- <path> discards all uncommitted changes to the specified files \
             in your working directory. These changes are permanently lost - they cannot be \
             recovered because they were never committed.\n\n\
             Safer alternatives:\n\
             - git stash: Save changes temporarily, restore later with 'git stash pop'\n\
             - git diff <path>: Review what would be lost before discarding\n\n\
             Preview changes first:\n  git diff -- <path>"
        ),
        destructive_pattern!(
            "checkout-ref-discard",
            r"git\s+(?:\S+\s+)*checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+",
            "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first.",
            High,
            "git checkout <ref> -- <path> replaces your working tree files with versions from \
             another commit or branch. Any uncommitted changes to those files are permanently \
             lost - they cannot be recovered.\n\n\
             Safer alternatives:\n\
             - git stash: Save changes first, then checkout, then restore with 'git stash pop'\n\
             - git show <ref>:<path>: View the file content without overwriting\n\n\
             Preview what would change:\n  git diff HEAD <ref> -- <path>"
        ),
        // restore without --staged affects working tree
        destructive_pattern!(
            "restore-worktree",
            r"git\s+(?:\S+\s+)*restore\s+(?!--staged\b)(?!-S\b)",
            "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first.",
            High,
            "git restore <path> discards uncommitted changes in your working directory, \
             reverting files to their last committed state. Changes that were never \
             committed are permanently lost.\n\n\
             Safer alternatives:\n\
             - git restore --staged <path>: Only unstage, keeps working directory changes\n\
             - git stash: Save all changes temporarily\n\
             - git diff <path>: Review what would be lost\n\n\
             Preview changes first:\n  git diff <path>"
        ),
        destructive_pattern!(
            "restore-worktree-explicit",
            r"git\s+(?:\S+\s+)*restore\s+.*(?:--worktree|-W\b)",
            "git restore --worktree/-W discards uncommitted changes permanently.",
            High,
            "git restore --worktree (or -W) explicitly targets your working directory, \
             discarding uncommitted changes. Even when combined with --staged, the worktree \
             changes are permanently lost.\n\n\
             Safer alternatives:\n\
             - git restore --staged <path>: Only unstage, keeps working directory\n\
             - git stash: Save changes first\n\n\
             Preview changes first:\n  git diff <path>"
        ),
        // reset --hard destroys uncommitted work (CRITICAL - extremely common mistake)
        destructive_pattern!(
            "reset-hard",
            r"git\s+(?:\S+\s+)*reset\s+--hard",
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
             Preview what would be lost:\n  git status && git diff"
        ),
        destructive_pattern!(
            "reset-merge",
            r"git\s+(?:\S+\s+)*reset\s+--merge",
            "git reset --merge can lose uncommitted changes.",
            High,
            "git reset --merge resets the index and updates files in the working tree that \
             differ between the target commit and HEAD, but keeps changes that are not staged. \
             However, if there are uncommitted changes in files that need to be updated, \
             those changes will be lost.\n\n\
             Safer alternatives:\n\
             - git stash: Save uncommitted changes before reset\n\
             - git merge --abort: If in the middle of a merge, abort safely\n\n\
             Preview what would change:\n  git status && git diff"
        ),
        // clean -f deletes untracked files (CRITICAL - permanently removes files)
        destructive_pattern!(
            "clean-force",
            r"git\s+(?:\S+\s+)*clean\s+(?:-[a-z]*f|--force\b)",
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
             ALWAYS preview first:\n  git clean -n -d"
        ),
        // force push can destroy remote history (CRITICAL - affects shared history)
        destructive_pattern!(
            "push-force-long",
            r"git\s+(?:\S+\s+)*push\s+.*--force(?![-a-z])",
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
             Check remote state first:\n  git fetch && git log origin/<branch>..HEAD"
        ),
        destructive_pattern!(
            "push-force-short",
            r"git\s+(?:\S+\s+)*push\s+.*-f\b",
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
             Check remote state first:\n  git fetch && git log origin/<branch>..HEAD"
        ),
        // branch -D/-f force deletes or overwrites without checks (Medium: recoverable via reflog)
        destructive_pattern!(
            "branch-force-delete",
            r"git\s+(?:\S+\s+)*branch\s+.*(?:-D\b|--force\b|-f\b)",
            "git branch -D/--force deletes branches without checks. Recoverable via 'git reflog'.",
            Medium,
            "git branch -D force-deletes a branch without checking if it has been merged. \
             If the branch contains unmerged commits, you may lose access to that work. \
             However, the commits still exist in git's object database and can be recovered \
             using reflog (for a limited time, typically 90 days).\n\n\
             Safer alternatives:\n\
             - git branch -d <branch>: Safe delete, fails if branch is not fully merged\n\
             - Merge the branch first, then delete with -d\n\n\
             Recovery if needed:\n\
               git reflog  # Find the commit hash\n\
               git checkout -b <branch> <commit-hash>"
        ),
        // stash destruction (Medium: single stash, recoverable via fsck/unreachable objects)
        destructive_pattern!(
            "stash-drop",
            r"git\s+(?:\S+\s+)*stash\s+drop",
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
               git show <commit-hash>  # Inspect each to find your stash"
        ),
        // stash clear destroys ALL stashes (CRITICAL)
        destructive_pattern!(
            "stash-clear",
            r"git\s+(?:\S+\s+)*stash\s+clear",
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
               git fsck --unreachable | grep commit"
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
        assert_blocks(
            &pack,
            "git restore --worktree file.txt",
            "discards uncommitted",
        );
    }

    #[test]
    fn test_branch_force_medium() {
        // Branch force delete is Medium severity (recoverable via reflog)
        let pack = create_pack();

        assert_blocks_with_severity(&pack, "git branch -D feature", Severity::Medium);
        assert_blocks_with_pattern(&pack, "git branch -D feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch --force feature", "branch-force-delete");
        assert_blocks_with_pattern(&pack, "git branch -f feature", "branch-force-delete");
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
                "git branch -d feature", // Safe delete with -d
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
}

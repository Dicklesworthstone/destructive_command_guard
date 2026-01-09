//! Strict Git pack - additional git protections beyond the core pack.
//!
//! This pack provides stricter protections that some users may want:
//! - Block all force pushes (even with --force-with-lease)
//! - Block rebase operations
//! - Block amending commits that have been pushed
//! - Block git filter-branch and other history rewriting

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the strict git pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "strict_git".to_string(),
        name: "Strict Git",
        description: "Stricter git protections: blocks all force pushes, rebases, and \
                      history rewriting operations",
        keywords: &["git"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Interactive rebase is allowed (you can still abort)
        // Actually no, let's be strict about this too
        // Read-only commands are always safe
        safe_pattern!("git-status", r"git\s+status"),
        safe_pattern!("git-log", r"git\s+log"),
        safe_pattern!("git-diff", r"git\s+diff"),
        safe_pattern!("git-show", r"git\s+show"),
        safe_pattern!("git-branch-list", r"git\s+branch\s*$|git\s+branch\s+-[alv]"),
        safe_pattern!("git-remote-v", r"git\s+remote\s+-v"),
        safe_pattern!("git-fetch", r"git\s+fetch"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Block ALL force pushes (including --force-with-lease)
        destructive_pattern!(
            "push-force-any",
            r"git\s+push\s+.*(?:--force|--force-with-lease|-f\b)",
            "Force push (even with --force-with-lease) can rewrite remote history. Disabled in strict mode."
        ),
        // Block rebase (can rewrite history)
        destructive_pattern!(
            "rebase",
            r"git\s+rebase\b",
            "git rebase rewrites commit history. Disabled in strict mode."
        ),
        // Block commit --amend (rewrites last commit)
        destructive_pattern!(
            "commit-amend",
            r"git\s+commit\s+.*--amend",
            "git commit --amend rewrites the last commit. Disabled in strict mode."
        ),
        // Block cherry-pick (can be misused)
        destructive_pattern!(
            "cherry-pick",
            r"git\s+cherry-pick\b",
            "git cherry-pick can introduce duplicate commits. Review carefully."
        ),
        // Block filter-branch (rewrites entire history)
        destructive_pattern!(
            "filter-branch",
            r"git\s+filter-branch\b",
            "git filter-branch rewrites entire repository history. Extremely dangerous!"
        ),
        // Block filter-repo (modern replacement for filter-branch)
        destructive_pattern!(
            "filter-repo",
            r"git\s+filter-repo\b",
            "git filter-repo rewrites repository history. Review carefully."
        ),
        // Block reflog expire (can lose recovery points)
        destructive_pattern!(
            "reflog-expire",
            r"git\s+reflog\s+expire",
            "git reflog expire removes reflog entries needed for recovery."
        ),
        // Block gc with aggressive options
        destructive_pattern!(
            "gc-aggressive",
            r"git\s+gc\s+.*--(?:aggressive|prune)",
            "git gc with aggressive/prune options can remove recoverable objects."
        ),
        // Block worktree remove
        destructive_pattern!(
            "worktree-remove",
            r"git\s+worktree\s+remove",
            "git worktree remove deletes a linked working tree."
        ),
        // Block submodule deinit
        destructive_pattern!(
            "submodule-deinit",
            r"git\s+submodule\s+deinit",
            "git submodule deinit removes submodule configuration."
        ),
    ]
}

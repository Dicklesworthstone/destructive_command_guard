//! Strict Git pack - additional git protections beyond the core pack.
//!
//! This pack provides stricter protections that some users may want:
//! - Block all force pushes (even with --force-with-lease)
//! - Block rebase operations
//! - Block amending commits that have been pushed
//! - Block git filter-branch and other history rewriting
//! - Block `git add .` / `git add -A` (stage everything blindly)
//! - Block direct pushes to main/master (should use PRs)

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack, SafePattern};

/// Create the strict git pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "strict_git".to_string(),
        name: "Strict Git",
        description: "Stricter git protections: blocks force pushes, rebases, history \
                      rewriting, blind staging, and direct pushes to default branches",
        keywords: &["git"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // No safe patterns needed: none of the destructive patterns in this pack
    // match read-only commands (git status, git log, etc.).  Previously broad
    // safe patterns like `git\s+status` were defined here, but they created a
    // bypass vector: a compound command such as `git add . ; git status` would
    // be whitelisted because the `git status` suffix matched the safe pattern,
    // hiding the destructive `git add .` prefix.
    vec![]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Block ALL force pushes (including --force-with-lease)
        destructive_pattern!(
            "push-force-any",
            r"git\b.*?\bpush\s+.*(?:--force|--force-with-lease|-f\b)",
            "Force push (even with --force-with-lease) can rewrite remote history. Disabled in strict mode."
        ),
        // Block rebase (can rewrite history)
        destructive_pattern!(
            "rebase",
            r"git\b.*?\brebase\b",
            "git rebase rewrites commit history. Disabled in strict mode."
        ),
        // Block commit --amend (rewrites last commit)
        destructive_pattern!(
            "commit-amend",
            r"git\b.*?\bcommit\s+.*--amend",
            "git commit --amend rewrites the last commit. Disabled in strict mode."
        ),
        // Block cherry-pick (can be misused)
        destructive_pattern!(
            "cherry-pick",
            r"git\b.*?\bcherry-pick\b",
            "git cherry-pick can introduce duplicate commits. Review carefully."
        ),
        // Block filter-branch (rewrites entire history)
        destructive_pattern!(
            "filter-branch",
            r"git\b.*?\bfilter-branch\b",
            "git filter-branch rewrites entire repository history. Extremely dangerous!"
        ),
        // Block filter-repo (modern replacement for filter-branch)
        destructive_pattern!(
            "filter-repo",
            r"git\b.*?\bfilter-repo\b",
            "git filter-repo rewrites repository history. Review carefully."
        ),
        // Block reflog expire (can lose recovery points)
        destructive_pattern!(
            "reflog-expire",
            r"git\b.*?\breflog\s+expire",
            "git reflog expire removes reflog entries needed for recovery."
        ),
        // Block gc with aggressive options
        destructive_pattern!(
            "gc-aggressive",
            r"git\b.*?\bgc\s+.*--(?:aggressive|prune)",
            "git gc with aggressive/prune options can remove recoverable objects."
        ),
        // Block worktree remove
        destructive_pattern!(
            "worktree-remove",
            r"git\b.*?\bworktree\s+remove",
            "git worktree remove deletes a linked working tree."
        ),
        // Block submodule deinit
        destructive_pattern!(
            "submodule-deinit",
            r"git\b.*?\bsubmodule\s+deinit",
            "git submodule deinit removes submodule configuration."
        ),
        // Block git add . (stages everything, may include secrets, .env, build artifacts)
        // Use (?:\s|$) instead of \s*$ so we also catch compound commands like
        // "git add . && echo done" (bypass via shell chaining). Also accept an
        // optional quote pair around `.` so `git add '.'` / `git add "."` are
        // caught — shell-quoted `.` evaluates to `.` in the exec and stages
        // everything identically.
        destructive_pattern!(
            "add-all-dot",
            r#"git\b.*?\badd\s+['"]?\.['"]?(?:\s|$)"#,
            "git add . stages everything including secrets, .env files, and build artifacts. Use 'git add <specific-files>' instead."
        ),
        // Block git add -A / git add --all (same concern as git add .)
        destructive_pattern!(
            "add-all-flag",
            r"git\b.*?\badd\s+(?:-A|--all)\b",
            "git add -A/--all stages all changes including secrets, .env files, and build artifacts. Use 'git add <specific-files>' instead."
        ),
        // Block push to master. Separators include `/` so explicit refspecs
        // like `HEAD:refs/heads/master` are caught — `main` appearing after
        // `/` in `refs/heads/main` used to bypass the old `[\s:]` separator.
        destructive_pattern!(
            "push-master",
            r"git\s+(?:\S+\s+)*push\s+(?:.*[\s:/])?master(?:\s|$)",
            "Direct push to master is blocked. Use a feature branch and open a Pull Request."
        ),
        // Block push to main
        destructive_pattern!(
            "push-main",
            r"git\s+(?:\S+\s+)*push\s+(?:.*[\s:/])?main(?:\s|$)",
            "Direct push to main is blocked. Use a feature branch and open a Pull Request."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn strict_git_patterns_match_with_git_global_flags() {
        // Same class bug as cloud/container packs: git's global flags
        // (`-C <path>`, `-c key=value`, `--git-dir=`, `--work-tree=`,
        // `--exec-path=`) go BEFORE the subcommand.  Every
        // `git\s+<sub>` pattern failed to match these shapes.  Most
        // impactful: `git -C /path/to/repo push --force` on a
        // CI-server where operators drive multiple worktrees from a
        // single invocation.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "git -C /path/to/repo push origin --force",
            "Force push",
        );
        assert_blocks(
            &pack,
            "git -c user.email=bot@corp.com rebase -i HEAD~3",
            "rebase",
        );
        assert_blocks(
            &pack,
            "git --git-dir=/prod/.git commit --amend",
            "commit --amend",
        );
        assert_blocks(
            &pack,
            "git -C /repo filter-branch --tree-filter 'rm -f secret' HEAD",
            "filter-branch",
        );
        assert_blocks(&pack, "git -C ./submodule worktree remove dead", "worktree");
        assert_blocks(&pack, "git -C /prod add .", "stages everything");
        assert_blocks(&pack, "git -C /prod add -A", "stages all changes");
    }

    #[test]
    fn test_add_all_dot() {
        let pack = create_pack();
        assert_blocks(&pack, "git add .", "stages everything");
        // Chained commands must still be caught (bypass vector)
        assert_blocks(&pack, "git add . && echo done", "stages everything");
        assert_blocks(&pack, "git add . ; git status", "stages everything");
        assert_blocks(&pack, "git add . | cat", "stages everything");
        // Trailing whitespace
        assert_blocks(&pack, "git add . ", "stages everything");
        // Quoted `.` — shell unquotes to `.`, same stage-everything effect.
        assert_blocks(&pack, "git add '.'", "stages everything");
        assert_blocks(&pack, "git add \".\"", "stages everything");
        assert_blocks(&pack, "git add '.' && echo done", "stages everything");
        // Should not match when adding specific dotfiles or paths starting with .
        assert_allows(&pack, "git add .gitignore");
        assert_allows(&pack, "git add ./src/main.rs");
        assert_allows(&pack, "git add .env.example");
    }

    #[test]
    fn test_add_all_flag() {
        let pack = create_pack();
        assert_blocks(&pack, "git add -A", "stages all changes");
        assert_blocks(&pack, "git add --all", "stages all changes");
        // Should not match unrelated flags
        assert_allows(&pack, "git add -p");
        assert_allows(&pack, "git add --patch");
    }

    #[test]
    fn test_push_master() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "git push origin master",
            "Direct push to master is blocked",
        );
        assert_blocks(&pack, "git push master", "Direct push to master is blocked");
        assert_blocks(
            &pack,
            "git push origin HEAD:master",
            "Direct push to master is blocked",
        );
        assert_blocks(
            &pack,
            "git push origin master:master",
            "Direct push to master is blocked",
        );

        // These should be allowed (unless blocked by other rules)
        assert_allows(&pack, "git push origin feature-master");
        assert_allows(&pack, "git push origin master-fix");
    }

    #[test]
    fn test_push_main() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "git push origin main",
            "Direct push to main is blocked",
        );
        assert_blocks(&pack, "git push main", "Direct push to main is blocked");
        assert_blocks(
            &pack,
            "git push origin HEAD:main",
            "Direct push to main is blocked",
        );
        assert_blocks(
            &pack,
            "git push origin main:main",
            "Direct push to main is blocked",
        );
        // Explicit refspec forms must not bypass via the `/` separator.
        assert_blocks(
            &pack,
            "git push origin HEAD:refs/heads/main",
            "Direct push to main is blocked",
        );
        assert_blocks(
            &pack,
            "git push origin refs/heads/main",
            "Direct push to main is blocked",
        );

        // These should be allowed (unless blocked by other rules)
        assert_allows(&pack, "git push origin feature-main");
        assert_allows(&pack, "git push origin main-fix");
        assert_allows(&pack, "git push origin maintain");
    }

    #[test]
    fn test_push_master_refspec() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "git push origin HEAD:refs/heads/master",
            "Direct push to master is blocked",
        );
        assert_blocks(
            &pack,
            "git push origin refs/heads/master",
            "Direct push to master is blocked",
        );
    }
}

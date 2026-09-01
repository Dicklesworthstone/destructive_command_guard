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
            r#"git\b.*?\bpush(?:[^\n;]*\s(?:--force(?:=\S*)?|--force-with-lease(?:=\S*)?|-f)(?=\s|$)|(?:\s+\S+)*\s+(?:\$?["']|\\)*\+\S+)"#,
            "Force push (even with --force-with-lease) can rewrite remote history. Disabled in strict mode.",
            executables = ["git", "git-push"]
        ),
        // `--mirror` force-updates every mirrored ref and deletes remote refs
        // that are absent locally. It is at least as destructive as --force.
        destructive_pattern!(
            "push-mirror",
            r"git\b.*?\bpush\b[^\n;]*(?:^|\s)--mirror(?:=\S*)?(?=\s|$)",
            "git push --mirror force-updates and deletes remote refs. Disabled in strict mode.",
            executables = ["git", "git-push"]
        ),
        // A dynamically constructed push argument can render Git's leading
        // `+refspec` force syntax only after the shell expands it. Strict mode
        // cannot prove such a push is non-forcing, so fail closed instead of
        // letting ANSI-C strings, printf substitutions, or env vars bypass the
        // literal-plus rule above.
        destructive_pattern!(
            "push-dynamic-argument",
            r"git\b.*?\bpush\b[^\n;]*(?:\\|\$|`|\*|\?|\{|\}|\[)",
            "Force push risk: a shell-expanded or escaped git push argument cannot be verified as non-forcing. Use literal remote and refspec arguments in strict mode.",
            executables = ["git", "git-push"]
        ),
        // Block rebase (can rewrite history)
        destructive_pattern!(
            "rebase",
            r"git\b.*?\brebase\b",
            "git rebase rewrites commit history. Disabled in strict mode.",
            executables = ["git", "git-rebase"]
        ),
        // Block commit --amend (rewrites last commit)
        destructive_pattern!(
            "commit-amend",
            r"git\b.*?\bcommit\s+.*--amend",
            "git commit --amend rewrites the last commit. Disabled in strict mode.",
            executables = ["git", "git-commit"]
        ),
        // Block cherry-pick (can be misused)
        destructive_pattern!(
            "cherry-pick",
            r"git\b.*?\bcherry-pick\b",
            "git cherry-pick can introduce duplicate commits. Review carefully.",
            executables = ["git", "git-cherry-pick"]
        ),
        // Block filter-branch (rewrites entire history)
        destructive_pattern!(
            "filter-branch",
            r"git\b.*?\bfilter-branch\b",
            "git filter-branch rewrites entire repository history. Extremely dangerous!",
            executables = ["git", "git-filter-branch"]
        ),
        // Block filter-repo (modern replacement for filter-branch)
        destructive_pattern!(
            "filter-repo",
            r"git\b.*?\bfilter-repo\b",
            "git filter-repo rewrites repository history. Review carefully.",
            executables = ["git", "git-filter-repo"]
        ),
        // Block reflog expire (can lose recovery points)
        destructive_pattern!(
            "reflog-expire",
            r"git\b.*?\breflog\s+expire",
            "git reflog expire removes reflog entries needed for recovery.",
            executables = ["git", "git-reflog"]
        ),
        // Block gc with aggressive options
        destructive_pattern!(
            "gc-aggressive",
            r"git\b.*?\bgc\s+.*--(?:aggressive|prune)",
            "git gc with aggressive/prune options can remove recoverable objects.",
            executables = ["git", "git-gc"]
        ),
        // Block worktree remove
        destructive_pattern!(
            "worktree-remove",
            r"git\b.*?\bworktree\s+remove",
            "git worktree remove deletes a linked working tree.",
            executables = ["git", "git-worktree"]
        ),
        // Block submodule deinit
        destructive_pattern!(
            "submodule-deinit",
            r"git\b.*?\bsubmodule\s+deinit",
            "git submodule deinit removes submodule configuration.",
            executables = ["git", "git-submodule"]
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
            "git add . stages everything including secrets, .env files, and build artifacts. Use 'git add <specific-files>' instead.",
            executables = ["git", "git-add"]
        ),
        // Block git add -A / git add --all (same concern as git add .)
        destructive_pattern!(
            "add-all-flag",
            r"git\b.*?\badd\s+(?:-A|--all)\b",
            "git add -A/--all stages all changes including secrets, .env files, and build artifacts. Use 'git add <specific-files>' instead.",
            executables = ["git", "git-add"]
        ),
        // Block push to master. Separators include `/` so explicit refspecs
        // like `HEAD:refs/heads/master` are caught — `main` appearing after
        // `/` in `refs/heads/main` used to bypass the old `[\s:]` separator.
        destructive_pattern!(
            "push-master",
            r"git(?:\s+(?:\S+\s+)*push|-push)\s+(?:.*[\s:/])?\+?master(?:\s|$)",
            "Direct push to master is blocked. Use a feature branch and open a Pull Request.",
            executables = ["git", "git-push"]
        ),
        // Block push to main
        destructive_pattern!(
            "push-main",
            r"git(?:\s+(?:\S+\s+)*push|-push)\s+(?:.*[\s:/])?\+?main(?:\s|$)",
            "Direct push to main is blocked. Use a feature branch and open a Pull Request.",
            executables = ["git", "git-push"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    /// Every strict_git rule is about the `git` executable, and each one
    /// declares that scope (issue #362). A raw `git\b.*?\brebase\b` regex used
    /// to match commands that merely *mention* git-flavored paths — most
    /// commonly `.git/rebase-merge` / `.git/rebase-apply` state directories
    /// passed to `ls`, `cat`, or `stat` while inspecting a repository.
    #[test]
    fn non_git_commands_naming_git_state_paths_do_not_match_362() {
        let pack = create_pack();
        for command in [
            // The reported shape: checking rebase/merge state with ls.
            "ls .git/MERGE_HEAD .git/rebase-merge .git/rebase-apply .git/index.lock",
            "ls -la .git/rebase-merge",
            "cat .git/rebase-apply/head-name",
            "stat .git/MERGE_HEAD .git/rebase-merge",
            "test -d .git/rebase-merge",
            // Prose and other executables that mention the verbs.
            "echo git rebase is disabled here",
            "grep -r 'git push --force' docs/",
            "rg 'git filter-branch' CHANGELOG.md",
        ] {
            assert_no_match(&pack, command);
        }
    }

    /// Executable scoping must not loosen the deny side: everything the pack
    /// blocked before #362 is still a `git` invocation and still blocks.
    #[test]
    fn scoping_keeps_git_invocations_blocked_362() {
        let pack = create_pack();
        assert_blocks(&pack, "git rebase -i HEAD~3", "rebase");
        assert_blocks(&pack, "git push --force origin main", "Force push");
        assert_blocks(&pack, "git add .", "stages everything");
        assert_blocks(&pack, "/usr/bin/git rebase main", "rebase");
        assert_blocks(&pack, "cd repo && git rebase main", "rebase");
    }

    /// Dashed-builtin spellings resolve argv0 to `git-<sub>`, not `git`, so
    /// the #362 `executables = ["git"]` scoping silently narrowed the pack:
    /// `git-rebase` / `git-push --force` passed strict_git entirely (#367).
    /// Every rule now also declares its dashed spelling, restoring the
    /// pre-#362 coverage without reopening the `ls .git/rebase-merge` FP.
    #[test]
    fn dashed_builtin_spellings_still_match_367() {
        let pack = create_pack();
        assert_blocks(&pack, "git-rebase -i HEAD~3", "rebase");
        assert_blocks(&pack, "git-push --force origin topic", "Force push");
        assert_blocks(&pack, "git-push origin --mirror", "--mirror");
        assert_blocks(&pack, "git-push origin +topic:topic", "Force push");
        assert_blocks(&pack, "git-push origin main", "Direct push to main");
        assert_blocks(&pack, "git-push origin master", "Direct push to master");
        assert_blocks(
            &pack,
            "git-push origin HEAD:refs/heads/main",
            "Direct push to main",
        );
        assert_blocks(&pack, "git-commit --amend", "rewrites the last commit");
        assert_blocks(&pack, "git-cherry-pick abc123", "duplicate commits");
        assert_blocks(
            &pack,
            "git-filter-branch --tree-filter 'rm -f secret' HEAD",
            "filter-branch",
        );
        assert_blocks(
            &pack,
            "git-filter-repo --path secret --invert-paths",
            "history",
        );
        assert_blocks(&pack, "git-reflog expire --all", "reflog");
        assert_blocks(
            &pack,
            "git-gc --aggressive --prune=now",
            "recoverable objects",
        );
        assert_blocks(&pack, "git-worktree remove dead", "worktree");
        assert_blocks(&pack, "git-submodule deinit lib", "submodule");
        assert_blocks(&pack, "git-add .", "stages everything");
        assert_blocks(&pack, "git-add -A", "stages all changes");
        // Path-qualified dashed spelling (git's own exec dir layout).
        assert_blocks(&pack, "/usr/libexec/git-core/git-rebase main", "rebase");
        // Chained: the governed segment still blocks.
        assert_blocks(&pack, "cd repo && git-rebase main", "rebase");
    }

    /// The dashed extension must not reopen what #362 closed: commands that
    /// merely mention git-flavored text but whose argv0 is neither `git` nor
    /// a dashed builtin stay unmatched, and ordinary dashed pushes to a
    /// feature branch remain allowed.
    #[test]
    fn dashed_builtin_scoping_stays_narrow_367() {
        let pack = create_pack();
        assert_no_match(&pack, "ls .git/rebase-merge");
        assert_no_match(&pack, "cat .git/rebase-apply/head-name");
        assert_no_match(&pack, "echo git-rebase is disabled here");
        assert_no_match(&pack, "grep -r 'git-push --force' docs/");
        assert_allows(&pack, "git-push origin feature-topic");
    }

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

    #[test]
    fn test_push_force_refspec_prefix() {
        let pack = create_pack();

        for command in [
            "git push origin +main",
            "git push origin +master",
            "git push origin +HEAD:main",
            "git push origin +HEAD:master",
            "git push origin +refs/heads/main",
            "git push origin +refs/heads/master",
            "git push origin +feature",
            "git -C /repo push origin +topic:topic",
            "git push origin '+topic:topic'",
            r"git push origin \+topic:topic",
            "git push origin ''+topic:topic",
            r#"git push origin "+"topic:topic"#,
            "git push origin $'+topic:topic'",
            r"git push origin $'\x2btopic:topic'",
            r"git push origin $'\053topic:topic'",
            r#"git push origin "$(printf '\x2btopic:topic')""#,
            r"git push origin $(printf '\053topic:topic')",
            r#"git push origin "$REFSPEC""#,
            r"git push origin ${PREFIX}topic:topic",
            "git push origin {+,}topic:topic",
            "git push origin *topic:topic",
            "git push origin [+-]topic:topic",
        ] {
            assert_blocks(&pack, command, "Force push");
        }

        assert_blocks(&pack, "git push --mirror origin", "--mirror");
        assert_blocks(&pack, "git -C /repo push origin --mirror", "--mirror");

        for command in [
            "git push origin feature-main",
            "git push origin main-fix",
            "git push origin feature+main",
            "git push origin +",
            "git push origin topic:topic --push-option=--force",
        ] {
            assert_allows(&pack, command);
        }
    }
}

//! GitHub Platform pack - protections for destructive GitHub CLI (`gh`) operations.
//!
//! This pack targets high-impact operations when managing GitHub repositories,
//! gists, releases, and other platform resources:
//! - Deleting repositories
//! - Archiving repositories
//! - Deleting gists
//! - Deleting releases
//! - Deleting issues
//! - Deleting SSH keys

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitHub Platform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.github".to_string(),
        name: "GitHub Platform",
        description: "Protects against destructive GitHub CLI operations like deleting repositories, gists, releases, or SSH keys.",
        // Broad on purpose: global `gh` flags can appear before the subcommand.
        keywords: &["gh"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Regex logic:
    // Match `gh`
    // Match optional global flags: `--flag` or `--flag value`
    // Ensure the flag value isn't one of our target subcommands (repo, gist, etc.)
    // Match the target subcommand and action

    // Subcommands to look ahead for: repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api
    // We use a robust value matcher that handles quoted strings to prevent bypasses.

    vec![
        safe_pattern!(
            "gh-repo-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+repo\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-gist-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+gist\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-release-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+release\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-issue-list-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+issue\s+(?:list|view)\b"
        ),
        safe_pattern!(
            "gh-ssh-key-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+ssh-key\s+list\b"
        ),
        safe_pattern!(
            "gh-secret-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+secret\s+list\b"
        ),
        safe_pattern!(
            "gh-variable-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+variable\s+list\b"
        ),
        safe_pattern!(
            "gh-auth-status",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+auth\s+status\b"
        ),
        safe_pattern!(
            "gh-status",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+status\b"
        ),
        // Safe API GETs
        safe_pattern!(
            "gh-api-explicit-get",
            r"^(?!(?=.*(?:-X\s*|--method(?:=|\s+))DELETE\b))gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))GET\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "gh-repo-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+repo\s+delete\b",
            "gh repo delete permanently deletes a GitHub repository. This cannot be undone."
        ),
        destructive_pattern!(
            "gh-repo-archive",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+repo\s+archive\b",
            "gh repo archive makes a repository read-only. While reversible, it stops all write access."
        ),
        destructive_pattern!(
            "gh-gist-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+gist\s+delete\b",
            "gh gist delete permanently deletes a Gist."
        ),
        destructive_pattern!(
            "gh-release-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+release\s+delete\b",
            "gh release delete permanently deletes a release."
        ),
        destructive_pattern!(
            "gh-issue-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+issue\s+delete\b",
            "gh issue delete permanently deletes an issue."
        ),
        destructive_pattern!(
            "gh-ssh-key-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+ssh-key\s+delete\b",
            "gh ssh-key delete removes an SSH key, potentially breaking access."
        ),
        destructive_pattern!(
            "gh-secret-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+secret\s+(?:delete|remove)\b",
            "gh secret delete removes GitHub Actions secrets."
        ),
        destructive_pattern!(
            "gh-variable-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+variable\s+(?:delete|remove)\b",
            "gh variable delete removes GitHub Actions variables."
        ),
        destructive_pattern!(
            "gh-repo-deploy-key-delete",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+repo\s+deploy-key\s+delete\b",
            "gh repo deploy-key delete removes a deploy key and can break access."
        ),
        destructive_pattern!(
            "gh-run-cancel",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+run\s+cancel\b",
            "gh run cancel stops a workflow run and may interrupt deployments."
        ),
        destructive_pattern!(
            "gh-api-delete-actions-secret",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/actions/secrets/",
            "gh api DELETE actions/secrets removes GitHub Actions secrets."
        ),
        destructive_pattern!(
            "gh-api-delete-actions-variable",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/actions/variables/",
            "gh api DELETE actions/variables removes GitHub Actions variables."
        ),
        destructive_pattern!(
            "gh-api-delete-hook",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/hooks/",
            "gh api DELETE hooks removes repository webhooks."
        ),
        destructive_pattern!(
            "gh-api-delete-deploy-key",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/keys/",
            "gh api DELETE keys removes deploy keys."
        ),
        destructive_pattern!(
            "gh-api-delete-release",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:/)?repos/[^/\s]+/[^/\s]+/releases/",
            "gh api DELETE releases removes GitHub releases."
        ),
        // API Deletes
        // DELETE /repos/{owner}/{repo} -> Delete a repository
        destructive_pattern!(
            "gh-api-delete-repo",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:\x22[^\x22]*\x22)|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b",
            "gh api DELETE calls can be destructive. Please verify the endpoint."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn allows_safe_variants() {
        let pack = create_pack();
        assert!(pack.check("gh repo list").is_none());
        assert!(pack.check("gh repo view").is_none());
        assert!(pack.check("gh gist list").is_none());
        assert!(pack.check("gh release view v1.0").is_none());
        assert!(pack.check("gh issue list").is_none());
        assert!(pack.check("gh ssh-key list").is_none());
        assert!(pack.check("gh secret list").is_none());
        assert!(pack.check("gh variable list").is_none());
        assert!(pack.check("gh auth status").is_none());
        assert!(pack.check("gh status").is_none());

        // With global flags
        assert!(pack.check("gh -R owner/repo repo view").is_none());
        assert!(pack.check("gh -R owner/repo secret list").is_none());
    }

    #[test]
    fn blocks_destructive_variants() {
        let mut pack = create_pack();
        // Manually inject keywords for testing if needed
        pack.keywords = &["gh"];

        let checks = vec![
            ("gh repo delete owner/repo", "gh-repo-delete"),
            ("gh -R owner/repo repo delete", "gh-repo-delete"),
            ("gh repo archive owner/repo", "gh-repo-archive"),
            ("gh gist delete 123", "gh-gist-delete"),
            ("gh release delete v1.0", "gh-release-delete"),
            ("gh issue delete 1", "gh-issue-delete"),
            ("gh ssh-key delete 1", "gh-ssh-key-delete"),
            ("gh secret delete SECRET_NAME", "gh-secret-delete"),
            ("gh secret remove SECRET_NAME", "gh-secret-delete"),
            ("gh variable delete VAR_NAME", "gh-variable-delete"),
            ("gh variable remove VAR_NAME", "gh-variable-delete"),
            ("gh repo deploy-key delete 123", "gh-repo-deploy-key-delete"),
            ("gh run cancel 123456", "gh-run-cancel"),
            (
                "gh api -X DELETE /repos/owner/repo/actions/secrets/SECRET",
                "gh-api-delete-actions-secret",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/actions/variables/VAR",
                "gh-api-delete-actions-variable",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/hooks/123",
                "gh-api-delete-hook",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/keys/456",
                "gh-api-delete-deploy-key",
            ),
            (
                "gh api -X DELETE /repos/owner/repo/releases/1",
                "gh-api-delete-release",
            ),
            ("gh api -X DELETE /repos/owner/repo", "gh-api-delete-repo"),
        ];

        for (cmd, expected_rule) in checks {
            let matched = pack
                .check(cmd)
                .unwrap_or_else(|| panic!("Should block: {cmd}"));
            assert_eq!(matched.name, Some(expected_rule), "Command: {cmd}");
        }
    }

    #[test]
    fn github_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "gh repo delete owner/repo", "gh-repo-delete");
        assert_blocks_with_pattern(&pack, "gh repo archive owner/repo", "gh-repo-archive");
        assert_blocks_with_pattern(&pack, "gh gist delete 123", "gh-gist-delete");
        assert_blocks_with_pattern(&pack, "gh release delete v1.0", "gh-release-delete");
        assert_blocks_with_pattern(&pack, "gh issue delete 1", "gh-issue-delete");
        assert_blocks_with_pattern(&pack, "gh ssh-key delete 1", "gh-ssh-key-delete");
        assert_blocks_with_pattern(&pack, "gh secret delete SECRET_NAME", "gh-secret-delete");
        assert_blocks_with_pattern(&pack, "gh variable delete VAR_NAME", "gh-variable-delete");
        assert_blocks_with_pattern(
            &pack,
            "gh repo deploy-key delete 123",
            "gh-repo-deploy-key-delete",
        );
        assert_blocks_with_pattern(&pack, "gh run cancel 123456", "gh-run-cancel");
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/actions/secrets/SECRET",
            "gh-api-delete-actions-secret",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/actions/variables/VAR",
            "gh-api-delete-actions-variable",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/hooks/123",
            "gh-api-delete-hook",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/keys/456",
            "gh-api-delete-deploy-key",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo/releases/1",
            "gh-api-delete-release",
        );
        assert_blocks_with_pattern(
            &pack,
            "gh api -X DELETE /repos/owner/repo",
            "gh-api-delete-repo",
        );
    }

    #[test]
    fn github_blocks_with_correct_severity() {
        let pack = create_pack();
        // All github destructive patterns use default severity (High)
        assert_blocks_with_severity(&pack, "gh repo delete owner/repo", Severity::High);
        assert_blocks_with_severity(&pack, "gh repo archive owner/repo", Severity::High);
        assert_blocks_with_severity(&pack, "gh gist delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "gh release delete v1.0", Severity::High);
        assert_blocks_with_severity(&pack, "gh issue delete 1", Severity::High);
        assert_blocks_with_severity(&pack, "gh ssh-key delete 1", Severity::High);
        assert_blocks_with_severity(&pack, "gh secret delete SECRET_NAME", Severity::High);
        assert_blocks_with_severity(&pack, "gh variable delete VAR_NAME", Severity::High);
        assert_blocks_with_severity(&pack, "gh repo deploy-key delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "gh run cancel 123456", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gh api -XDELETE /repos/owner/repo/actions/secrets/SECRET",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "gh api --method=DELETE /repos/owner/repo",
            Severity::High,
        );
    }

    #[test]
    fn github_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "gh repo list");
        assert_safe_pattern_matches(&pack, "gh repo view");
        assert_safe_pattern_matches(&pack, "gh gist list");
        assert_safe_pattern_matches(&pack, "gh gist view abc123");
        assert_safe_pattern_matches(&pack, "gh release list");
        assert_safe_pattern_matches(&pack, "gh release view v1.0");
        assert_safe_pattern_matches(&pack, "gh issue list");
        assert_safe_pattern_matches(&pack, "gh issue view 42");
        assert_safe_pattern_matches(&pack, "gh ssh-key list");
        assert_safe_pattern_matches(&pack, "gh secret list");
        assert_safe_pattern_matches(&pack, "gh variable list");
        assert_safe_pattern_matches(&pack, "gh auth status");
        assert_safe_pattern_matches(&pack, "gh status");
        assert_safe_pattern_matches(&pack, "gh api -X GET /repos/owner/repo");
    }

    #[test]
    fn gh_api_get_safe_pattern_does_not_mask_delete_methods() {
        let pack = create_pack();
        let command = "gh api -X GET /repos/owner/repo/actions/secrets \
            -XDELETE /repos/owner/repo/actions/secrets/SECRET";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "gh-api-delete-actions-secret");
    }

    #[test]
    fn github_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

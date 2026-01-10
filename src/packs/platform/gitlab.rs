//! GitLab Platform pack - protections for destructive GitLab platform operations.
//!
//! This pack focuses on non-CI GitLab operations like deleting projects,
//! archiving repositories, removing protected branches, and deleting webhooks.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitLab Platform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "platform.gitlab".to_string(),
        name: "GitLab Platform",
        description: "Protects against destructive GitLab platform operations like deleting projects, \
                      releases, protected branches, and webhooks.",
        keywords: &["glab", "gitlab-rails", "gitlab-rake"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "glab-repo-list",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+list\b"
        ),
        safe_pattern!(
            "glab-repo-view",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+view\b"
        ),
        safe_pattern!(
            "glab-repo-clone",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+clone\b"
        ),
        safe_pattern!(
            "glab-mr-list",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+mr\s+list\b"
        ),
        safe_pattern!(
            "glab-mr-view",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+mr\s+view\b"
        ),
        safe_pattern!(
            "glab-issue-list",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+issue\s+list\b"
        ),
        safe_pattern!(
            "glab-issue-view",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+issue\s+view\b"
        ),
        safe_pattern!(
            "glab-release-list",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+list\b"
        ),
        safe_pattern!(
            "glab-release-view",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+view\b"
        ),
        safe_pattern!(
            "glab-api-explicit-get",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+GET\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "glab-repo-delete",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+delete\b",
            "glab repo delete permanently deletes a GitLab project."
        ),
        destructive_pattern!(
            "glab-repo-archive",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+archive\b",
            "glab repo archive makes a GitLab project read-only."
        ),
        destructive_pattern!(
            "glab-release-delete",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+delete\b",
            "glab release delete removes GitLab releases."
        ),
        destructive_pattern!(
            "glab-api-delete-project",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*(?:/)?projects/[^/\s]+(?:\s|$)",
            "glab api DELETE /projects/* deletes a GitLab project."
        ),
        destructive_pattern!(
            "glab-api-delete-protected-branch",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*(?:/)?protected_branches/",
            "glab api DELETE protected_branches removes branch protections."
        ),
        destructive_pattern!(
            "glab-api-delete-hook",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*(?:/)?hooks/",
            "glab api DELETE hooks removes GitLab webhooks."
        ),
        destructive_pattern!(
            "gitlab-rails-runner-destructive",
            r"gitlab-rails\s+runner\b.*\b(?:destroy_all|delete_all|\.destroy\b|\.delete\b|truncate|drop)\b",
            "gitlab-rails runner destructive operations can remove data."
        ),
        destructive_pattern!(
            "gitlab-rake-destructive",
            r"gitlab-rake\b.*\b(?:gitlab:)?backup:restore\b|gitlab-rake\b.*\b(?:gitlab:)?db:(?:drop|reset)\b",
            "gitlab-rake destructive maintenance tasks can delete or replace data."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "platform.gitlab");
        assert_eq!(pack.name, "GitLab Platform");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"glab"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_repo_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "glab repo delete my/group", "glab-repo-delete");
    }

    #[test]
    fn test_repo_archive_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "glab repo archive my/group", "glab-repo-archive");
    }

    #[test]
    fn test_release_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "glab release delete v1.2.3", "glab-release-delete");
    }

    #[test]
    fn test_api_delete_project_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "glab api -X DELETE projects/123",
            "glab-api-delete-project",
        );
    }

    #[test]
    fn test_api_delete_protected_branch_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "glab api --method DELETE /projects/123/protected_branches/main",
            "glab-api-delete-protected-branch",
        );
    }

    #[test]
    fn test_api_delete_hook_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "glab api -X DELETE /projects/123/hooks/456",
            "glab-api-delete-hook",
        );
    }

    #[test]
    fn test_gitlab_rails_runner_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gitlab-rails runner \"Project.destroy_all\"",
            "gitlab-rails-runner-destructive",
        );
    }

    #[test]
    fn test_gitlab_rake_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gitlab-rake gitlab:backup:restore",
            "gitlab-rake-destructive",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "glab repo list");
        assert_allows(&pack, "glab repo view my/group");
        assert_allows(&pack, "glab repo clone my/group");
        assert_allows(&pack, "glab mr list");
        assert_allows(&pack, "glab mr view 123");
        assert_allows(&pack, "glab issue list");
        assert_allows(&pack, "glab issue view 456");
        assert_allows(&pack, "glab release list");
        assert_allows(&pack, "glab release view v1.2.3");
        assert_allows(&pack, "glab api -X GET projects/123");
    }
}

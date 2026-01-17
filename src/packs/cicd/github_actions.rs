//! GitHub Actions pack - protections for destructive GitHub Actions operations via `gh`.
//!
//! This pack targets high-impact operations when managing GitHub Actions workflows,
//! secrets, and variables:
//! - Deleting secrets / variables
//! - Disabling workflows
//! - Canceling runs
//! - `gh api` DELETE calls against `/actions/*` endpoints

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitHub Actions pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cicd.github_actions".to_string(),
        name: "GitHub Actions",
        description: "Protects against destructive GitHub Actions operations like deleting secrets/variables \
             or using gh api DELETE against /actions endpoints.",
        // Broad on purpose: global `gh` flags can appear before the subcommand.
        keywords: &["gh"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "gh-actions-secret-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+secret\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-variable-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+variable\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-workflow-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-workflow-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+view\b"
        ),
        safe_pattern!(
            "gh-actions-run-list",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+list\b"
        ),
        safe_pattern!(
            "gh-actions-run-view",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+view\b"
        ),
        // Safe only when GET is explicit (default method can vary by flags).
        safe_pattern!(
            "gh-actions-api-explicit-get",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b.*(?:-X|--method)\s+GET\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "gh-actions-secret-remove",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+secret\s+(?:delete|remove)\b",
            "gh secret delete/remove deletes GitHub Actions secrets. This can break CI and may be hard to recover."
        ),
        destructive_pattern!(
            "gh-actions-variable-remove",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+variable\s+(?:delete|remove)\b",
            "gh variable delete/remove deletes GitHub Actions variables. This can break workflows."
        ),
        destructive_pattern!(
            "gh-actions-workflow-disable",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+disable\b",
            "gh workflow disable disables workflows. This is reversible, but can disrupt CI."
        ),
        destructive_pattern!(
            "gh-actions-run-cancel",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+cancel\b",
            "gh run cancel cancels a running workflow. This is reversible, but may disrupt deployments."
        ),
        destructive_pattern!(
            "gh-actions-api-delete-secrets",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*\b/?repos/[^\s/]+/[^\s/]+/actions/secrets\b",
            "gh api DELETE against /actions/secrets deletes GitHub Actions secrets."
        ),
        destructive_pattern!(
            "gh-actions-api-delete-variables",
            r"gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*\b/?repos/[^\s/]+/[^\s/]+/actions/variables\b",
            "gh api DELETE against /actions/variables deletes GitHub Actions variables."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_safe_list_variants() {
        let pack = create_pack();
        assert!(pack.check("gh secret list").is_none());
        assert!(pack.check("gh variable list").is_none());
        assert!(pack.check("gh workflow list").is_none());
        assert!(pack.check("gh run list").is_none());
    }

    #[test]
    fn blocks_secret_and_variable_removal() {
        let pack = create_pack();

        let matched = pack
            .check("gh secret delete FOO")
            .expect("secret delete should be detected");
        assert_eq!(matched.name, Some("gh-actions-secret-remove"));

        let matched = pack
            .check("gh -R owner/repo secret remove FOO")
            .expect("secret remove with global flags should be detected");
        assert_eq!(matched.name, Some("gh-actions-secret-remove"));

        let matched = pack
            .check("gh variable delete FOO")
            .expect("variable delete should be detected");
        assert_eq!(matched.name, Some("gh-actions-variable-remove"));
    }

    #[test]
    fn blocks_workflow_disable_and_run_cancel() {
        let pack = create_pack();

        let matched = pack
            .check("gh workflow disable 123")
            .expect("workflow disable should be detected");
        assert_eq!(matched.name, Some("gh-actions-workflow-disable"));

        let matched = pack
            .check("gh run cancel 123")
            .expect("run cancel should be detected");
        assert_eq!(matched.name, Some("gh-actions-run-cancel"));
    }

    #[test]
    fn detects_gh_api_delete_against_actions_endpoints() {
        let pack = create_pack();

        let matched = pack
            .check("gh api -X DELETE repos/o/r/actions/secrets/FOO")
            .expect("gh api DELETE secrets should be detected");
        assert_eq!(matched.name, Some("gh-actions-api-delete-secrets"));

        let matched = pack
            .check("gh api --method DELETE /repos/o/r/actions/variables/FOO")
            .expect("gh api DELETE variables should be detected");
        assert_eq!(matched.name, Some("gh-actions-api-delete-variables"));
    }
}

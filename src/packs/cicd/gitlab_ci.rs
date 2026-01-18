//! `GitLab` CI pack - protections for destructive GitLab CI/CD operations.
//!
//! Blocks variable deletion, pipeline artifact deletion, and runner unregistration.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the GitLab CI pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cicd.gitlab_ci".to_string(),
        name: "GitLab CI",
        description: "Protects against destructive GitLab CI/CD operations like deleting variables, \
                      removing artifacts, and unregistering runners.",
        keywords: &["glab", "gitlab-runner"],
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
            "glab-variable-list",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+list\b"
        ),
        safe_pattern!(
            "glab-ci-list",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+list\b"
        ),
        safe_pattern!(
            "glab-ci-view",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+view\b"
        ),
        safe_pattern!(
            "glab-ci-status",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+status\b"
        ),
        safe_pattern!(
            "gitlab-runner-list",
            r"gitlab-runner(?:\s+--?\S+(?:\s+\S+)?)*\s+list\b"
        ),
        safe_pattern!(
            "gitlab-runner-status",
            r"gitlab-runner(?:\s+--?\S+(?:\s+\S+)?)*\s+status\b"
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
            "glab-variable-delete",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+delete\b",
            "glab variable delete removes CI variables and can break pipelines.",
            High,
            "Deleting a GitLab CI/CD variable removes it from the project, group, or instance. \
             Pipelines that depend on this variable will fail with undefined variable errors. \
             Protected or masked variable values cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - glab variable list: Review existing variables first\n\
             - Update variable value instead of deleting\n\
             - Check .gitlab-ci.yml for variable usage before removing"
        ),
        destructive_pattern!(
            "glab-ci-delete",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+delete\b",
            "glab ci delete removes pipeline artifacts or pipelines.",
            Medium,
            "Deleting pipelines or artifacts removes build history, job logs, and generated \
             files. This affects debugging capabilities and audit trails. Artifacts needed \
             for deployments or releases will no longer be available.\n\n\
             Safer alternatives:\n\
             - glab ci list: Review pipelines before deletion\n\
             - glab ci view: Inspect pipeline details\n\
             - Download artifacts before deletion if needed"
        ),
        destructive_pattern!(
            "glab-api-delete-variables",
            r"glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X|--method)\s+DELETE\b.*\bvariables\b",
            "glab api DELETE against variables endpoints removes CI variables.",
            High,
            "Making DELETE requests to GitLab variables API removes CI/CD variables directly. \
             This bypasses CLI confirmations and immediately affects all pipelines using these \
             variables. Protected variable values cannot be recovered.\n\n\
             Safer alternatives:\n\
             - Use glab variable delete for safer deletion\n\
             - GET request first: Verify variable exists\n\
             - Prefer CLI commands over direct API calls"
        ),
        destructive_pattern!(
            "gitlab-runner-unregister",
            r"gitlab-runner(?:\s+--?\S+(?:\s+\S+)?)*\s+unregister\b",
            "gitlab-runner unregister removes runners and can halt CI.",
            Critical,
            "Unregistering a GitLab runner removes it from the GitLab instance. Jobs assigned \
             to this runner will be stuck pending or fail. With --all-runners, all runners \
             on the machine are removed, potentially halting all CI/CD for multiple projects.\n\n\
             Safer alternatives:\n\
             - gitlab-runner list: Review registered runners first\n\
             - Pause the runner in GitLab UI instead\n\
             - Verify replacement runners are available before removing"
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
        assert_eq!(pack.id, "cicd.gitlab_ci");
        assert_eq!(pack.name, "GitLab CI");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"glab"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_variable_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "glab variable delete CI_TOKEN",
            "glab-variable-delete",
        );
    }

    #[test]
    fn test_ci_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "glab ci delete 123", "glab-ci-delete");
    }

    #[test]
    fn test_api_delete_variables_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "glab api -X DELETE projects/1/variables/FOO",
            "glab-api-delete-variables",
        );
    }

    #[test]
    fn test_runner_unregister_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "gitlab-runner unregister --all-runners",
            "gitlab-runner-unregister",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "glab variable list");
        assert_allows(&pack, "glab ci list");
        assert_allows(&pack, "glab ci view 123");
        assert_allows(&pack, "glab ci status");
        assert_allows(&pack, "gitlab-runner list");
        assert_allows(&pack, "gitlab-runner status");
    }
}

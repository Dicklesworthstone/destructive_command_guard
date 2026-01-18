//! `CircleCI` pack - protections for destructive `CircleCI` CLI/API operations.
//!
//! This pack targets high-impact `CircleCI` operations like deleting contexts,
//! removing context secrets, deleting orbs/namespaces, and removing pipelines.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `CircleCI` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cicd.circleci".to_string(),
        name: "CircleCI",
        description: "Protects against destructive CircleCI operations like deleting contexts, \
                      removing secrets, deleting orbs/namespaces, or removing pipelines.",
        keywords: &["circleci"],
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
            "circleci-context-list",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+context\s+list\b"
        ),
        safe_pattern!(
            "circleci-orb-list",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+orb\s+list\b"
        ),
        safe_pattern!(
            "circleci-orb-info",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+orb\s+info\b"
        ),
        safe_pattern!(
            "circleci-pipeline-list",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+pipeline\s+list\b"
        ),
        safe_pattern!(
            "circleci-project-list",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+list\b"
        ),
        safe_pattern!(
            "circleci-namespace-list",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+list\b"
        ),
        safe_pattern!(
            "circleci-config-validate",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+config\s+validate\b"
        ),
        safe_pattern!(
            "circleci-local-execute",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+local\s+execute\b"
        ),
        safe_pattern!(
            "circleci-policy-status",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+status\b"
        ),
        safe_pattern!(
            "circleci-diagnostic",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+diagnostic\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "circleci-context-delete",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+context\s+delete\b",
            "circleci context delete removes contexts and their secrets.",
            Critical,
            "Deleting a CircleCI context removes all secrets stored within it. Any pipeline \
             jobs that reference this context will fail immediately. Secret values cannot be \
             recovered after deletion and must be manually re-entered.\n\n\
             Safer alternatives:\n\
             - circleci context list: Review contexts before deletion\n\
             - circleci context show: Inspect context secrets (names only)\n\
             - Document secret names before removing context"
        ),
        destructive_pattern!(
            "circleci-context-remove-secret",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+context\s+remove-secret\b",
            "circleci context remove-secret deletes secrets from a context.",
            High,
            "Removing a secret from a context makes it unavailable to all jobs using that \
             context. Pipelines depending on this secret will fail. The secret value cannot \
             be retrieved after removal.\n\n\
             Safer alternatives:\n\
             - circleci context show: Review secrets in context first\n\
             - Update the secret value instead of removing\n\
             - Document secret value externally before removal"
        ),
        destructive_pattern!(
            "circleci-orb-delete",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+orb\s+delete\b",
            "circleci orb delete removes an orb from the registry.",
            High,
            "Deleting an orb removes it from the CircleCI orb registry. Any pipeline using \
             this orb will fail on the next run. If other teams or projects depend on this \
             orb, their CI/CD will break without warning.\n\n\
             Safer alternatives:\n\
             - circleci orb info: Review orb details and usage\n\
             - Deprecate the orb instead of deleting\n\
             - Check for dependent projects before deletion"
        ),
        destructive_pattern!(
            "circleci-namespace-delete",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+delete\b",
            "circleci namespace delete removes an orb namespace.",
            Critical,
            "Deleting a namespace removes all orbs within that namespace from the registry. \
             This is a cascading deletion that affects every orb published under this namespace. \
             All pipelines using any orb from this namespace will fail.\n\n\
             Safer alternatives:\n\
             - circleci namespace list: Review namespaces first\n\
             - circleci orb list: Inventory orbs in namespace\n\
             - Delete individual orbs instead if needed"
        ),
        destructive_pattern!(
            "circleci-pipeline-delete",
            r"circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+pipeline\s+delete\b",
            "circleci pipeline delete removes pipeline history.",
            Medium,
            "Deleting pipeline history removes records of past builds, including logs, artifacts, \
             and test results. This affects audit trails and debugging capabilities. The history \
             cannot be recovered once deleted.\n\n\
             Safer alternatives:\n\
             - circleci pipeline list: Review pipelines before deletion\n\
             - Export logs and artifacts before deletion\n\
             - Consider archiving rather than deleting"
        ),
        destructive_pattern!(
            "circleci-api-delete-envvar",
            r"curl(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-X|--request)\s+DELETE\b.*circleci\.com/api/[^\s]*\b(?:envvar|environment-variable)\b",
            "curl DELETE against CircleCI envvar endpoints removes environment variables.",
            High,
            "Making DELETE requests to CircleCI environment variable endpoints removes variables \
             from projects. Pipelines depending on these variables will fail on next run. \
             Variable values cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - GET request first: Review variable exists\n\
             - Update variable value instead of deleting\n\
             - Use circleci CLI for safer operations"
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
        assert_eq!(pack.id, "cicd.circleci");
        assert_eq!(pack.name, "CircleCI");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"circleci"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_context_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "circleci context delete org/my-org context/prod",
            "circleci-context-delete",
        );
    }

    #[test]
    fn test_context_remove_secret_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "circleci context remove-secret org/my-org context/prod AWS_ACCESS_KEY_ID",
            "circleci-context-remove-secret",
        );
    }

    #[test]
    fn test_orb_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "circleci orb delete my-org/my-orb",
            "circleci-orb-delete",
        );
    }

    #[test]
    fn test_namespace_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "circleci namespace delete my-org",
            "circleci-namespace-delete",
        );
    }

    #[test]
    fn test_pipeline_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "circleci pipeline delete 123456",
            "circleci-pipeline-delete",
        );
    }

    #[test]
    fn test_api_delete_envvar_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://circleci.com/api/v2/project/gh/org/repo/envvar/FOO",
            "circleci-api-delete-envvar",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "circleci context list org/my-org");
        assert_allows(&pack, "circleci orb list org/my-org");
        assert_allows(&pack, "circleci orb info my-org/my-orb");
        assert_allows(&pack, "circleci pipeline list org/my-org/project/app");
        assert_allows(&pack, "circleci project list");
        assert_allows(&pack, "circleci namespace list");
        assert_allows(&pack, "circleci config validate .circleci/config.yml");
        assert_allows(&pack, "circleci local execute");
        assert_allows(&pack, "circleci policy status");
        assert_allows(&pack, "circleci diagnostic");
    }
}

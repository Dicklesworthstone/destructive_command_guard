//! `New Relic` monitoring pack - protections for destructive `New Relic` operations.
//!
//! Covers destructive CLI/API operations:
//! - `newrelic ... delete` for entities, APM applications, workloads, and synthetics
//! - `curl -X DELETE` to `api.newrelic.com`
//! - GraphQL mutations containing delete operations (best-effort)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `New Relic` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "monitoring.newrelic".to_string(),
        name: "New Relic",
        description: "Protects against destructive New Relic CLI/API operations like deleting entities \
                      or alerting resources.",
        keywords: &["newrelic", "api.newrelic.com", "graphql"],
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
            "newrelic-entity-search",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+entity\s+search\b"
        ),
        safe_pattern!(
            "newrelic-apm-app-get",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+apm\s+application\s+get\b"
        ),
        safe_pattern!(
            "newrelic-query",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+query\b"
        ),
        safe_pattern!(
            "newrelic-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*api\.newrelic\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "newrelic-entity-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+entity\s+delete\b",
            "newrelic entity delete removes a New Relic entity, impacting observability."
        ),
        destructive_pattern!(
            "newrelic-apm-app-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+apm\s+application\s+delete\b",
            "newrelic apm application delete removes an APM application."
        ),
        destructive_pattern!(
            "newrelic-workload-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+workload\s+delete\b",
            "newrelic workload delete removes a workload definition."
        ),
        destructive_pattern!(
            "newrelic-synthetics-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+synthetics\s+delete\b",
            "newrelic synthetics delete removes a synthetics monitor."
        ),
        destructive_pattern!(
            "newrelic-api-delete",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.newrelic\.com",
            "New Relic API DELETE calls remove monitoring/alerting resources."
        ),
        destructive_pattern!(
            "newrelic-graphql-delete-mutation",
            r"(?i)curl\s+.*api\.newrelic\.com[^\s]*?/graphql\b.*\bmutation\b.*\bdelete\w*\b",
            "New Relic GraphQL delete mutations can remove monitoring resources."
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
        assert_eq!(pack.id, "monitoring.newrelic");
        assert_eq!(pack.name, "New Relic");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"newrelic"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "newrelic entity search --name my-service");
        assert_safe_pattern_matches(&pack, "newrelic apm application get 123");
        assert_safe_pattern_matches(&pack, "newrelic query \"SELECT count(*) FROM Transaction\"");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.newrelic.com/v2/alerts_policies.json",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "newrelic entity delete 123",
            "newrelic-entity-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "newrelic apm application delete 123",
            "newrelic-apm-app-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "newrelic workload delete 123",
            "newrelic-workload-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "newrelic synthetics delete 123",
            "newrelic-synthetics-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.newrelic.com/v2/alerts_policies/123.json",
            "newrelic-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            r#"curl -X POST https://api.newrelic.com/graphql -d '{"query":"mutation { deleteEntity(guid: \"abc\") }"}'"#,
            "newrelic-graphql-delete-mutation",
        );
    }
}

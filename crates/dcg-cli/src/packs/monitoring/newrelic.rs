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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand so a resource/entity name containing
    // the subcommand keyword as a substring doesn't short-circuit
    // destructive newrelic ops via the safe rule.
    vec![
        safe_pattern!(
            "newrelic-entity-search",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+entity\s+search(?=\s|$)"
        ),
        safe_pattern!(
            "newrelic-apm-app-get",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+apm\s+application\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "newrelic-query",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+query(?=\s|$)"
        ),
        safe_pattern!(
            "newrelic-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:POST|DELETE)\b)(?=.*api\.newrelic\.com))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*api\.newrelic\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "newrelic-entity-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+entity\s+delete\b",
            "newrelic entity delete removes a New Relic entity, impacting observability.",
            High,
            "Deleting a New Relic entity removes all associated telemetry data, relationships, \
             and alert configurations. Historical metrics for this entity will no longer be \
             accessible.\n\n\
             Safer alternatives:\n\
             - newrelic entity search: Find and verify the entity first\n\
             - Tag the entity as deprecated instead of deleting\n\
             - Export entity configuration before deletion"
        ),
        destructive_pattern!(
            "newrelic-apm-app-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+apm\s+application\s+delete\b",
            "newrelic apm application delete removes an APM application.",
            High,
            "Deleting an APM application removes all application performance data, traces, \
             and associated alert policies. You lose visibility into application behavior \
             and historical performance trends.\n\n\
             Safer alternatives:\n\
             - newrelic apm application get <id>: Review application details first\n\
             - Disable the APM agent in your application instead\n\
             - Export application settings and dashboards as backup"
        ),
        destructive_pattern!(
            "newrelic-workload-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+workload\s+delete\b",
            "newrelic workload delete removes a workload definition.",
            High,
            "Deleting a workload removes the logical grouping of entities and any associated \
             health status calculations. Teams using this workload for service overview will \
             lose their aggregated view.\n\n\
             Safer alternatives:\n\
             - Review workload entities and dependencies first\n\
             - Export workload definition using the API\n\
             - Modify the workload rather than deleting and recreating"
        ),
        destructive_pattern!(
            "newrelic-synthetics-delete",
            r"\bnewrelic\b(?:\s+--?\S+(?:\s+\S+)?)*\s+synthetics\s+delete\b",
            "newrelic synthetics delete removes a synthetics monitor.",
            High,
            "Deleting a synthetics monitor stops all uptime and availability checking for \
             the monitored endpoint. You will no longer receive alerts when the endpoint \
             becomes unavailable or slow.\n\n\
             Safer alternatives:\n\
             - Disable the monitor temporarily instead of deleting\n\
             - Export monitor configuration as code (Terraform/Pulumi)\n\
             - newrelic synthetics search: Verify you're deleting the correct monitor"
        ),
        destructive_pattern!(
            "newrelic-api-delete",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.newrelic\.com).*",
            "New Relic API DELETE calls remove monitoring/alerting resources.",
            High,
            "Direct API DELETE calls permanently remove New Relic resources without \
             confirmation. Alert policies, dashboards, and monitors are deleted immediately.\n\n\
             Safer alternatives:\n\
             - GET the resource first to verify the ID and export configuration\n\
             - Use the New Relic CLI for better feedback and confirmation\n\
             - Use Terraform/Pulumi for version-controlled resource management"
        ),
        destructive_pattern!(
            "newrelic-graphql-delete-mutation",
            r"(?i)\bcurl\b(?=.*api\.newrelic\.com[^\s]*?/graphql\b)(?=.*\bmutation\b)(?=.*\bdelete\w*\b).*",
            "New Relic GraphQL delete mutations can remove monitoring resources.",
            High,
            "GraphQL delete mutations remove New Relic resources via the NerdGraph API. \
             This affects entities, dashboards, alert policies, and other observability \
             resources.\n\n\
             Safer alternatives:\n\
             - Run a query first to verify the GUID or resource ID\n\
             - Use the New Relic CLI or UI for deletion with better feedback\n\
             - Export the resource definition before deletion"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
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

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let api_delete = "curl -X GET https://api.newrelic.com/v2/alerts_policies.json \
            -X DELETE https://api.newrelic.com/v2/alerts_policies/123.json";

        assert_no_safe_match(&pack, api_delete);
        assert_blocks_with_pattern(&pack, api_delete, "newrelic-api-delete");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.newrelic.com/v2/alerts_policies/123.json --request=DELETE",
            "newrelic-api-delete",
        );

        let graphql_delete = concat!(
            "curl -X GET https://api.newrelic.com/v2/alerts_policies.json ",
            r#"-X POST https://api.newrelic.com/graphql -d '{"query":"mutation { deleteEntity(guid: \"abc\") }"}'"#
        );
        assert_no_safe_match(&pack, graphql_delete);
        assert_blocks_with_pattern(&pack, graphql_delete, "newrelic-graphql-delete-mutation");
    }

    #[test]
    fn newrelic_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "newrelic entity delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "newrelic apm application delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "newrelic workload delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "newrelic synthetics delete 123", Severity::High);
    }

    #[test]
    fn newrelic_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}

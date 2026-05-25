//! `Flipt` Feature Flags pack - protections for destructive `Flipt` operations.
//!
//! Covers destructive operations for:
//! - `flipt` CLI (`flipt delete`, etc.)
//! - `Flipt` API (DELETE requests)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Flipt` Feature Flags pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "featureflags.flipt".to_string(),
        name: "Flipt",
        description: "Protects against destructive Flipt CLI and API operations.",
        keywords: &["flipt"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // flipt CLI - list/get operations
        safe_pattern!(
            "flipt-flag-list",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-flag-get",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-flag-create",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-flag-update",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+update(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-segment-list",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-segment-get",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-segment-create",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-namespace-list",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-namespace-get",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-namespace-create",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-rule-list",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-rule-get",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-rule-create",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-evaluate",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+evaluate(?=\s|$)"
        ),
        // Help and version commands
        safe_pattern!(
            "flipt-help",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help|-h|help)(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-version",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version|version)(?=\s|$)"
        ),
        // Server commands (safe)
        safe_pattern!(
            "flipt-server",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:server|serve)(?=\s|$)"
        ),
        safe_pattern!(
            "flipt-config",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // flipt CLI - delete operations
        destructive_pattern!(
            "flipt-flag-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+delete\b",
            "flipt flag delete permanently removes a feature flag. This cannot be undone.",
            Critical,
            "Deleting a Flipt feature flag immediately removes it from evaluation. All \
             applications checking this flag will receive default values or errors. Rules, \
             variants, and distributions associated with the flag are also removed.\n\n\
             Safer alternatives:\n\
             - flipt flag get: Review flag configuration first\n\
             - Disable the flag instead of deleting\n\
             - Export flag configuration before deletion"
        ),
        destructive_pattern!(
            "flipt-segment-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+delete\b",
            "flipt segment delete removes a segment and its constraints.",
            High,
            "Deleting a segment removes user grouping rules. Any flags using this segment \
             for targeting will lose that targeting logic, potentially changing which users \
             receive which variants.\n\n\
             Safer alternatives:\n\
             - flipt segment get: Review segment configuration\n\
             - Check which flags reference this segment\n\
             - Update flags to use different segments first"
        ),
        destructive_pattern!(
            "flipt-namespace-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+delete\b",
            "flipt namespace delete removes a namespace and all its flags, segments, and rules.",
            Critical,
            "Deleting a namespace removes ALL flags, segments, rules, and constraints \
             within it. This is a complete wipe of that feature flag environment. All \
             applications using this namespace will lose flag evaluations.\n\n\
             Safer alternatives:\n\
             - flipt namespace get: Review namespace contents\n\
             - Export all flags and segments before deletion\n\
             - Migrate resources to another namespace first"
        ),
        destructive_pattern!(
            "flipt-rule-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+delete\b",
            "flipt rule delete removes a targeting rule from a flag.",
            High,
            "Deleting a rule changes how the flag evaluates for targeted users. Users \
             previously matching this rule will fall through to other rules or receive \
             the default variant.\n\n\
             Safer alternatives:\n\
             - flipt rule get: Review rule configuration\n\
             - Disable the rule instead of deleting\n\
             - Verify other rules handle affected users"
        ),
        destructive_pattern!(
            "flipt-constraint-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+constraint\s+delete\b",
            "flipt constraint delete removes a constraint from a segment.",
            Medium,
            "Removing a constraint changes segment membership. Users previously excluded \
             or included by this constraint will now match or not match the segment \
             differently.\n\n\
             Safer alternatives:\n\
             - Review segment membership before and after\n\
             - Test constraint changes in a staging namespace\n\
             - Document why the constraint is being removed"
        ),
        destructive_pattern!(
            "flipt-variant-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+variant\s+delete\b",
            "flipt variant delete removes a variant from a flag.",
            High,
            "Deleting a variant removes a possible flag value. Rules distributing traffic \
             to this variant will fail or need adjustment. Applications expecting this \
             variant value may break.\n\n\
             Safer alternatives:\n\
             - Check which rules reference this variant\n\
             - Update distributions before deleting\n\
             - Zero out traffic to this variant first"
        ),
        destructive_pattern!(
            "flipt-distribution-delete",
            r"flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+distribution\s+delete\b",
            "flipt distribution delete removes a distribution from a rule.",
            Medium,
            "Removing a distribution changes traffic allocation within a rule. The \
             affected variant will no longer receive traffic from this rule, shifting \
             all traffic to remaining distributions.\n\n\
             Safer alternatives:\n\
             - Review current traffic allocation\n\
             - Adjust percentages instead of deleting\n\
             - Verify other distributions handle the traffic"
        ),
        // API - DELETE requests (Flipt uses gRPC but also has REST API)
        destructive_pattern!(
            "flipt-api-delete",
            r"curl\s+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)\s+.*?/api/v1/",
            "DELETE request to Flipt API can remove flags, segments, or rules.",
            High,
            "Direct API DELETE calls to Flipt can remove flags, segments, rules, or \
             namespaces without CLI confirmation prompts. API deletions take effect \
             immediately across all connected applications.\n\n\
             Safer alternatives:\n\
             - Use the Flipt CLI for better confirmation prompts\n\
             - GET the resource first to verify what will be deleted\n\
             - Use the Flipt UI for visibility into dependencies"
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
        assert_eq!(pack.id, "featureflags.flipt");
        assert_eq!(pack.name, "Flipt");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"flipt"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // flipt CLI - list/get operations
        assert_safe_pattern_matches(&pack, "flipt flag list");
        assert_safe_pattern_matches(&pack, "flipt flag list --namespace default");
        assert_safe_pattern_matches(&pack, "flipt flag get my-flag");
        assert_safe_pattern_matches(&pack, "flipt flag create --key new-flag");
        assert_safe_pattern_matches(&pack, "flipt flag update my-flag --name renamed");
        assert_safe_pattern_matches(&pack, "flipt segment list");
        assert_safe_pattern_matches(&pack, "flipt segment get beta-users");
        assert_safe_pattern_matches(&pack, "flipt namespace list");
        assert_safe_pattern_matches(&pack, "flipt namespace get production");
        assert_safe_pattern_matches(&pack, "flipt rule list --flag my-flag");
        assert_safe_pattern_matches(&pack, "flipt evaluate --flag my-flag --entity user-123");
        // Help commands
        assert_safe_pattern_matches(&pack, "flipt --help");
        assert_safe_pattern_matches(&pack, "flipt help");
        assert_safe_pattern_matches(&pack, "flipt --version");
        // Server commands
        assert_safe_pattern_matches(&pack, "flipt server");
        assert_safe_pattern_matches(&pack, "flipt serve");
        assert_safe_pattern_matches(&pack, "flipt config");
    }

    #[test]
    fn blocks_flag_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "flipt flag delete my-flag --namespace default",
            "flipt-flag-delete",
        );
    }

    #[test]
    fn blocks_segment_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "flipt segment delete beta-users",
            "flipt-segment-delete",
        );
    }

    #[test]
    fn blocks_namespace_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "flipt namespace delete production",
            "flipt-namespace-delete",
        );
    }

    #[test]
    fn blocks_rule_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "flipt rule delete --flag my-flag --id rule-123",
            "flipt-rule-delete",
        );
    }

    #[test]
    fn blocks_variant_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "flipt variant delete --flag my-flag --key variant-a",
            "flipt-variant-delete",
        );
    }

    #[test]
    fn blocks_api_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://flipt.example.com:8080/api/v1/namespaces/default/flags/my-flag",
            "flipt-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -XDELETE http://flipt.example.com:8080/api/v1/namespaces/default/flags/my-flag",
            "flipt-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE http://flipt.example.com:8080/api/v1/namespaces/default/flags/my-flag",
            "flipt-api-delete",
        );
    }

    #[test]
    fn allows_non_flipt_commands() {
        let pack = create_pack();
        assert_allows(&pack, "echo flipt");
        assert_allows(&pack, "cat flipt.yaml");
    }
}

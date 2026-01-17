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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // flipt CLI - list/get operations
        safe_pattern!("flipt-flag-list", r"flipt\s+flag\s+list\b"),
        safe_pattern!("flipt-flag-get", r"flipt\s+flag\s+get\b"),
        safe_pattern!("flipt-flag-create", r"flipt\s+flag\s+create\b"),
        safe_pattern!("flipt-flag-update", r"flipt\s+flag\s+update\b"),
        safe_pattern!("flipt-segment-list", r"flipt\s+segment\s+list\b"),
        safe_pattern!("flipt-segment-get", r"flipt\s+segment\s+get\b"),
        safe_pattern!("flipt-segment-create", r"flipt\s+segment\s+create\b"),
        safe_pattern!("flipt-namespace-list", r"flipt\s+namespace\s+list\b"),
        safe_pattern!("flipt-namespace-get", r"flipt\s+namespace\s+get\b"),
        safe_pattern!("flipt-namespace-create", r"flipt\s+namespace\s+create\b"),
        safe_pattern!("flipt-rule-list", r"flipt\s+rule\s+list\b"),
        safe_pattern!("flipt-rule-get", r"flipt\s+rule\s+get\b"),
        safe_pattern!("flipt-rule-create", r"flipt\s+rule\s+create\b"),
        safe_pattern!("flipt-evaluate", r"flipt\s+evaluate\b"),
        // Help and version commands
        safe_pattern!("flipt-help", r"flipt\s+(?:--help|-h|help)\b"),
        safe_pattern!("flipt-version", r"flipt\s+(?:--version|version)\b"),
        // Server commands (safe)
        safe_pattern!("flipt-server", r"flipt\s+(?:server|serve)\b"),
        safe_pattern!("flipt-config", r"flipt\s+config\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // flipt CLI - delete operations
        destructive_pattern!(
            "flipt-flag-delete",
            r"flipt\s+flag\s+delete\b",
            "flipt flag delete permanently removes a feature flag. This cannot be undone."
        ),
        destructive_pattern!(
            "flipt-segment-delete",
            r"flipt\s+segment\s+delete\b",
            "flipt segment delete removes a segment and its constraints."
        ),
        destructive_pattern!(
            "flipt-namespace-delete",
            r"flipt\s+namespace\s+delete\b",
            "flipt namespace delete removes a namespace and all its flags, segments, and rules."
        ),
        destructive_pattern!(
            "flipt-rule-delete",
            r"flipt\s+rule\s+delete\b",
            "flipt rule delete removes a targeting rule from a flag."
        ),
        destructive_pattern!(
            "flipt-constraint-delete",
            r"flipt\s+constraint\s+delete\b",
            "flipt constraint delete removes a constraint from a segment."
        ),
        destructive_pattern!(
            "flipt-variant-delete",
            r"flipt\s+variant\s+delete\b",
            "flipt variant delete removes a variant from a flag."
        ),
        destructive_pattern!(
            "flipt-distribution-delete",
            r"flipt\s+distribution\s+delete\b",
            "flipt distribution delete removes a distribution from a rule."
        ),
        // API - DELETE requests (Flipt uses gRPC but also has REST API)
        destructive_pattern!(
            "flipt-api-delete",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*?/api/v1/",
            "DELETE request to Flipt API can remove flags, segments, or rules."
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
    }

    #[test]
    fn allows_non_flipt_commands() {
        let pack = create_pack();
        assert_allows(&pack, "echo flipt");
        assert_allows(&pack, "cat flipt.yaml");
    }
}

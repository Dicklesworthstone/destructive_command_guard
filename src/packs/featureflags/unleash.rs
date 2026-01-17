//! `Unleash` Feature Flags pack - protections for destructive `Unleash` operations.
//!
//! Covers destructive operations for:
//! - `unleash` CLI
//! - `Unleash` API (DELETE requests)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Unleash` Feature Flags pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "featureflags.unleash".to_string(),
        name: "Unleash",
        description: "Protects against destructive Unleash CLI and API operations.",
        keywords: &["unleash"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // unleash CLI - list/get operations
        safe_pattern!("unleash-features-list", r"unleash\s+features?\s+list\b"),
        safe_pattern!("unleash-features-get", r"unleash\s+features?\s+get\b"),
        safe_pattern!("unleash-features-create", r"unleash\s+features?\s+create\b"),
        safe_pattern!("unleash-features-update", r"unleash\s+features?\s+update\b"),
        safe_pattern!("unleash-features-enable", r"unleash\s+features?\s+enable\b"),
        safe_pattern!(
            "unleash-features-disable",
            r"unleash\s+features?\s+disable\b"
        ),
        safe_pattern!("unleash-projects-list", r"unleash\s+projects?\s+list\b"),
        safe_pattern!("unleash-projects-get", r"unleash\s+projects?\s+get\b"),
        safe_pattern!("unleash-projects-create", r"unleash\s+projects?\s+create\b"),
        safe_pattern!(
            "unleash-environments-list",
            r"unleash\s+environments?\s+list\b"
        ),
        safe_pattern!(
            "unleash-environments-get",
            r"unleash\s+environments?\s+get\b"
        ),
        safe_pattern!("unleash-strategies-list", r"unleash\s+strategies?\s+list\b"),
        safe_pattern!("unleash-strategies-get", r"unleash\s+strategies?\s+get\b"),
        // Help and version commands
        safe_pattern!("unleash-help", r"unleash\s+(?:--help|-h|help)\b"),
        safe_pattern!("unleash-version", r"unleash\s+(?:--version|version)\b"),
        // API - GET requests
        safe_pattern!(
            "unleash-api-get",
            r"curl\s+.*(?:-X\s+GET|--request\s+GET)\s+.*/api/admin/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // unleash CLI - delete/archive operations
        destructive_pattern!(
            "unleash-features-delete",
            r"unleash\s+features?\s+delete\b",
            "unleash features delete permanently removes a feature toggle. This cannot be undone."
        ),
        destructive_pattern!(
            "unleash-features-archive",
            r"unleash\s+features?\s+archive\b",
            "unleash features archive soft-deletes a feature toggle."
        ),
        destructive_pattern!(
            "unleash-projects-delete",
            r"unleash\s+projects?\s+delete\b",
            "unleash projects delete removes a project and all its feature toggles."
        ),
        destructive_pattern!(
            "unleash-environments-delete",
            r"unleash\s+environments?\s+delete\b",
            "unleash environments delete removes an environment."
        ),
        destructive_pattern!(
            "unleash-strategies-delete",
            r"unleash\s+strategies?\s+delete\b",
            "unleash strategies delete removes a custom strategy."
        ),
        destructive_pattern!(
            "unleash-api-keys-delete",
            r"unleash\s+api-keys?\s+delete\b",
            "unleash api-keys delete removes an API key."
        ),
        // API - DELETE requests
        destructive_pattern!(
            "unleash-api-delete-features",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*?/api/admin/projects/.*/features/",
            "DELETE request to Unleash API removes feature toggles."
        ),
        destructive_pattern!(
            "unleash-api-delete-projects",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*?/api/admin/projects/[^/]+$",
            "DELETE request to Unleash API removes projects."
        ),
        destructive_pattern!(
            "unleash-api-delete-generic",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*?/api/admin/",
            "DELETE request to Unleash API can remove resources."
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
        assert_eq!(pack.id, "featureflags.unleash");
        assert_eq!(pack.name, "Unleash");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"unleash"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // unleash CLI - list/get operations
        assert_safe_pattern_matches(&pack, "unleash features list");
        assert_safe_pattern_matches(&pack, "unleash feature list --project default");
        assert_safe_pattern_matches(&pack, "unleash features get my-toggle");
        assert_safe_pattern_matches(&pack, "unleash features create --name new-toggle");
        assert_safe_pattern_matches(&pack, "unleash features update my-toggle --name renamed");
        assert_safe_pattern_matches(&pack, "unleash features enable my-toggle");
        assert_safe_pattern_matches(&pack, "unleash features disable my-toggle");
        assert_safe_pattern_matches(&pack, "unleash projects list");
        assert_safe_pattern_matches(&pack, "unleash projects get default");
        assert_safe_pattern_matches(&pack, "unleash environments list");
        assert_safe_pattern_matches(&pack, "unleash strategies list");
        // Help commands
        assert_safe_pattern_matches(&pack, "unleash --help");
        assert_safe_pattern_matches(&pack, "unleash help");
        assert_safe_pattern_matches(&pack, "unleash --version");
    }

    #[test]
    fn blocks_features_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "unleash features delete my-toggle --project default",
            "unleash-features-delete",
        );
    }

    #[test]
    fn blocks_features_archive() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "unleash features archive my-toggle",
            "unleash-features-archive",
        );
    }

    #[test]
    fn blocks_projects_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "unleash projects delete my-project",
            "unleash-projects-delete",
        );
    }

    #[test]
    fn blocks_environments_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "unleash environments delete staging",
            "unleash-environments-delete",
        );
    }

    #[test]
    fn blocks_strategies_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "unleash strategies delete custom-strategy",
            "unleash-strategies-delete",
        );
    }

    #[test]
    fn blocks_api_keys_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "unleash api-keys delete key-123",
            "unleash-api-keys-delete",
        );
    }

    #[test]
    fn blocks_api_delete_features() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://unleash.example.com:4242/api/admin/projects/default/features/my-toggle",
            "unleash-api-delete-features",
        );
    }

    #[test]
    fn blocks_api_delete_projects() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://unleash.example.com:4242/api/admin/projects/my-project",
            "unleash-api-delete-projects",
        );
    }

    #[test]
    fn allows_non_unleash_commands() {
        let pack = create_pack();
        assert_allows(&pack, "echo unleash");
        assert_allows(&pack, "cat unleash.yaml");
    }
}

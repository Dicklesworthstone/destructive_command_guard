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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // unleash CLI - list/get operations
        safe_pattern!(
            "unleash-features-list",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-features-get",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-features-create",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-features-update",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+update(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-features-enable",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+enable(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-features-disable",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+disable\b"
        ),
        safe_pattern!(
            "unleash-projects-list",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-projects-get",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-projects-create",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-environments-list",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+environments?\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-environments-get",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+environments?\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-strategies-list",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+strategies?\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-strategies-get",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+strategies?\s+get(?=\s|$)"
        ),
        // Help and version commands
        safe_pattern!(
            "unleash-help",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help|-h|help)(?=\s|$)"
        ),
        safe_pattern!(
            "unleash-version",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version|version)(?=\s|$)"
        ),
        // API - GET requests
        safe_pattern!(
            "unleash-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*/api/admin/))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*/api/admin/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // unleash CLI - delete/archive operations
        destructive_pattern!(
            "unleash-features-delete",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+delete\b",
            "unleash features delete permanently removes a feature toggle. This cannot be undone.",
            Critical,
            "Deleting an Unleash feature toggle permanently removes it and all its \
             strategies. SDKs will return the default value (typically false). Event \
             history is preserved but the toggle cannot be recovered.\n\n\
             Safer alternatives:\n\
             - unleash features archive: Soft-delete with recovery\n\
             - Disable the toggle in all environments first\n\
             - Export toggle configuration before deletion"
        ),
        destructive_pattern!(
            "unleash-features-archive",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+archive\b",
            "unleash features archive soft-deletes a feature toggle.",
            High,
            "Archiving a toggle removes it from evaluation but allows recovery. SDKs \
             will stop receiving the toggle and return default values. Archived toggles \
             can be restored from the Unleash UI.\n\n\
             Safer alternatives:\n\
             - Disable the toggle before archiving\n\
             - Verify no code paths depend on the toggle\n\
             - Document the toggle's purpose before archiving"
        ),
        destructive_pattern!(
            "unleash-projects-delete",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+delete\b",
            "unleash projects delete removes a project and all its feature toggles.",
            Critical,
            "Deleting a project removes ALL feature toggles, strategies, and environments \
             within it. This is irreversible. All applications using toggles from this \
             project will receive default values.\n\n\
             Safer alternatives:\n\
             - Export project configuration first\n\
             - Archive toggles individually for recovery options\n\
             - Migrate critical toggles to another project"
        ),
        destructive_pattern!(
            "unleash-environments-delete",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+environments?\s+delete\b",
            "unleash environments delete removes an environment.",
            Critical,
            "Deleting an environment removes all toggle configurations for that \
             environment. API keys for this environment stop working. Applications \
             will fail to fetch toggle states.\n\n\
             Safer alternatives:\n\
             - Export environment configuration\n\
             - Disable toggles in the environment first\n\
             - Rotate API keys before deletion"
        ),
        destructive_pattern!(
            "unleash-strategies-delete",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+strategies?\s+delete\b",
            "unleash strategies delete removes a custom strategy.",
            High,
            "Deleting a custom strategy breaks all toggles using it. Those toggles \
             will fail to evaluate properly, potentially returning unexpected values \
             or errors.\n\n\
             Safer alternatives:\n\
             - Check which toggles use this strategy\n\
             - Migrate toggles to built-in strategies first\n\
             - Create a replacement strategy before deleting"
        ),
        destructive_pattern!(
            "unleash-api-keys-delete",
            r"unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+api-keys?\s+delete\b",
            "unleash api-keys delete removes an API key.",
            High,
            "Deleting an API key immediately revokes access for all SDKs using that \
             key. Applications will fail to connect and receive toggle updates, \
             falling back to cached or default values.\n\n\
             Safer alternatives:\n\
             - Create new API keys before deleting old ones\n\
             - Update SDK configurations first\n\
             - Use key rotation instead of deletion"
        ),
        // API - DELETE requests
        destructive_pattern!(
            "unleash-api-delete-features",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*?/api/admin/projects/.*/features/).*",
            "DELETE request to Unleash API removes feature toggles.",
            Critical,
            "API DELETE calls to features permanently remove toggles without archive \
             recovery options. All strategies and configurations are lost immediately.\n\n\
             Safer alternatives:\n\
             - Use the Unleash CLI for confirmation prompts\n\
             - Archive toggles instead of deleting\n\
             - GET the toggle configuration first"
        ),
        destructive_pattern!(
            "unleash-api-delete-projects",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*?/api/admin/projects/[^/\s]+(?:\s|$)).*",
            "DELETE request to Unleash API removes projects.",
            Critical,
            "API DELETE calls to projects remove ALL toggles, strategies, and \
             configurations within the project. This is the most destructive \
             operation and cannot be undone.\n\n\
             Safer alternatives:\n\
             - Export project configuration completely\n\
             - Use the Unleash UI for visibility\n\
             - Archive toggles individually first"
        ),
        destructive_pattern!(
            "unleash-api-delete-generic",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*?/api/admin/).*",
            "DELETE request to Unleash API can remove resources.",
            High,
            "Generic DELETE requests to the Unleash admin API can remove various \
             resources including strategies, environments, users, and API keys. \
             Review the specific endpoint before executing.\n\n\
             Safer alternatives:\n\
             - Verify the exact resource being deleted\n\
             - Use the Unleash CLI or UI for better visibility\n\
             - GET the resource first to confirm"
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
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET http://unleash.example.com:4242/api/admin/projects/default/features \
            -X DELETE http://unleash.example.com:4242/api/admin/projects/default/features/my-toggle";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "unleash-api-delete-features");

        assert_blocks_with_pattern(
            &pack,
            "curl http://unleash.example.com:4242/api/admin/projects/my-project --request=DELETE",
            "unleash-api-delete-projects",
        );
    }

    #[test]
    fn allows_non_unleash_commands() {
        let pack = create_pack();
        assert_allows(&pack, "echo unleash");
        assert_allows(&pack, "cat unleash.yaml");
    }

    #[test]
    fn global_flags_do_not_bypass() {
        let pack = create_pack();
        // unleash CLI accepts --api-url, --api-token, --project, --environment flags.
        assert_blocks_with_pattern(
            &pack,
            "unleash --api-url https://unleash.example.com --project default features delete my-toggle",
            "unleash-features-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "unleash --api-token abc123 projects delete my-project",
            "unleash-projects-delete",
        );
        assert!(
            pack.check("unleash --api-url https://u.example.com features list")
                .is_none(),
            "safe list with global flag should remain safe"
        );
    }
}

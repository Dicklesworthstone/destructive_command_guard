//! `Split.io` Feature Flags pack - protections for destructive `Split.io` operations.
//!
//! Covers destructive operations for:
//! - split CLI (`split splits delete`, `split environments delete`, etc.)
//! - `Split.io` API (DELETE requests to `api.split.io`)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Split.io` Feature Flags pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "featureflags.split".to_string(),
        name: "Split.io",
        description: "Protects against destructive Split.io CLI and API operations.",
        keywords: &["split", "api.split.io"],
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
        // split CLI - list/get operations
        safe_pattern!(
            "split-splits-list",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "split-splits-get",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "split-splits-create",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "split-splits-update",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+update(?=\s|$)"
        ),
        safe_pattern!(
            "split-environments-list",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "split-environments-get",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "split-environments-create",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "split-segments-list",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "split-segments-get",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "split-segments-create",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "split-traffic-types-list",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+traffic-types\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "split-traffic-types-get",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+traffic-types\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "split-workspaces-list",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+workspaces\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "split-workspaces-get",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+workspaces\s+get(?=\s|$)"
        ),
        // Help and version commands
        safe_pattern!(
            "split-help",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help|-h|help)(?=\s|$)"
        ),
        safe_pattern!(
            "split-version",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version|version)(?=\s|$)"
        ),
        // API - GET requests
        safe_pattern!(
            "split-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.split\.io))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*api\.split\.io"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // split CLI - delete operations
        destructive_pattern!(
            "split-splits-delete",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+delete\b",
            "split splits delete permanently removes a split definition. This cannot be undone.",
            Critical,
            "Deleting a split permanently removes the feature flag definition and all its \
             targeting rules. SDKs will return control treatment for this split. Historical \
             data and metrics are preserved but the split cannot be recovered.\n\n\
             Safer alternatives:\n\
             - split splits kill: Stop traffic without deleting\n\
             - Archive the split in the UI\n\
             - Export split configuration first"
        ),
        destructive_pattern!(
            "split-splits-kill",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+kill\b",
            "split splits kill terminates a split, stopping all traffic to treatments.",
            High,
            "Killing a split immediately stops all treatment assignment and returns the \
             default treatment to all users. Unlike delete, the split can be reactivated, \
             but all users will see behavior change immediately.\n\n\
             Safer alternatives:\n\
             - Gradually ramp down traffic percentages first\n\
             - Verify the default treatment behavior\n\
             - Communicate the change to stakeholders"
        ),
        destructive_pattern!(
            "split-environments-delete",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+delete\b",
            "split environments delete removes an environment and all its configurations.",
            Critical,
            "Deleting an environment removes all split configurations, targeting rules, \
             and API keys for that environment. Applications using this environment will \
             receive default treatments for all splits.\n\n\
             Safer alternatives:\n\
             - Export environment configuration\n\
             - Rotate API keys before deletion\n\
             - Kill all splits in the environment first"
        ),
        destructive_pattern!(
            "split-segments-delete",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+delete\b",
            "split segments delete removes a segment and its targeting rules.",
            High,
            "Deleting a segment removes user grouping definitions. Splits targeting this \
             segment will lose that targeting rule, changing which users receive which \
             treatments.\n\n\
             Safer alternatives:\n\
             - Check which splits use this segment\n\
             - Update split targeting before deletion\n\
             - Export segment membership"
        ),
        destructive_pattern!(
            "split-traffic-types-delete",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+traffic-types\s+delete\b",
            "split traffic-types delete removes a traffic type. This affects all splits using it.",
            Critical,
            "Deleting a traffic type affects ALL splits configured for that traffic type. \
             SDKs sending this traffic type will no longer match any splits, returning \
             control treatment for all evaluations.\n\n\
             Safer alternatives:\n\
             - Review all splits using this traffic type\n\
             - Migrate splits to a different traffic type\n\
             - Ensure no SDKs are sending this traffic type"
        ),
        destructive_pattern!(
            "split-workspaces-delete",
            r"split(?:\s+--?\S+(?:\s+\S+)?)*\s+workspaces\s+delete\b",
            "split workspaces delete removes a workspace and all its resources.",
            Critical,
            "Deleting a workspace removes ALL splits, segments, environments, and API keys \
             within it. This is the most destructive operation and affects all applications \
             using any resource in this workspace.\n\n\
             Safer alternatives:\n\
             - Export complete workspace configuration\n\
             - Migrate critical splits to another workspace\n\
             - Contact Split.io support for assistance"
        ),
        // API - DELETE requests
        destructive_pattern!(
            "split-api-delete-splits",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.split\.io/.*/splits/).*",
            "DELETE request to Split.io API removes split definitions.",
            Critical,
            "API DELETE calls to splits permanently remove feature flags without CLI \
             confirmation. All targeting rules and treatments are lost immediately.\n\n\
             Safer alternatives:\n\
             - Use the Split CLI for confirmation prompts\n\
             - GET the split configuration first\n\
             - Use the Split UI for visibility into impact"
        ),
        destructive_pattern!(
            "split-api-delete-environments",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.split\.io/.*/environments/).*",
            "DELETE request to Split.io API removes environments.",
            Critical,
            "API DELETE calls to environments invalidate all API keys and remove all \
             split configurations for that environment. Applications will lose all \
             feature flag evaluations.\n\n\
             Safer alternatives:\n\
             - Use the Split CLI for better confirmation\n\
             - Export environment configuration first\n\
             - Rotate API keys before deletion"
        ),
        destructive_pattern!(
            "split-api-delete-segments",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.split\.io/.*/segments/).*",
            "DELETE request to Split.io API removes segments.",
            High,
            "API DELETE calls to segments remove user groupings. Splits using this \
             segment will lose targeting rules, changing treatment assignment for \
             affected users.\n\n\
             Safer alternatives:\n\
             - Check segment dependencies first\n\
             - Update split targeting before deletion\n\
             - Export segment membership data"
        ),
        destructive_pattern!(
            "split-api-delete-generic",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.split\.io).*",
            "DELETE request to Split.io API can remove resources.",
            High,
            "Generic DELETE requests to the Split.io API can remove various resources. \
             Review the specific endpoint to understand what will be deleted.\n\n\
             Safer alternatives:\n\
             - Verify the exact resource being deleted\n\
             - Use the Split CLI or UI for better visibility\n\
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
        assert_eq!(pack.id, "featureflags.split");
        assert_eq!(pack.name, "Split.io");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"split"));
        assert!(pack.keywords.contains(&"api.split.io"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // split CLI - list/get operations
        assert_safe_pattern_matches(&pack, "split splits list");
        assert_safe_pattern_matches(&pack, "split splits list --workspace my-workspace");
        assert_safe_pattern_matches(&pack, "split splits get my-split");
        assert_safe_pattern_matches(&pack, "split splits create --name new-split");
        assert_safe_pattern_matches(&pack, "split splits update my-split --name renamed");
        assert_safe_pattern_matches(&pack, "split environments list");
        assert_safe_pattern_matches(&pack, "split environments get production");
        assert_safe_pattern_matches(&pack, "split environments create --name staging");
        assert_safe_pattern_matches(&pack, "split segments list");
        assert_safe_pattern_matches(&pack, "split segments get beta-users");
        assert_safe_pattern_matches(&pack, "split traffic-types list");
        assert_safe_pattern_matches(&pack, "split traffic-types get user");
        assert_safe_pattern_matches(&pack, "split workspaces list");
        assert_safe_pattern_matches(&pack, "split workspaces get my-workspace");
        // Help commands
        assert_safe_pattern_matches(&pack, "split --help");
        assert_safe_pattern_matches(&pack, "split help");
        assert_safe_pattern_matches(&pack, "split --version");
        // API - GET requests
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.split.io/internal/api/v2/splits",
        );
    }

    #[test]
    fn blocks_splits_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "split splits delete my-split --workspace my-workspace",
            "split-splits-delete",
        );
    }

    #[test]
    fn blocks_splits_kill() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "split splits kill my-split --workspace my-workspace",
            "split-splits-kill",
        );
    }

    #[test]
    fn blocks_environments_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "split environments delete staging --workspace my-workspace",
            "split-environments-delete",
        );
    }

    #[test]
    fn blocks_segments_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "split segments delete beta-users",
            "split-segments-delete",
        );
    }

    #[test]
    fn blocks_traffic_types_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "split traffic-types delete user",
            "split-traffic-types-delete",
        );
    }

    #[test]
    fn blocks_workspaces_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "split workspaces delete my-workspace",
            "split-workspaces-delete",
        );
    }

    #[test]
    fn blocks_api_delete_splits() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.split.io/internal/api/v2/splits/my-split",
            "split-api-delete-splits",
        );
    }

    #[test]
    fn blocks_api_delete_environments() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.split.io/internal/api/v2/environments/staging",
            "split-api-delete-environments",
        );
    }

    #[test]
    fn blocks_api_delete_segments() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.split.io/internal/api/v2/segments/beta-users",
            "split-api-delete-segments",
        );
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET https://api.split.io/internal/api/v2/splits \
            -X DELETE https://api.split.io/internal/api/v2/splits/my-split";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "split-api-delete-splits");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.split.io/internal/api/v2/environments/staging -XDELETE",
            "split-api-delete-environments",
        );
    }

    #[test]
    fn allows_non_split_commands() {
        let pack = create_pack();
        assert_allows(&pack, "echo split");
        assert_allows(&pack, "cat split.log");
    }

    #[test]
    fn global_flags_do_not_bypass() {
        let pack = create_pack();
        // split CLI accepts --apikey, --workspace, --format global flags.
        assert_blocks_with_pattern(
            &pack,
            "split --apikey abc123 splits delete my-split",
            "split-splits-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "split --workspace ws --apikey abc workspaces delete ws2",
            "split-workspaces-delete",
        );
        assert!(
            pack.check("split --apikey abc123 splits list").is_none(),
            "safe list with global flag should remain safe"
        );
    }
}

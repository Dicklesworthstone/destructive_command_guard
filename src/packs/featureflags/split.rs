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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // split CLI - list/get operations
        safe_pattern!("split-splits-list", r"split\s+splits\s+list\b"),
        safe_pattern!("split-splits-get", r"split\s+splits\s+get\b"),
        safe_pattern!("split-splits-create", r"split\s+splits\s+create\b"),
        safe_pattern!("split-splits-update", r"split\s+splits\s+update\b"),
        safe_pattern!("split-environments-list", r"split\s+environments\s+list\b"),
        safe_pattern!("split-environments-get", r"split\s+environments\s+get\b"),
        safe_pattern!(
            "split-environments-create",
            r"split\s+environments\s+create\b"
        ),
        safe_pattern!("split-segments-list", r"split\s+segments\s+list\b"),
        safe_pattern!("split-segments-get", r"split\s+segments\s+get\b"),
        safe_pattern!("split-segments-create", r"split\s+segments\s+create\b"),
        safe_pattern!(
            "split-traffic-types-list",
            r"split\s+traffic-types\s+list\b"
        ),
        safe_pattern!("split-traffic-types-get", r"split\s+traffic-types\s+get\b"),
        safe_pattern!("split-workspaces-list", r"split\s+workspaces\s+list\b"),
        safe_pattern!("split-workspaces-get", r"split\s+workspaces\s+get\b"),
        // Help and version commands
        safe_pattern!("split-help", r"split\s+(?:--help|-h|help)\b"),
        safe_pattern!("split-version", r"split\s+(?:--version|version)\b"),
        // API - GET requests
        safe_pattern!(
            "split-api-get",
            r"curl\s+.*(?:-X\s+GET|--request\s+GET)\s+.*api\.split\.io"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // split CLI - delete operations
        destructive_pattern!(
            "split-splits-delete",
            r"split\s+splits\s+delete\b",
            "split splits delete permanently removes a split definition. This cannot be undone."
        ),
        destructive_pattern!(
            "split-splits-kill",
            r"split\s+splits\s+kill\b",
            "split splits kill terminates a split, stopping all traffic to treatments."
        ),
        destructive_pattern!(
            "split-environments-delete",
            r"split\s+environments\s+delete\b",
            "split environments delete removes an environment and all its configurations."
        ),
        destructive_pattern!(
            "split-segments-delete",
            r"split\s+segments\s+delete\b",
            "split segments delete removes a segment and its targeting rules."
        ),
        destructive_pattern!(
            "split-traffic-types-delete",
            r"split\s+traffic-types\s+delete\b",
            "split traffic-types delete removes a traffic type. This affects all splits using it."
        ),
        destructive_pattern!(
            "split-workspaces-delete",
            r"split\s+workspaces\s+delete\b",
            "split workspaces delete removes a workspace and all its resources."
        ),
        // API - DELETE requests
        destructive_pattern!(
            "split-api-delete-splits",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*api\.split\.io/.*/splits/",
            "DELETE request to Split.io API removes split definitions."
        ),
        destructive_pattern!(
            "split-api-delete-environments",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*api\.split\.io/.*/environments/",
            "DELETE request to Split.io API removes environments."
        ),
        destructive_pattern!(
            "split-api-delete-segments",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*api\.split\.io/.*/segments/",
            "DELETE request to Split.io API removes segments."
        ),
        destructive_pattern!(
            "split-api-delete-generic",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*api\.split\.io",
            "DELETE request to Split.io API can remove resources."
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
    fn allows_non_split_commands() {
        let pack = create_pack();
        assert_allows(&pack, "echo split");
        assert_allows(&pack, "cat split.log");
    }
}

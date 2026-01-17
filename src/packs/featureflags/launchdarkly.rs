//! `LaunchDarkly` Feature Flags pack - protections for destructive `LaunchDarkly` operations.
//!
//! Covers destructive operations for:
//! - `ldcli` CLI (`ldcli flags delete`, `ldcli projects delete`, etc.)
//! - `LaunchDarkly` API (DELETE requests to `app.launchdarkly.com`)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `LaunchDarkly` Feature Flags pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "featureflags.launchdarkly".to_string(),
        name: "LaunchDarkly",
        description: "Protects against destructive LaunchDarkly CLI and API operations.",
        keywords: &["ldcli", "launchdarkly"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // ldcli - list/get operations
        safe_pattern!("ldcli-flags-list", r"ldcli\s+flags\s+list\b"),
        safe_pattern!("ldcli-flags-get", r"ldcli\s+flags\s+get\b"),
        safe_pattern!("ldcli-flags-create", r"ldcli\s+flags\s+create\b"),
        safe_pattern!("ldcli-flags-update", r"ldcli\s+flags\s+update\b"),
        safe_pattern!("ldcli-projects-list", r"ldcli\s+projects\s+list\b"),
        safe_pattern!("ldcli-projects-get", r"ldcli\s+projects\s+get\b"),
        safe_pattern!("ldcli-projects-create", r"ldcli\s+projects\s+create\b"),
        safe_pattern!("ldcli-environments-list", r"ldcli\s+environments\s+list\b"),
        safe_pattern!("ldcli-environments-get", r"ldcli\s+environments\s+get\b"),
        safe_pattern!(
            "ldcli-environments-create",
            r"ldcli\s+environments\s+create\b"
        ),
        safe_pattern!("ldcli-segments-list", r"ldcli\s+segments\s+list\b"),
        safe_pattern!("ldcli-segments-get", r"ldcli\s+segments\s+get\b"),
        safe_pattern!("ldcli-segments-create", r"ldcli\s+segments\s+create\b"),
        safe_pattern!("ldcli-metrics-list", r"ldcli\s+metrics\s+list\b"),
        safe_pattern!("ldcli-metrics-get", r"ldcli\s+metrics\s+get\b"),
        // Help and version commands
        safe_pattern!("ldcli-help", r"ldcli\s+(?:--help|-h|help)\b"),
        safe_pattern!("ldcli-version", r"ldcli\s+(?:--version|version)\b"),
        // API - GET requests
        safe_pattern!(
            "launchdarkly-api-get",
            r"curl\s+.*(?:-X\s+GET|--request\s+GET)\s+.*app\.launchdarkly\.com/api"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ldcli - delete operations
        destructive_pattern!(
            "ldcli-flags-delete",
            r"ldcli\s+flags\s+delete\b",
            "ldcli flags delete permanently removes a feature flag. This cannot be undone."
        ),
        destructive_pattern!(
            "ldcli-flags-archive",
            r"ldcli\s+flags\s+archive\b",
            "ldcli flags archive soft-deletes a feature flag. While recoverable, this affects all environments."
        ),
        destructive_pattern!(
            "ldcli-projects-delete",
            r"ldcli\s+projects\s+delete\b",
            "ldcli projects delete removes an entire project and all its flags, environments, and settings."
        ),
        destructive_pattern!(
            "ldcli-environments-delete",
            r"ldcli\s+environments\s+delete\b",
            "ldcli environments delete removes an environment and all its flag configurations."
        ),
        destructive_pattern!(
            "ldcli-segments-delete",
            r"ldcli\s+segments\s+delete\b",
            "ldcli segments delete removes a user segment and its targeting rules."
        ),
        destructive_pattern!(
            "ldcli-metrics-delete",
            r"ldcli\s+metrics\s+delete\b",
            "ldcli metrics delete removes a metric and its experiment data."
        ),
        // API - DELETE requests (ordered from most specific to least specific)
        destructive_pattern!(
            "launchdarkly-api-delete-environments",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*app\.launchdarkly\.com/api/.*/environments/",
            "DELETE request to LaunchDarkly API removes environments."
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-flags",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*app\.launchdarkly\.com/api/.*/flags/",
            "DELETE request to LaunchDarkly API removes feature flags."
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-segments",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*app\.launchdarkly\.com/api/.*/segments/",
            "DELETE request to LaunchDarkly API removes segments."
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-projects",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*app\.launchdarkly\.com/api/v2/projects/[^/]+$",
            "DELETE request to LaunchDarkly API removes projects."
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-generic",
            r"curl\s+.*(?:-X\s+DELETE|--request\s+DELETE)\s+.*app\.launchdarkly\.com/api/",
            "DELETE request to LaunchDarkly API can remove resources."
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
        assert_eq!(pack.id, "featureflags.launchdarkly");
        assert_eq!(pack.name, "LaunchDarkly");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"ldcli"));
        assert!(pack.keywords.contains(&"launchdarkly"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // ldcli - list/get operations
        assert_safe_pattern_matches(&pack, "ldcli flags list");
        assert_safe_pattern_matches(&pack, "ldcli flags list --project my-project");
        assert_safe_pattern_matches(&pack, "ldcli flags get my-flag");
        assert_safe_pattern_matches(&pack, "ldcli flags create --name new-flag");
        assert_safe_pattern_matches(&pack, "ldcli flags update my-flag --name renamed");
        assert_safe_pattern_matches(&pack, "ldcli projects list");
        assert_safe_pattern_matches(&pack, "ldcli projects get my-project");
        assert_safe_pattern_matches(&pack, "ldcli projects create --name new-project");
        assert_safe_pattern_matches(&pack, "ldcli environments list");
        assert_safe_pattern_matches(&pack, "ldcli environments get production");
        assert_safe_pattern_matches(&pack, "ldcli environments create --name staging");
        assert_safe_pattern_matches(&pack, "ldcli segments list");
        assert_safe_pattern_matches(&pack, "ldcli segments get beta-users");
        assert_safe_pattern_matches(&pack, "ldcli segments create --name new-segment");
        assert_safe_pattern_matches(&pack, "ldcli metrics list");
        assert_safe_pattern_matches(&pack, "ldcli metrics get click-rate");
        // Help commands
        assert_safe_pattern_matches(&pack, "ldcli --help");
        assert_safe_pattern_matches(&pack, "ldcli help");
        assert_safe_pattern_matches(&pack, "ldcli --version");
        assert_safe_pattern_matches(&pack, "ldcli version");
        // API - GET requests
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://app.launchdarkly.com/api/v2/flags/my-project",
        );
    }

    #[test]
    fn blocks_flags_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ldcli flags delete my-flag --project my-project",
            "ldcli-flags-delete",
        );
    }

    #[test]
    fn blocks_flags_archive() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ldcli flags archive my-flag --project my-project",
            "ldcli-flags-archive",
        );
    }

    #[test]
    fn blocks_projects_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ldcli projects delete my-project",
            "ldcli-projects-delete",
        );
    }

    #[test]
    fn blocks_environments_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ldcli environments delete staging --project my-project",
            "ldcli-environments-delete",
        );
    }

    #[test]
    fn blocks_segments_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ldcli segments delete beta-users --project my-project",
            "ldcli-segments-delete",
        );
    }

    #[test]
    fn blocks_metrics_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "ldcli metrics delete click-rate --project my-project",
            "ldcli-metrics-delete",
        );
    }

    #[test]
    fn blocks_api_delete_flags() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://app.launchdarkly.com/api/v2/flags/my-project/my-flag",
            "launchdarkly-api-delete-flags",
        );
    }

    #[test]
    fn blocks_api_delete_projects() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://app.launchdarkly.com/api/v2/projects/my-project",
            "launchdarkly-api-delete-projects",
        );
    }

    #[test]
    fn blocks_api_delete_environments() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://app.launchdarkly.com/api/v2/projects/my-project/environments/staging",
            "launchdarkly-api-delete-environments",
        );
    }

    #[test]
    fn blocks_api_delete_segments() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://app.launchdarkly.com/api/v2/segments/my-project/beta-users",
            "launchdarkly-api-delete-segments",
        );
    }

    #[test]
    fn blocks_api_generic_delete() {
        let pack = create_pack();
        // A DELETE request that doesn't match specific patterns should still be blocked
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://app.launchdarkly.com/api/v2/other-resource",
            "launchdarkly-api-delete-generic",
        );
    }

    #[test]
    fn allows_non_launchdarkly_commands() {
        let pack = create_pack();
        // Unrelated commands should not match safe patterns but also not be blocked
        assert_allows(&pack, "echo launchdarkly");
        assert_allows(&pack, "cat ldcli.log");
    }
}

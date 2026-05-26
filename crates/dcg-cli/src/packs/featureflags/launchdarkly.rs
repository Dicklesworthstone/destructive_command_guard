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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // ldcli - list/get operations
        safe_pattern!(
            "ldcli-flags-list",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-flags-get",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-flags-create",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-flags-update",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+update(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-projects-list",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-projects-get",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-projects-create",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-environments-list",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-environments-get",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-environments-create",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-segments-list",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-segments-get",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-segments-create",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-metrics-list",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+metrics\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-metrics-get",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+metrics\s+get(?=\s|$)"
        ),
        // Help and version commands
        safe_pattern!(
            "ldcli-help",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help|-h|help)(?=\s|$)"
        ),
        safe_pattern!(
            "ldcli-version",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version|version)(?=\s|$)"
        ),
        // API - GET requests
        safe_pattern!(
            "launchdarkly-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*app\.launchdarkly\.com/api"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ldcli - delete operations
        destructive_pattern!(
            "ldcli-flags-delete",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+delete\b",
            "ldcli flags delete permanently removes a feature flag. This cannot be undone.",
            Critical,
            "Deleting a LaunchDarkly flag permanently removes it from all environments. \
             SDKs will return default values, potentially breaking feature gates. Targeting \
             rules, prerequisites, and experiment data are lost.\n\n\
             Safer alternatives:\n\
             - ldcli flags archive: Soft-delete with recovery option\n\
             - Turn off the flag in all environments first\n\
             - Export flag configuration before deletion"
        ),
        destructive_pattern!(
            "ldcli-flags-archive",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+archive\b",
            "ldcli flags archive soft-deletes a feature flag. While recoverable, this affects all environments.",
            High,
            "Archiving a flag removes it from the flag list and evaluation. While archived \
             flags can be restored, SDKs will stop receiving the flag and return defaults \
             immediately across all environments.\n\n\
             Safer alternatives:\n\
             - Turn off the flag before archiving\n\
             - Verify no code paths depend on the flag\n\
             - Document the flag's purpose before archiving"
        ),
        destructive_pattern!(
            "ldcli-projects-delete",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+delete\b",
            "ldcli projects delete removes an entire project and all its flags, environments, and settings.",
            Critical,
            "Deleting a project removes ALL flags, environments, segments, and metrics \
             within it. This is irreversible and affects all applications using this \
             project's SDK keys.\n\n\
             Safer alternatives:\n\
             - Export project configuration first\n\
             - Archive flags individually to preserve recovery options\n\
             - Migrate critical flags to another project"
        ),
        destructive_pattern!(
            "ldcli-environments-delete",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+delete\b",
            "ldcli environments delete removes an environment and all its flag configurations.",
            Critical,
            "Deleting an environment removes all flag configurations, targeting rules, \
             and SDK keys for that environment. Applications using this environment's \
             SDK key will fail to connect.\n\n\
             Safer alternatives:\n\
             - Rotate SDK keys before deletion\n\
             - Export environment configuration\n\
             - Turn off all flags in the environment first"
        ),
        destructive_pattern!(
            "ldcli-segments-delete",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+delete\b",
            "ldcli segments delete removes a user segment and its targeting rules.",
            High,
            "Deleting a segment removes user grouping rules across all environments. \
             Flags targeting this segment will lose that targeting, changing which \
             users receive which variations.\n\n\
             Safer alternatives:\n\
             - Review which flags use this segment\n\
             - Update flag targeting before deletion\n\
             - Export segment configuration"
        ),
        destructive_pattern!(
            "ldcli-metrics-delete",
            r"ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+metrics\s+delete\b",
            "ldcli metrics delete removes a metric and its experiment data.",
            High,
            "Deleting a metric removes the metric definition and all associated \
             experiment results. Historical experiment data for this metric is lost \
             and cannot be recovered.\n\n\
             Safer alternatives:\n\
             - Export experiment results first\n\
             - Archive the metric if possible\n\
             - Document metric findings before deletion"
        ),
        // API - DELETE requests (ordered from most specific to least specific)
        destructive_pattern!(
            "launchdarkly-api-delete-environments",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/.*/environments/).*",
            "DELETE request to LaunchDarkly API removes environments.",
            Critical,
            "API DELETE calls to environments immediately invalidate SDK keys and remove \
             all flag configurations for that environment. Connected applications will \
             lose flag evaluations.\n\n\
             Safer alternatives:\n\
             - Use ldcli for better confirmation prompts\n\
             - GET the environment config first\n\
             - Rotate SDK keys before deletion"
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-flags",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/.*/flags/).*",
            "DELETE request to LaunchDarkly API removes feature flags.",
            Critical,
            "API DELETE calls permanently remove flags without archive recovery options. \
             All targeting rules, variations, and prerequisites are lost across all \
             environments.\n\n\
             Safer alternatives:\n\
             - Use ldcli flags archive for soft-delete\n\
             - GET the flag configuration first\n\
             - Use the LaunchDarkly UI for visibility"
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-segments",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/.*/segments/).*",
            "DELETE request to LaunchDarkly API removes segments.",
            High,
            "API DELETE calls to segments remove user groupings immediately. Flags \
             using this segment will lose targeting rules, changing feature behavior \
             for those users.\n\n\
             Safer alternatives:\n\
             - Check segment dependencies first\n\
             - Update flag targeting before deletion\n\
             - Export segment membership"
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-projects",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/v2/projects/[^/\s]+(?:\s|$)).*",
            "DELETE request to LaunchDarkly API removes projects.",
            Critical,
            "API DELETE calls to projects remove ALL resources: flags, environments, \
             segments, metrics, and SDK keys. This is the most destructive operation \
             and cannot be undone.\n\n\
             Safer alternatives:\n\
             - Export project configuration completely\n\
             - Use ldcli for confirmation prompts\n\
             - Contact LaunchDarkly support for assistance"
        ),
        destructive_pattern!(
            "launchdarkly-api-delete-generic",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/).*",
            "DELETE request to LaunchDarkly API can remove resources.",
            High,
            "Generic DELETE requests to the LaunchDarkly API can remove various \
             resources including webhooks, integrations, teams, and access tokens. \
             Review the specific endpoint before executing.\n\n\
             Safer alternatives:\n\
             - Verify the exact resource being deleted\n\
             - Use the LaunchDarkly UI for better visibility\n\
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
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET https://app.launchdarkly.com/api/v2/flags/my-project \
            -X DELETE https://app.launchdarkly.com/api/v2/flags/my-project/my-flag";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "launchdarkly-api-delete-flags");

        assert_blocks_with_pattern(
            &pack,
            "curl https://app.launchdarkly.com/api/v2/projects/my-project -XDELETE",
            "launchdarkly-api-delete-projects",
        );
    }

    #[test]
    fn allows_non_launchdarkly_commands() {
        let pack = create_pack();
        // Unrelated commands should not match safe patterns but also not be blocked
        assert_allows(&pack, "echo launchdarkly");
        assert_allows(&pack, "cat ldcli.log");
    }

    #[test]
    fn global_flags_do_not_bypass() {
        let pack = create_pack();
        // ldcli accepts --access-token, --base-uri, --output, --project flags.
        assert_blocks_with_pattern(
            &pack,
            "ldcli --access-token abc --project my-project flags delete my-flag",
            "ldcli-flags-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "ldcli --base-uri https://ld.example.com projects delete my-project",
            "ldcli-projects-delete",
        );
        assert!(
            pack.check("ldcli --access-token abc flags list").is_none(),
            "safe list with token flag should remain safe"
        );
    }
}

//! Datadog monitoring patterns.
//!
//! Covers destructive CLI/API operations:
//! - datadog-ci monitor/dashboard deletion
//! - Datadog API DELETE calls for monitors/dashboards/synthetics
//! - Terraform destroy targeting Datadog resources

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Datadog pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "monitoring.datadog".to_string(),
        name: "Datadog",
        description: "Protects against destructive Datadog CLI/API operations like deleting monitors and dashboards.",
        keywords: &["datadog-ci", "datadoghq", "datadog"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand so a monitor/dashboard name containing
    // `get` or `list` as a substring doesn't short-circuit destructive
    // datadog-ci ops via the safe rule.
    vec![
        safe_pattern!(
            "datadog-ci-monitors-list",
            r"datadog-ci\b(?:\s+--?\S+(?:\s+\S+)?)*\s+monitors\s+(?:get|list)(?=\s|$)"
        ),
        safe_pattern!(
            "datadog-ci-dashboards-list",
            r"datadog-ci\b(?:\s+--?\S+(?:\s+\S+)?)*\s+dashboards\s+(?:get|list)(?=\s|$)"
        ),
        safe_pattern!(
            "datadog-api-get",
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.datadoghq\.com.*\/(?:monitor|dashboard|synthetics)\/))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*api\.datadoghq\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "datadog-ci-monitors-delete",
            r"datadog-ci\b.*?\bmonitors\s+delete\b",
            "datadog-ci monitors delete removes a Datadog monitor.",
            High,
            "Deleting a Datadog monitor stops all alerting for that check. You will no \
             longer be notified if the monitored condition occurs, potentially missing \
             critical production issues.\n\n\
             Safer alternatives:\n\
             - datadog-ci monitors get <id>: Review the monitor configuration first\n\
             - Mute the monitor temporarily instead of deleting\n\
             - Export monitor JSON configuration as backup before deletion"
        ),
        destructive_pattern!(
            "datadog-ci-dashboards-delete",
            r"datadog-ci\b.*?\bdashboards\s+delete\b",
            "datadog-ci dashboards delete removes a Datadog dashboard.",
            High,
            "Deleting a dashboard removes all widgets, queries, and layout configuration. \
             Team members relying on this dashboard for visibility will lose access \
             immediately.\n\n\
             Safer alternatives:\n\
             - datadog-ci dashboards get <id>: Export dashboard JSON first\n\
             - Clone the dashboard before making changes\n\
             - Use Terraform or Pulumi for version-controlled dashboard definitions"
        ),
        destructive_pattern!(
            "datadog-api-delete",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.datadoghq\.com.*\/(?:monitor|dashboard|synthetics)\/).*",
            "Datadog API DELETE calls remove monitors/dashboards/synthetics.",
            High,
            "Direct API DELETE calls permanently remove Datadog resources without \
             confirmation prompts. Monitors, dashboards, and synthetic tests are deleted \
             immediately.\n\n\
             Safer alternatives:\n\
             - GET the resource first to verify the ID and export configuration\n\
             - Use datadog-ci CLI which provides better feedback\n\
             - Use Terraform/Pulumi for auditable, reversible infrastructure changes"
        ),
        destructive_pattern!(
            "terraform-datadog-destroy",
            r"terraform\b.*?\bdestroy\b.*\bdatadog_[a-zA-Z0-9_]+\b",
            "terraform destroy targeting Datadog resources removes monitoring infrastructure.",
            High,
            "Terraform destroy removes Datadog monitors, dashboards, and other resources \
             defined in your configuration. While Terraform tracks state, the actual \
             monitoring resources are deleted immediately from Datadog.\n\n\
             Safer alternatives:\n\
             - terraform plan -destroy -target=... to preview deletions\n\
             - terraform state rm to stop managing without deleting\n\
             - Remove from Terraform config and apply instead of destroy"
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
        assert_eq!(pack.id, "monitoring.datadog");
        assert_eq!(pack.name, "Datadog");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"datadog-ci"));
        assert!(pack.keywords.contains(&"datadoghq"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "datadog-ci monitors list");
        assert_safe_pattern_matches(&pack, "datadog-ci monitors get 123");
        assert_safe_pattern_matches(&pack, "datadog-ci dashboards list");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.datadoghq.com/api/v1/monitor",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "datadog-ci monitors delete 123",
            "datadog-ci-monitors-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "datadog-ci dashboards delete abc",
            "datadog-ci-dashboards-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.datadoghq.com/api/v1/dashboard/abc",
            "datadog-api-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "terraform destroy -target=datadog_monitor.alerts",
            "terraform-datadog-destroy",
        );
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET https://api.datadoghq.com/api/v1/monitor \
            -X DELETE https://api.datadoghq.com/api/v1/dashboard/abc";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "datadog-api-delete");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.datadoghq.com/api/v1/dashboard/abc -XDELETE",
            "datadog-api-delete",
        );
    }

    #[test]
    fn datadog_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "datadog-ci monitors delete 123", Severity::High);
        assert_blocks_with_severity(&pack, "datadog-ci dashboards delete abc", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.datadoghq.com/api/v1/dashboard/abc",
            Severity::High,
        );
    }

    #[test]
    fn datadog_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}

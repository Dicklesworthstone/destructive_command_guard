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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "datadog-ci-monitors-list",
            r"datadog-ci\s+monitors\s+(?:get|list)\b"
        ),
        safe_pattern!(
            "datadog-ci-dashboards-list",
            r"datadog-ci\s+dashboards\s+(?:get|list)\b"
        ),
        safe_pattern!(
            "datadog-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*api\.datadoghq\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "datadog-ci-monitors-delete",
            r"datadog-ci\s+monitors\s+delete\b",
            "datadog-ci monitors delete removes a Datadog monitor."
        ),
        destructive_pattern!(
            "datadog-ci-dashboards-delete",
            r"datadog-ci\s+dashboards\s+delete\b",
            "datadog-ci dashboards delete removes a Datadog dashboard."
        ),
        destructive_pattern!(
            "datadog-api-delete",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.datadoghq\.com.*\/(monitor|dashboard|synthetics)\/",
            "Datadog API DELETE calls remove monitors/dashboards/synthetics."
        ),
        destructive_pattern!(
            "terraform-datadog-destroy",
            r"terraform\s+destroy\b.*\bdatadog_[a-zA-Z0-9_]+\b",
            "terraform destroy targeting Datadog resources removes monitoring infrastructure."
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
}

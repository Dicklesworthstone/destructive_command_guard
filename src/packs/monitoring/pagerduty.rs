//! `PagerDuty` monitoring pack - protections for destructive `PagerDuty` operations.
//!
//! Covers destructive CLI/API operations:
//! - `pd ... delete` for services, schedules, escalation policies, users, and teams
//! - `PagerDuty` API DELETE calls for services and schedules

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `PagerDuty` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "monitoring.pagerduty".to_string(),
        name: "PagerDuty",
        description: "Protects against destructive PagerDuty CLI/API operations like deleting \
                      services and schedules (which can break incident routing).",
        keywords: &["pd", "pagerduty", "api.pagerduty.com"],
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
            "pd-service-read",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+(?:list|get)\b"
        ),
        safe_pattern!(
            "pd-schedule-read",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+schedule\s+(?:list|get)\b"
        ),
        safe_pattern!(
            "pd-incident-list",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+incident\s+list\b"
        ),
        safe_pattern!(
            "pagerduty-api-get",
            r"(?i)curl\s+.*(?:-X|--request)\s+GET\b.*api\.pagerduty\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "pd-service-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+delete\b",
            "pd service delete removes a PagerDuty service, which can break incident routing."
        ),
        destructive_pattern!(
            "pd-schedule-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+schedule\s+delete\b",
            "pd schedule delete removes a PagerDuty schedule."
        ),
        destructive_pattern!(
            "pd-escalation-policy-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+escalation-policy\s+delete\b",
            "pd escalation-policy delete removes a PagerDuty escalation policy."
        ),
        destructive_pattern!(
            "pd-user-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+delete\b",
            "pd user delete removes a PagerDuty user."
        ),
        destructive_pattern!(
            "pd-team-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+team\s+delete\b",
            "pd team delete removes a PagerDuty team."
        ),
        destructive_pattern!(
            "pagerduty-api-delete-service",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.pagerduty\.com[^\s]*?/services/[^\s]+",
            "PagerDuty API DELETE /services/{id} deletes a PagerDuty service."
        ),
        destructive_pattern!(
            "pagerduty-api-delete-schedule",
            r"(?i)curl\s+.*(?:-X|--request)\s+DELETE\b.*api\.pagerduty\.com[^\s]*?/schedules/[^\s]+",
            "PagerDuty API DELETE /schedules/{id} deletes a PagerDuty schedule."
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
        assert_eq!(pack.id, "monitoring.pagerduty");
        assert_eq!(pack.name, "PagerDuty");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"pd"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "pd service list");
        assert_safe_pattern_matches(&pack, "pd service get P123");
        assert_safe_pattern_matches(&pack, "pd schedule list");
        assert_safe_pattern_matches(&pack, "pd schedule get P234");
        assert_safe_pattern_matches(&pack, "pd incident list");
        assert_safe_pattern_matches(&pack, "curl -X GET https://api.pagerduty.com/services");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "pd service delete P123", "pd-service-delete");
        assert_blocks_with_pattern(&pack, "pd schedule delete P234", "pd-schedule-delete");
        assert_blocks_with_pattern(
            &pack,
            "pd escalation-policy delete P345",
            "pd-escalation-policy-delete",
        );
        assert_blocks_with_pattern(&pack, "pd user delete P456", "pd-user-delete");
        assert_blocks_with_pattern(&pack, "pd team delete P567", "pd-team-delete");
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.pagerduty.com/services/P123",
            "pagerduty-api-delete-service",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.pagerduty.com/schedules/P234",
            "pagerduty-api-delete-schedule",
        );
    }
}

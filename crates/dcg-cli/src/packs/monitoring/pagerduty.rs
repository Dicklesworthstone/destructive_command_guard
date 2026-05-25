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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.pagerduty\.com[^\s]*?/(?:services|schedules)/[^\s]+))curl\s+.*(?:-X\s*|--request(?:=|\s+))GET\b.*api\.pagerduty\.com"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "pd-service-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+delete\b",
            "pd service delete removes a PagerDuty service, which can break incident routing.",
            Critical,
            "Deleting a PagerDuty service removes all incident routing, integrations, and \
             escalation policies attached to it. Incidents will no longer be created for \
             this service, potentially causing outages to go unnoticed.\n\n\
             Safer alternatives:\n\
             - pd service list: Verify the service before deletion\n\
             - Disable the service temporarily instead of deleting\n\
             - Export service configuration via API before deletion"
        ),
        destructive_pattern!(
            "pd-schedule-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+schedule\s+delete\b",
            "pd schedule delete removes a PagerDuty schedule.",
            High,
            "Deleting a schedule removes all on-call rotations and overrides. Escalation \
             policies using this schedule will have gaps in coverage, potentially leaving \
             incidents unassigned.\n\n\
             Safer alternatives:\n\
             - pd schedule get <id>: Review schedule details first\n\
             - Update the schedule rather than deleting\n\
             - Check which escalation policies reference this schedule"
        ),
        destructive_pattern!(
            "pd-escalation-policy-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+escalation-policy\s+delete\b",
            "pd escalation-policy delete removes a PagerDuty escalation policy.",
            High,
            "Deleting an escalation policy breaks incident routing for all services using \
             it. Incidents may not be escalated properly, leading to delayed response \
             times.\n\n\
             Safer alternatives:\n\
             - Review which services use this escalation policy\n\
             - Update the policy rather than deleting\n\
             - Assign services to a different policy before deletion"
        ),
        destructive_pattern!(
            "pd-user-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+delete\b",
            "pd user delete removes a PagerDuty user.",
            High,
            "Deleting a user removes them from all schedules and escalation policies. \
             On-call coverage may have gaps, and incident history associated with this \
             user may be affected.\n\n\
             Safer alternatives:\n\
             - Deactivate the user instead of deleting\n\
             - Reassign their schedule shifts first\n\
             - Transfer incident ownership before deletion"
        ),
        destructive_pattern!(
            "pd-team-delete",
            r"\bpd\b(?:\s+--?\S+(?:\s+\S+)?)*\s+team\s+delete\b",
            "pd team delete removes a PagerDuty team.",
            High,
            "Deleting a team removes the organizational grouping and may affect access \
             controls, service ownership, and escalation policies.\n\n\
             Safer alternatives:\n\
             - pd team list: Verify the team before deletion\n\
             - Reassign team members and services first\n\
             - Merge teams rather than delete"
        ),
        destructive_pattern!(
            "pagerduty-api-delete-service",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.pagerduty\.com[^\s]*?/services/[^\s]+).*",
            "PagerDuty API DELETE /services/{id} deletes a PagerDuty service.",
            Critical,
            "Direct API deletion of a service removes all incident routing immediately. \
             There is no confirmation prompt when using curl directly.\n\n\
             Safer alternatives:\n\
             - GET the service first to verify the ID\n\
             - Use the pd CLI for better feedback\n\
             - Export service configuration before deletion"
        ),
        destructive_pattern!(
            "pagerduty-api-delete-schedule",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*api\.pagerduty\.com[^\s]*?/schedules/[^\s]+).*",
            "PagerDuty API DELETE /schedules/{id} deletes a PagerDuty schedule.",
            High,
            "API deletion of a schedule removes on-call rotations immediately. Escalation \
             policies referencing this schedule will have coverage gaps.\n\n\
             Safer alternatives:\n\
             - GET the schedule first to verify the ID\n\
             - Use the pd CLI for better feedback\n\
             - Check dependent escalation policies before deletion"
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

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let service_delete = "curl -X GET https://api.pagerduty.com/services \
            -X DELETE https://api.pagerduty.com/services/P123";

        assert_no_safe_match(&pack, service_delete);
        assert_blocks_with_pattern(&pack, service_delete, "pagerduty-api-delete-service");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.pagerduty.com/schedules/P234 -XDELETE",
            "pagerduty-api-delete-schedule",
        );
    }

    #[test]
    fn pagerduty_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "pd service delete P123", Severity::Critical);
        assert_blocks_with_severity(&pack, "pd schedule delete P234", Severity::High);
        assert_blocks_with_severity(&pack, "pd escalation-policy delete P345", Severity::High);
        assert_blocks_with_severity(&pack, "pd user delete P456", Severity::High);
        assert_blocks_with_severity(&pack, "pd team delete P567", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.pagerduty.com/services/P123",
            Severity::Critical,
        );
    }

    #[test]
    fn pagerduty_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}

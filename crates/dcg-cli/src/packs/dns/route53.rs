//! AWS Route53 DNS pack - protections for destructive Route53 operations.
//!
//! Covers destructive CLI operations:
//! - Hosted zone deletion
//! - DNS record set deletion via change-resource-record-sets
//! - Health check deletion
//! - Query logging config deletion
//! - Traffic policy deletion
//! - Reusable delegation set deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS Route53 DNS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "dns.route53".to_string(),
        name: "AWS Route53",
        description: "Protects against destructive AWS Route53 DNS operations like hosted zone deletion \
                      and record set DELETE changes.",
        keywords: &["aws", "route53"],
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
            "route53-list-hosted-zones",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+list-hosted-zones\b"
        ),
        safe_pattern!(
            "route53-list-resource-record-sets",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+list-resource-record-sets\b"
        ),
        safe_pattern!(
            "route53-get-hosted-zone",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+get-hosted-zone\b"
        ),
        safe_pattern!(
            "route53-test-dns-answer",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+test-dns-answer\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "route53-delete-hosted-zone",
            r"\baws\b.*?\broute53\s+delete-hosted-zone\b",
            "aws route53 delete-hosted-zone permanently deletes a Route53 hosted zone.",
            Critical,
            "Deleting a hosted zone removes ALL DNS records for that domain. Services, \
             websites, and email that depend on these records will become unreachable. \
             The zone must be empty (except NS/SOA) before AWS allows deletion.\n\n\
             Safer alternatives:\n\
             - aws route53 list-resource-record-sets to review records first\n\
             - Export zone to file before deletion\n\
             - Delete individual records instead of the entire zone"
        ),
        destructive_pattern!(
            "route53-change-resource-record-sets-delete",
            r"\baws\b.*?\broute53\s+change-resource-record-sets\b.*\bDELETE\b",
            "aws route53 change-resource-record-sets with DELETE removes DNS records.",
            High,
            "DELETE actions in change-resource-record-sets immediately remove DNS records. \
             DNS caching may provide brief respite, but resolvers will fail to reach your \
             services once caches expire (often within minutes for low TTL records).\n\n\
             Safer alternatives:\n\
             - Use UPSERT action to modify rather than delete and recreate\n\
             - Test changes in a non-production hosted zone first\n\
             - Use aws route53 list-resource-record-sets to verify record state"
        ),
        destructive_pattern!(
            "route53-delete-health-check",
            r"\baws\b.*?\broute53\s+delete-health-check\b",
            "aws route53 delete-health-check permanently deletes a Route53 health check.",
            High,
            "Deleting a health check can disrupt DNS failover. If records reference this \
             health check, Route53 may route traffic to unhealthy endpoints or stop \
             failover entirely, causing outages.\n\n\
             Safer alternatives:\n\
             - aws route53 get-health-check to review configuration first\n\
             - Check which records use this health check before deletion\n\
             - Update dependent records to use a different health check first"
        ),
        destructive_pattern!(
            "route53-delete-query-logging-config",
            r"\baws\b.*?\broute53\s+delete-query-logging-config\b",
            "aws route53 delete-query-logging-config removes a Route53 query logging configuration.",
            Medium,
            "Deleting query logging stops DNS query visibility for that hosted zone. This \
             can impact debugging, security monitoring, and compliance auditing. Historical \
             logs in CloudWatch remain, but new queries will not be logged.\n\n\
             Safer alternatives:\n\
             - aws route53 get-query-logging-config to review before deletion\n\
             - Disable logging temporarily by updating the config instead\n\
             - Ensure CloudWatch log retention meets compliance needs"
        ),
        destructive_pattern!(
            "route53-delete-traffic-policy",
            r"\baws\b.*?\broute53\s+delete-traffic-policy\b",
            "aws route53 delete-traffic-policy permanently deletes a Route53 traffic policy.",
            High,
            "Deleting a traffic policy removes the routing logic. Policy instances \
             (applied to hosted zones) will fail to update or may stop working. This \
             can disrupt geo-routing, latency-based routing, or weighted distributions.\n\n\
             Safer alternatives:\n\
             - aws route53 list-traffic-policy-instances to check usage first\n\
             - Create a new policy version instead of deleting\n\
             - Delete policy instances before deleting the policy itself"
        ),
        destructive_pattern!(
            "route53-delete-reusable-delegation-set",
            r"\baws\b.*?\broute53\s+delete-reusable-delegation-set\b",
            "aws route53 delete-reusable-delegation-set permanently deletes a reusable delegation set.",
            High,
            "Deleting a reusable delegation set affects all hosted zones using it. If \
             domain registrars point to these name servers, DNS resolution will fail \
             for all associated domains until registrar records are updated.\n\n\
             Safer alternatives:\n\
             - Check which hosted zones use this delegation set first\n\
             - Migrate zones to a different delegation set before deletion\n\
             - Update domain registrar NS records after any changes"
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
        assert_eq!(pack.id, "dns.route53");
        assert_eq!(pack.name, "AWS Route53");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"aws"));
        assert!(pack.keywords.contains(&"route53"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws route53 list-hosted-zones");
        assert_safe_pattern_matches(
            &pack,
            "aws route53 list-resource-record-sets --hosted-zone-id Z123",
        );
        assert_safe_pattern_matches(&pack, "aws route53 get-hosted-zone --id Z123");
        assert_safe_pattern_matches(
            &pack,
            "aws route53 test-dns-answer --hosted-zone-id Z123 --record-name example.com",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-hosted-zone --id Z123",
            "route53-delete-hosted-zone",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"}]}'",
            "route53-change-resource-record-sets-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-health-check --health-check-id abc",
            "route53-delete-health-check",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-query-logging-config --id abc",
            "route53-delete-query-logging-config",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-traffic-policy --id abc --version 1",
            "route53-delete-traffic-policy",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws route53 delete-reusable-delegation-set --id N123",
            "route53-delete-reusable-delegation-set",
        );
    }

    #[test]
    fn aws_global_flags_do_not_bypass() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws --profile prod route53 delete-hosted-zone --id Z123",
            "route53-delete-hosted-zone",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws --region us-east-1 --profile prod route53 delete-health-check --health-check-id h",
            "route53-delete-health-check",
        );
        assert!(
            pack.check("aws --profile prod route53 list-hosted-zones")
                .is_none(),
            "safe read with global flag should remain safe"
        );
    }

    #[test]
    fn route53_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws route53 delete-hosted-zone --id Z123",
            "aws route53 delete-hosted-zone permanently deletes a Route53 hosted zone",
        );
        assert_blocks(
            &pack,
            "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"}]}'",
            "aws route53 change-resource-record-sets with DELETE removes DNS records",
        );
        assert_blocks(
            &pack,
            "aws route53 delete-health-check --health-check-id abc",
            "aws route53 delete-health-check permanently deletes a Route53 health check",
        );
        assert_blocks(
            &pack,
            "aws route53 delete-query-logging-config --id abc",
            "aws route53 delete-query-logging-config removes a Route53 query logging configuration",
        );
        assert_blocks(
            &pack,
            "aws route53 delete-traffic-policy --id abc --version 1",
            "aws route53 delete-traffic-policy permanently deletes a Route53 traffic policy",
        );
        assert_blocks(
            &pack,
            "aws route53 delete-reusable-delegation-set --id N123",
            "aws route53 delete-reusable-delegation-set permanently deletes a reusable delegation set",
        );
    }

    #[test]
    fn route53_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "aws route53 delete-hosted-zone --id Z123",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch '{\"Changes\":[{\"Action\":\"DELETE\"}]}'",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws route53 delete-health-check --health-check-id abc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws route53 delete-query-logging-config --id abc",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "aws route53 delete-traffic-policy --id abc --version 1",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws route53 delete-reusable-delegation-set --id N123",
            Severity::High,
        );
    }

    #[test]
    fn route53_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws route53 list-hosted-zones");
        assert_safe_pattern_matches(&pack, "aws route53 list-hosted-zones --max-items 10");
        assert_safe_pattern_matches(
            &pack,
            "aws route53 list-resource-record-sets --hosted-zone-id Z123",
        );
        assert_safe_pattern_matches(&pack, "aws route53 get-hosted-zone --id Z123");
        assert_safe_pattern_matches(
            &pack,
            "aws route53 test-dns-answer --hosted-zone-id Z123 --record-name example.com",
        );
        assert_safe_pattern_matches(&pack, "aws --profile prod route53 list-hosted-zones");
        assert_safe_pattern_matches(
            &pack,
            "aws --region us-east-1 route53 get-hosted-zone --id Z123",
        );
    }

    #[test]
    fn route53_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "docker ps");
    }
}

//! AWS Elastic Load Balancing (ELB) pack - protections for destructive ELB operations.
//!
//! Covers destructive operations:
//! - `aws elbv2 delete-*` operations (ALB/NLB)
//! - `aws elbv2 deregister-targets` (removes live targets)
//! - `aws elb delete-load-balancer` (Classic ELB)
//! - `aws elb deregister-instances-from-load-balancer` (removes live instances)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS ELB load balancer pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "loadbalancer.elb".to_string(),
        name: "AWS ELB",
        description: "Protects against destructive AWS Elastic Load Balancing (ELB/ALB/NLB) \
                      operations like deleting load balancers, target groups, or deregistering \
                      targets from live traffic.",
        keywords: &[
            "elbv2",
            "delete-load-balancer",
            "delete-target-group",
            "deregister-targets",
            "delete-listener",
            "delete-rule",
            "deregister-instances-from-load-balancer",
        ],
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
        // ELBv2 safe describe operations
        safe_pattern!(
            "elbv2-describe-load-balancers",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+describe-load-balancers\b"
        ),
        safe_pattern!(
            "elbv2-describe-target-groups",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+describe-target-groups\b"
        ),
        safe_pattern!(
            "elbv2-describe-target-health",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+describe-target-health\b"
        ),
        // Classic ELB safe describe operations
        safe_pattern!(
            "elb-describe-load-balancers",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elb\s+describe-load-balancers\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ELBv2 destructive operations (ALB/NLB)
        destructive_pattern!(
            "elbv2-delete-load-balancer",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+delete-load-balancer\b",
            "aws elbv2 delete-load-balancer permanently deletes the load balancer."
        ),
        destructive_pattern!(
            "elbv2-delete-target-group",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+delete-target-group\b",
            "aws elbv2 delete-target-group permanently deletes the target group."
        ),
        destructive_pattern!(
            "elbv2-deregister-targets",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+deregister-targets\b",
            "aws elbv2 deregister-targets removes targets from the load balancer, impacting live traffic."
        ),
        destructive_pattern!(
            "elbv2-delete-listener",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+delete-listener\b",
            "aws elbv2 delete-listener deletes a listener, potentially breaking traffic routing."
        ),
        destructive_pattern!(
            "elbv2-delete-rule",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elbv2\s+delete-rule\b",
            "aws elbv2 delete-rule deletes a listener rule, potentially breaking routing."
        ),
        // Classic ELB destructive operations
        destructive_pattern!(
            "elb-delete-load-balancer",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elb\s+delete-load-balancer\b",
            "aws elb delete-load-balancer permanently deletes the classic load balancer."
        ),
        destructive_pattern!(
            "elb-deregister-instances",
            r"\baws\b(?:\s+(?:--profile|--region|--output|--endpoint-url)\s+\S+|\s+--\S+)*\s+elb\s+deregister-instances-from-load-balancer\b",
            "aws elb deregister-instances-from-load-balancer removes instances from the load balancer, impacting live traffic."
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
        assert_eq!(pack.id, "loadbalancer.elb");
        assert_eq!(pack.name, "AWS ELB");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"elbv2"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws elbv2 describe-load-balancers");
        assert_safe_pattern_matches(
            &pack,
            "aws --profile prod elbv2 describe-target-groups --names my-tg",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws --region us-west-2 --output json elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:us-west-2:123:targetgroup/tg/abc",
        );
        assert_safe_pattern_matches(&pack, "aws elb describe-load-balancers");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws elbv2 delete-load-balancer --load-balancer-arn arn:aws:elasticloadbalancing:us-west-2:123:loadbalancer/app/lb/abc",
            "elbv2-delete-load-balancer",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws --profile prod elbv2 delete-target-group --target-group-arn arn:aws:elasticloadbalancing:us-west-2:123:targetgroup/tg/abc",
            "elbv2-delete-target-group",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws elbv2 deregister-targets --target-group-arn arn:aws:elasticloadbalancing:us-west-2:123:targetgroup/tg/abc --targets Id=i-0123456789abcdef0",
            "elbv2-deregister-targets",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws elbv2 delete-listener --listener-arn arn:aws:elasticloadbalancing:us-west-2:123:listener/app/lb/abc/def",
            "elbv2-delete-listener",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws elbv2 delete-rule --rule-arn arn:aws:elasticloadbalancing:us-west-2:123:listener-rule/app/lb/abc/def/ghi",
            "elbv2-delete-rule",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws elb delete-load-balancer --load-balancer-name my-classic-elb",
            "elb-delete-load-balancer",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws elb deregister-instances-from-load-balancer --load-balancer-name my-classic-elb --instances i-0123456789abcdef0",
            "elb-deregister-instances",
        );
    }

    #[test]
    fn elb_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "aws elbv2 delete-load-balancer --load-balancer-arn arn:aws:elasticloadbalancing:us-west-2:123:loadbalancer/app/lb/abc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws --profile prod elbv2 delete-target-group --target-group-arn arn:aws:elasticloadbalancing:us-west-2:123:targetgroup/tg/abc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws elbv2 deregister-targets --target-group-arn arn:aws:elasticloadbalancing:us-west-2:123:targetgroup/tg/abc --targets Id=i-0123456789abcdef0",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws elbv2 delete-listener --listener-arn arn:aws:elasticloadbalancing:us-west-2:123:listener/app/lb/abc/def",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws elbv2 delete-rule --rule-arn arn:aws:elasticloadbalancing:us-west-2:123:listener-rule/app/lb/abc/def/ghi",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws elb delete-load-balancer --load-balancer-name my-classic-elb",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws elb deregister-instances-from-load-balancer --load-balancer-name my-classic-elb --instances i-0123456789abcdef0",
            Severity::High,
        );
    }

    #[test]
    fn elb_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

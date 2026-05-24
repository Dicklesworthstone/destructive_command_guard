//! AWS SES pack - protections for destructive AWS Simple Email Service operations.
//!
//! Covers destructive operations:
//! - Identity deletion (ses and sesv2)
//! - Template deletion
//! - Configuration set deletion
//! - Receipt rule deletion
//! - Contact list deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS SES pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "email.ses".to_string(),
        name: "AWS SES",
        description: "Protects against destructive AWS Simple Email Service operations like \
                      identity deletion, template deletion, and configuration set removal.",
        keywords: &["ses", "sesv2"],
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
        // SES v1 read operations
        safe_pattern!(
            "ses-list-identities",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+list-identities(?=\s|$)"
        ),
        safe_pattern!(
            "ses-list-templates",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+list-templates(?=\s|$)"
        ),
        safe_pattern!(
            "ses-list-configuration-sets",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+list-configuration-sets\b"
        ),
        safe_pattern!(
            "ses-list-receipt-rules",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+list-receipt-rules\b"
        ),
        safe_pattern!(
            "ses-list-receipt-rule-sets",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+list-receipt-rule-sets\b"
        ),
        safe_pattern!(
            "ses-get-identity-verification-attributes",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+get-identity-verification-attributes\b"
        ),
        safe_pattern!(
            "ses-get-identity-dkim-attributes",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+get-identity-dkim-attributes\b"
        ),
        safe_pattern!(
            "ses-get-identity-notification-attributes",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+get-identity-notification-attributes\b"
        ),
        safe_pattern!(
            "ses-get-template",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+get-template(?=\s|$)"
        ),
        safe_pattern!(
            "ses-describe-configuration-set",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+describe-configuration-set\b"
        ),
        safe_pattern!(
            "ses-describe-receipt-rule",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+describe-receipt-rule\b"
        ),
        safe_pattern!(
            "ses-describe-receipt-rule-set",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+describe-receipt-rule-set\b"
        ),
        safe_pattern!(
            "ses-get-send-quota",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+get-send-quota(?=\s|$)"
        ),
        safe_pattern!(
            "ses-get-send-statistics",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+get-send-statistics\b"
        ),
        // SES v2 read operations
        safe_pattern!(
            "sesv2-list-email-identities",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+list-email-identities\b"
        ),
        safe_pattern!(
            "sesv2-list-email-templates",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+list-email-templates\b"
        ),
        safe_pattern!(
            "sesv2-list-configuration-sets",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+list-configuration-sets\b"
        ),
        safe_pattern!(
            "sesv2-list-contact-lists",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+list-contact-lists\b"
        ),
        safe_pattern!(
            "sesv2-list-dedicated-ip-pools",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+list-dedicated-ip-pools\b"
        ),
        safe_pattern!(
            "sesv2-get-email-identity",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+get-email-identity\b"
        ),
        safe_pattern!(
            "sesv2-get-email-template",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+get-email-template\b"
        ),
        safe_pattern!(
            "sesv2-get-configuration-set",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+get-configuration-set\b"
        ),
        safe_pattern!(
            "sesv2-get-contact-list",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+get-contact-list\b"
        ),
        safe_pattern!(
            "sesv2-get-dedicated-ip-pool",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+get-dedicated-ip-pool\b"
        ),
        safe_pattern!(
            "sesv2-get-account",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+get-account(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // SES v1 deletion operations
        destructive_pattern!(
            "ses-delete-identity",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+delete-identity\b",
            "aws ses delete-identity removes a verified email identity.",
            High,
            "Deleting a verified identity prevents sending from that address or domain. \
             Applications using this identity will fail to send emails. Re-verification \
             requires DNS changes and propagation time.\n\n\
             Safer alternatives:\n\
             - aws ses list-identities: Review identities first\n\
             - Check which applications use this identity\n\
             - Create new identity before deleting old one"
        ),
        destructive_pattern!(
            "ses-delete-template",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+delete-template\b",
            "aws ses delete-template removes an email template.",
            Medium,
            "Deleting a template breaks any applications that reference it. Emails using \
             this template will fail to send until the template is recreated.\n\n\
             Safer alternatives:\n\
             - aws ses get-template: Export template before deletion\n\
             - Verify no active campaigns use this template\n\
             - Create replacement template before deleting"
        ),
        destructive_pattern!(
            "ses-delete-configuration-set",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+delete-configuration-set\b",
            "aws ses delete-configuration-set removes a configuration set.",
            High,
            "Deleting a configuration set removes tracking and event destinations. \
             Applications using this set will lose metrics, bounce handling, and \
             complaint processing.\n\n\
             Safer alternatives:\n\
             - aws ses describe-configuration-set: Review configuration\n\
             - Migrate applications to a new configuration set first\n\
             - Document event destinations before deletion"
        ),
        destructive_pattern!(
            "ses-delete-receipt-rule-set",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+delete-receipt-rule-set\b",
            "aws ses delete-receipt-rule-set removes a receipt rule set.",
            Critical,
            "Deleting a receipt rule set stops all email receiving configured by that set. \
             Incoming emails may bounce or be lost. This affects all receipt rules in the set.\n\n\
             Safer alternatives:\n\
             - aws ses describe-receipt-rule-set: Review rules first\n\
             - Create replacement rule set before deletion\n\
             - Test with a non-active rule set"
        ),
        destructive_pattern!(
            "ses-delete-receipt-rule",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ses\s+delete-receipt-rule(?:\s|$)",
            "aws ses delete-receipt-rule removes a receipt rule.",
            High,
            "Deleting a receipt rule changes how incoming emails are processed. Actions \
             like S3 storage, Lambda triggers, or SNS notifications will stop for \
             matching emails.\n\n\
             Safer alternatives:\n\
             - aws ses describe-receipt-rule: Review rule configuration\n\
             - Disable the rule before deleting\n\
             - Ensure no critical workflows depend on this rule"
        ),
        // SES v2 deletion operations
        destructive_pattern!(
            "sesv2-delete-email-identity",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+delete-email-identity\b",
            "aws sesv2 delete-email-identity removes a verified email identity.",
            High,
            "Deleting a verified identity prevents sending from that address or domain. \
             DKIM and SPF records become orphaned. Applications will fail until a new \
             identity is verified.\n\n\
             Safer alternatives:\n\
             - aws sesv2 get-email-identity: Review identity configuration\n\
             - Verify replacement identity before deletion\n\
             - Update applications to use new identity first"
        ),
        destructive_pattern!(
            "sesv2-delete-email-template",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+delete-email-template\b",
            "aws sesv2 delete-email-template removes an email template.",
            Medium,
            "Deleting a template breaks any send operations referencing it. Bulk email \
             sends and transactional emails using this template will fail.\n\n\
             Safer alternatives:\n\
             - aws sesv2 get-email-template: Export template content\n\
             - Check for active campaigns using this template\n\
             - Version templates rather than deleting"
        ),
        destructive_pattern!(
            "sesv2-delete-configuration-set",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+delete-configuration-set\b",
            "aws sesv2 delete-configuration-set removes a configuration set.",
            High,
            "Deleting a configuration set removes all event destinations, tracking options, \
             and delivery settings. Applications using this set lose visibility into \
             email delivery.\n\n\
             Safer alternatives:\n\
             - aws sesv2 get-configuration-set: Export configuration\n\
             - Migrate to new configuration set first\n\
             - Document all event destinations"
        ),
        destructive_pattern!(
            "sesv2-delete-contact-list",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+delete-contact-list\b",
            "aws sesv2 delete-contact-list removes a contact list.",
            High,
            "Deleting a contact list permanently removes all contacts and their preferences. \
             Subscription management and list-based sending will fail. This cannot be undone.\n\n\
             Safer alternatives:\n\
             - Export contact list data before deletion\n\
             - Check for active campaigns using this list\n\
             - Use list segmentation instead of deletion"
        ),
        destructive_pattern!(
            "sesv2-delete-dedicated-ip-pool",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+sesv2\s+delete-dedicated-ip-pool\b",
            "aws sesv2 delete-dedicated-ip-pool removes a dedicated IP pool.",
            Critical,
            "Deleting a dedicated IP pool releases the IPs back to the shared pool. \
             Email reputation built on these IPs is lost. Configuration sets using \
             this pool will fall back to shared IPs.\n\n\
             Safer alternatives:\n\
             - Migrate configuration sets to a new pool first\n\
             - Document IP addresses and reputation metrics\n\
             - Contact AWS support if IPs need to be preserved"
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
        assert_eq!(pack.id, "email.ses");
        assert_eq!(pack.name, "AWS SES");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"ses"));
        assert!(pack.keywords.contains(&"sesv2"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // SES v1 read operations
        assert_safe_pattern_matches(&pack, "aws ses list-identities");
        assert_safe_pattern_matches(&pack, "aws ses list-templates");
        assert_safe_pattern_matches(&pack, "aws ses list-configuration-sets");
        assert_safe_pattern_matches(
            &pack,
            "aws ses list-receipt-rules --rule-set-name MyRuleSet",
        );
        assert_safe_pattern_matches(&pack, "aws ses list-receipt-rule-sets");
        assert_safe_pattern_matches(
            &pack,
            "aws ses get-identity-verification-attributes --identities example.com",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws ses get-identity-dkim-attributes --identities example.com",
        );
        assert_safe_pattern_matches(&pack, "aws ses get-template --template-name MyTemplate");
        assert_safe_pattern_matches(
            &pack,
            "aws ses describe-configuration-set --configuration-set-name MySet",
        );
        assert_safe_pattern_matches(&pack, "aws ses get-send-quota");
        assert_safe_pattern_matches(&pack, "aws ses get-send-statistics");
        // SES v2 read operations
        assert_safe_pattern_matches(&pack, "aws sesv2 list-email-identities");
        assert_safe_pattern_matches(&pack, "aws sesv2 list-email-templates");
        assert_safe_pattern_matches(&pack, "aws sesv2 list-configuration-sets");
        assert_safe_pattern_matches(&pack, "aws sesv2 list-contact-lists");
        assert_safe_pattern_matches(&pack, "aws sesv2 list-dedicated-ip-pools");
        assert_safe_pattern_matches(
            &pack,
            "aws sesv2 get-email-identity --email-identity example.com",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws sesv2 get-email-template --template-name MyTemplate",
        );
        assert_safe_pattern_matches(
            &pack,
            "aws sesv2 get-configuration-set --configuration-set-name MySet",
        );
        assert_safe_pattern_matches(&pack, "aws sesv2 get-account");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // SES v1 deletion operations
        assert_blocks_with_pattern(
            &pack,
            "aws ses delete-identity --identity example.com",
            "ses-delete-identity",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ses delete-template --template-name MyTemplate",
            "ses-delete-template",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ses delete-configuration-set --configuration-set-name MySet",
            "ses-delete-configuration-set",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ses delete-receipt-rule --rule-set-name MyRuleSet --rule-name MyRule",
            "ses-delete-receipt-rule",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws ses delete-receipt-rule-set --rule-set-name MyRuleSet",
            "ses-delete-receipt-rule-set",
        );
        // SES v2 deletion operations
        assert_blocks_with_pattern(
            &pack,
            "aws sesv2 delete-email-identity --email-identity example.com",
            "sesv2-delete-email-identity",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sesv2 delete-email-template --template-name MyTemplate",
            "sesv2-delete-email-template",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sesv2 delete-configuration-set --configuration-set-name MySet",
            "sesv2-delete-configuration-set",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sesv2 delete-contact-list --contact-list-name MyList",
            "sesv2-delete-contact-list",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws sesv2 delete-dedicated-ip-pool --pool-name MyPool",
            "sesv2-delete-dedicated-ip-pool",
        );
    }

    #[test]
    fn ses_blocks_with_correct_severity() {
        let pack = create_pack();
        // SES v1
        assert_blocks_with_severity(
            &pack,
            "aws ses delete-identity --identity example.com",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws ses delete-template --template-name MyTemplate",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "aws ses delete-configuration-set --configuration-set-name MySet",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws ses delete-receipt-rule-set --rule-set-name MyRuleSet",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "aws ses delete-receipt-rule --rule-set-name MyRuleSet --rule-name MyRule",
            Severity::High,
        );
        // SES v2
        assert_blocks_with_severity(
            &pack,
            "aws sesv2 delete-email-identity --email-identity example.com",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sesv2 delete-email-template --template-name MyTemplate",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sesv2 delete-configuration-set --configuration-set-name MySet",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sesv2 delete-contact-list --contact-list-name MyList",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws sesv2 delete-dedicated-ip-pool --pool-name MyPool",
            Severity::Critical,
        );
    }

    #[test]
    fn ses_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }

    #[test]
    fn aws_global_flags_do_not_bypass() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws --profile prod ses delete-identity --identity example.com",
            "ses-delete-identity",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws --region us-east-1 --profile prod sesv2 delete-contact-list --contact-list-name X",
            "sesv2-delete-contact-list",
        );
        assert!(
            pack.check("aws --profile prod ses list-identities")
                .is_none(),
            "safe read with global flag should remain safe"
        );
    }
}

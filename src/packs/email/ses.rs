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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // SES v1 read operations
        safe_pattern!("ses-list-identities", r"\baws\s+ses\s+list-identities\b"),
        safe_pattern!("ses-list-templates", r"\baws\s+ses\s+list-templates\b"),
        safe_pattern!(
            "ses-list-configuration-sets",
            r"\baws\s+ses\s+list-configuration-sets\b"
        ),
        safe_pattern!(
            "ses-list-receipt-rules",
            r"\baws\s+ses\s+list-receipt-rules\b"
        ),
        safe_pattern!(
            "ses-list-receipt-rule-sets",
            r"\baws\s+ses\s+list-receipt-rule-sets\b"
        ),
        safe_pattern!(
            "ses-get-identity-verification-attributes",
            r"\baws\s+ses\s+get-identity-verification-attributes\b"
        ),
        safe_pattern!(
            "ses-get-identity-dkim-attributes",
            r"\baws\s+ses\s+get-identity-dkim-attributes\b"
        ),
        safe_pattern!(
            "ses-get-identity-notification-attributes",
            r"\baws\s+ses\s+get-identity-notification-attributes\b"
        ),
        safe_pattern!("ses-get-template", r"\baws\s+ses\s+get-template\b"),
        safe_pattern!(
            "ses-describe-configuration-set",
            r"\baws\s+ses\s+describe-configuration-set\b"
        ),
        safe_pattern!(
            "ses-describe-receipt-rule",
            r"\baws\s+ses\s+describe-receipt-rule\b"
        ),
        safe_pattern!(
            "ses-describe-receipt-rule-set",
            r"\baws\s+ses\s+describe-receipt-rule-set\b"
        ),
        safe_pattern!("ses-get-send-quota", r"\baws\s+ses\s+get-send-quota\b"),
        safe_pattern!(
            "ses-get-send-statistics",
            r"\baws\s+ses\s+get-send-statistics\b"
        ),
        // SES v2 read operations
        safe_pattern!(
            "sesv2-list-email-identities",
            r"\baws\s+sesv2\s+list-email-identities\b"
        ),
        safe_pattern!(
            "sesv2-list-email-templates",
            r"\baws\s+sesv2\s+list-email-templates\b"
        ),
        safe_pattern!(
            "sesv2-list-configuration-sets",
            r"\baws\s+sesv2\s+list-configuration-sets\b"
        ),
        safe_pattern!(
            "sesv2-list-contact-lists",
            r"\baws\s+sesv2\s+list-contact-lists\b"
        ),
        safe_pattern!(
            "sesv2-list-dedicated-ip-pools",
            r"\baws\s+sesv2\s+list-dedicated-ip-pools\b"
        ),
        safe_pattern!(
            "sesv2-get-email-identity",
            r"\baws\s+sesv2\s+get-email-identity\b"
        ),
        safe_pattern!(
            "sesv2-get-email-template",
            r"\baws\s+sesv2\s+get-email-template\b"
        ),
        safe_pattern!(
            "sesv2-get-configuration-set",
            r"\baws\s+sesv2\s+get-configuration-set\b"
        ),
        safe_pattern!(
            "sesv2-get-contact-list",
            r"\baws\s+sesv2\s+get-contact-list\b"
        ),
        safe_pattern!(
            "sesv2-get-dedicated-ip-pool",
            r"\baws\s+sesv2\s+get-dedicated-ip-pool\b"
        ),
        safe_pattern!("sesv2-get-account", r"\baws\s+sesv2\s+get-account\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // SES v1 deletion operations
        destructive_pattern!(
            "ses-delete-identity",
            r"\baws\s+ses\s+delete-identity\b",
            "aws ses delete-identity removes a verified email identity."
        ),
        destructive_pattern!(
            "ses-delete-template",
            r"\baws\s+ses\s+delete-template\b",
            "aws ses delete-template removes an email template."
        ),
        destructive_pattern!(
            "ses-delete-configuration-set",
            r"\baws\s+ses\s+delete-configuration-set\b",
            "aws ses delete-configuration-set removes a configuration set."
        ),
        destructive_pattern!(
            "ses-delete-receipt-rule-set",
            r"\baws\s+ses\s+delete-receipt-rule-set\b",
            "aws ses delete-receipt-rule-set removes a receipt rule set."
        ),
        destructive_pattern!(
            "ses-delete-receipt-rule",
            r"\baws\s+ses\s+delete-receipt-rule(?:\s|$)",
            "aws ses delete-receipt-rule removes a receipt rule."
        ),
        // SES v2 deletion operations
        destructive_pattern!(
            "sesv2-delete-email-identity",
            r"\baws\s+sesv2\s+delete-email-identity\b",
            "aws sesv2 delete-email-identity removes a verified email identity."
        ),
        destructive_pattern!(
            "sesv2-delete-email-template",
            r"\baws\s+sesv2\s+delete-email-template\b",
            "aws sesv2 delete-email-template removes an email template."
        ),
        destructive_pattern!(
            "sesv2-delete-configuration-set",
            r"\baws\s+sesv2\s+delete-configuration-set\b",
            "aws sesv2 delete-configuration-set removes a configuration set."
        ),
        destructive_pattern!(
            "sesv2-delete-contact-list",
            r"\baws\s+sesv2\s+delete-contact-list\b",
            "aws sesv2 delete-contact-list removes a contact list."
        ),
        destructive_pattern!(
            "sesv2-delete-dedicated-ip-pool",
            r"\baws\s+sesv2\s+delete-dedicated-ip-pool\b",
            "aws sesv2 delete-dedicated-ip-pool removes a dedicated IP pool."
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
}

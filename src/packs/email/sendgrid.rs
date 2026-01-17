//! `SendGrid` pack - protections for destructive `SendGrid` API operations.
//!
//! Covers destructive operations:
//! - Template deletion
//! - API key deletion
//! - Domain authentication removal
//! - Sender identity deletion
//! - Suppression list operations

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack, SafePattern};

/// Create the `SendGrid` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "email.sendgrid".to_string(),
        name: "SendGrid",
        description: "Protects against destructive SendGrid API operations like template deletion, \
                      API key deletion, and domain authentication removal.",
        keywords: &["sendgrid", "api.sendgrid.com"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

const fn create_safe_patterns() -> Vec<SafePattern> {
    // No safe patterns - this pack uses destructive patterns only.
    // GET/POST requests to SendGrid API endpoints are allowed by default.
    vec![]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Template deletion
        destructive_pattern!(
            "sendgrid-delete-template",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/templates/|sendgrid\.com/v3/templates/\S+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to SendGrid /v3/templates removes a transactional template."
        ),
        // API key deletion
        destructive_pattern!(
            "sendgrid-delete-api-key",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/api_keys/|sendgrid\.com/v3/api_keys/\S+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to SendGrid /v3/api_keys removes an API key."
        ),
        // Domain authentication deletion
        destructive_pattern!(
            "sendgrid-delete-whitelabel-domain",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/whitelabel/domains/|sendgrid\.com/v3/whitelabel/domains/\d+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to SendGrid /v3/whitelabel/domains removes domain authentication."
        ),
        // Sender identity deletion
        destructive_pattern!(
            "sendgrid-delete-sender",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/(?:senders|verified_senders)/|sendgrid\.com/v3/(?:senders|verified_senders)/\d+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to SendGrid /v3/senders or /v3/verified_senders removes a sender identity."
        ),
        // Teammate deletion
        destructive_pattern!(
            "sendgrid-delete-teammate",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/teammates/|sendgrid\.com/v3/teammates/\w+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to SendGrid /v3/teammates removes a teammate from the account."
        ),
        // Suppression deletion
        destructive_pattern!(
            "sendgrid-delete-suppression",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/(?:suppression|asm)/",
            "DELETE to SendGrid suppression endpoints removes entries from suppression lists."
        ),
        // Webhook deletion
        destructive_pattern!(
            "sendgrid-delete-webhook",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/user/webhooks/",
            "DELETE to SendGrid /v3/user/webhooks removes a webhook configuration."
        ),
        // Subuser deletion
        destructive_pattern!(
            "sendgrid-delete-subuser",
            r"(?:-X\s*DELETE|--request\s+DELETE).*sendgrid\.com/v3/subusers/|sendgrid\.com/v3/subusers/\w+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to SendGrid /v3/subusers removes a subuser account."
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
        assert_eq!(pack.id, "email.sendgrid");
        assert_eq!(pack.name, "SendGrid");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"sendgrid"));
        assert!(pack.keywords.contains(&"api.sendgrid.com"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // GET/POST requests are allowed (default allow, no safe patterns needed)
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/templates");
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/templates/d-abc123");
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/api_keys");
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/stats");
        assert_allows(
            &pack,
            "curl -X POST https://api.sendgrid.com/v3/mail/send -d '{}'",
        );
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/whitelabel/domains");
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/senders");
        assert_allows(&pack, "curl https://api.sendgrid.com/v3/user/profile");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Template deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/templates/d-abc123",
            "sendgrid-delete-template",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE https://api.sendgrid.com/v3/templates/d-abc123",
            "sendgrid-delete-template",
        );
        // API key deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/api_keys/abc123",
            "sendgrid-delete-api-key",
        );
        // Domain deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/whitelabel/domains/12345",
            "sendgrid-delete-whitelabel-domain",
        );
        // Sender deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/senders/12345",
            "sendgrid-delete-sender",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/verified_senders/12345",
            "sendgrid-delete-sender",
        );
        // Teammate deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/teammates/username",
            "sendgrid-delete-teammate",
        );
        // Suppression deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/suppression/bounces/email@test.com",
            "sendgrid-delete-suppression",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/asm/groups/123",
            "sendgrid-delete-suppression",
        );
        // Webhook deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/user/webhooks/event/settings",
            "sendgrid-delete-webhook",
        );
        // Subuser deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/subusers/username",
            "sendgrid-delete-subuser",
        );
    }
}

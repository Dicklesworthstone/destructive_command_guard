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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/templates/|sendgrid\.com/v3/templates/\S+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to SendGrid /v3/templates removes a transactional template.",
            High,
            "Deleting a template breaks any email sends referencing that template ID. \
             Applications will receive errors when trying to send with a deleted template. \
             All versions of the template are removed.\n\n\
             Safer alternatives:\n\
             - GET /v3/templates/{id}: Export template before deletion\n\
             - Create a new version instead of deleting\n\
             - Check email code for template ID references"
        ),
        // API key deletion
        destructive_pattern!(
            "sendgrid-delete-api-key",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/api_keys/|sendgrid\.com/v3/api_keys/\S+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to SendGrid /v3/api_keys removes an API key.",
            Critical,
            "Deleting an API key immediately revokes access. All applications using this \
             key will fail to authenticate. You cannot recover the key value after deletion.\n\n\
             Safer alternatives:\n\
             - Create new API key before deleting old one\n\
             - Update applications with new key first\n\
             - Use API key scopes to limit damage"
        ),
        // Domain authentication deletion
        destructive_pattern!(
            "sendgrid-delete-whitelabel-domain",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/whitelabel/domains/|sendgrid\.com/v3/whitelabel/domains/\d+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to SendGrid /v3/whitelabel/domains removes domain authentication.",
            Critical,
            "Deleting domain authentication removes DKIM and SPF records. Emails sent \
             from this domain will fail authentication checks, leading to delivery issues \
             and potential spam classification.\n\n\
             Safer alternatives:\n\
             - Document DNS records before deletion\n\
             - Verify new domain authentication is working\n\
             - Plan for DNS propagation delays"
        ),
        // Sender identity deletion
        destructive_pattern!(
            "sendgrid-delete-sender",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/(?:senders|verified_senders)/|sendgrid\.com/v3/(?:senders|verified_senders)/\d+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to SendGrid /v3/senders or /v3/verified_senders removes a sender identity.",
            High,
            "Deleting a sender identity prevents sending from that email address. \
             Marketing campaigns and transactional emails using this sender will fail. \
             Re-verification may require email confirmation.\n\n\
             Safer alternatives:\n\
             - Create new sender identity before deleting\n\
             - Update email configurations first\n\
             - Check for scheduled campaigns using this sender"
        ),
        // Teammate deletion
        destructive_pattern!(
            "sendgrid-delete-teammate",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/teammates/|sendgrid\.com/v3/teammates/\w+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to SendGrid /v3/teammates removes a teammate from the account.",
            Medium,
            "Deleting a teammate revokes their access to the SendGrid account. They lose \
             access to templates, statistics, and settings they may have been managing.\n\n\
             Safer alternatives:\n\
             - Change teammate permissions instead of deleting\n\
             - Ensure knowledge transfer is complete\n\
             - Verify teammate doesn't own critical configurations"
        ),
        // Suppression deletion
        destructive_pattern!(
            "sendgrid-delete-suppression",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/(?:suppression|asm)/",
            "DELETE to SendGrid suppression endpoints removes entries from suppression lists.",
            High,
            "Removing suppression entries allows emails to be sent to addresses that \
             previously bounced, complained, or unsubscribed. This can damage sender \
             reputation and violate CAN-SPAM compliance.\n\n\
             Safer alternatives:\n\
             - Verify the email address is valid before removing\n\
             - Check bounce reason codes\n\
             - Respect unsubscribe requests (may be legally required)"
        ),
        // Webhook deletion
        destructive_pattern!(
            "sendgrid-delete-webhook",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/user/webhooks/",
            "DELETE to SendGrid /v3/user/webhooks removes a webhook configuration.",
            Medium,
            "Deleting a webhook stops event notifications to your application. Bounce \
             handling, open tracking, and click tracking data will not be received. \
             This can affect email analytics and automation.\n\n\
             Safer alternatives:\n\
             - Document webhook URL and event types\n\
             - Test new webhook before removing old one\n\
             - Verify no critical automations depend on events"
        ),
        // Subuser deletion
        destructive_pattern!(
            "sendgrid-delete-subuser",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*sendgrid\.com/v3/subusers/|sendgrid\.com/v3/subusers/\w+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to SendGrid /v3/subusers removes a subuser account.",
            Critical,
            "Deleting a subuser removes all their data including templates, statistics, \
             and API keys. Applications using subuser credentials will fail immediately. \
             This cannot be undone.\n\n\
             Safer alternatives:\n\
             - Export subuser data and configurations\n\
             - Migrate to new subuser before deleting\n\
             - Disable subuser access instead of deleting"
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
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE https://api.sendgrid.com/v3/api_keys/abc123",
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

    #[test]
    fn sendgrid_blocks_with_correct_severity() {
        let pack = create_pack();
        // Template deletion - High
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/templates/d-abc123",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl --request DELETE https://api.sendgrid.com/v3/templates/d-abc123",
            Severity::High,
        );
        // API key deletion - Critical
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/api_keys/abc123",
            Severity::Critical,
        );
        // Domain authentication deletion - Critical
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/whitelabel/domains/12345",
            Severity::Critical,
        );
        // Sender identity deletion - High
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/senders/12345",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/verified_senders/12345",
            Severity::High,
        );
        // Teammate deletion - Medium
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/teammates/username",
            Severity::Medium,
        );
        // Suppression deletion - High
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/suppression/bounces/email@test.com",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/asm/groups/123",
            Severity::High,
        );
        // Webhook deletion - Medium
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/user/webhooks/event/settings",
            Severity::Medium,
        );
        // Subuser deletion - Critical
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.sendgrid.com/v3/subusers/username",
            Severity::Critical,
        );
    }

    #[test]
    fn sendgrid_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

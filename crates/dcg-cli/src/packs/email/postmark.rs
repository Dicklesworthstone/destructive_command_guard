//! Postmark pack - protections for destructive Postmark API operations.
//!
//! Covers destructive operations:
//! - Server deletion
//! - Template deletion (supports numeric IDs and string aliases)
//! - Domain deletion
//! - Sender signature deletion
//! - Webhook deletion
//! - Message stream deletion (supports hyphenated names)
//! - Suppression deletion

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack, SafePattern};

/// Create the Postmark pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "email.postmark".to_string(),
        name: "Postmark",
        description: "Protects against destructive Postmark API operations like server deletion, \
                      template deletion, and sender signature removal.",
        keywords: &["postmark", "api.postmarkapp.com"],
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
    // GET/POST requests to Postmark API endpoints are allowed by default.
    vec![]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Server deletion
        destructive_pattern!(
            "postmark-delete-server",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/servers/|api\.postmarkapp\.com/servers/\d+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark /servers removes a server configuration.",
            Critical,
            "Deleting a Postmark server removes all associated templates, message streams, \
             webhooks, and statistics. All applications using this server's API tokens will \
             fail to send emails. Server tokens cannot be recovered.\n\n\
             Safer alternatives:\n\
             - GET /servers/{id}: Export server configuration\n\
             - GET /templates: Export all templates first\n\
             - Create new server and migrate before deleting"
        ),
        // Template deletion
        destructive_pattern!(
            "postmark-delete-template",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/templates/|api\.postmarkapp\.com/templates/[^\s/]+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark /templates removes an email template.",
            Medium,
            "Deleting a Postmark template breaks any email sends referencing that template \
             ID or alias. Applications will receive errors when attempting to send with the \
             deleted template. Template content cannot be recovered.\n\n\
             Safer alternatives:\n\
             - GET /templates/{id}: Export template content first\n\
             - Create a new template version instead of deleting\n\
             - Search codebase for template ID/alias references"
        ),
        // Domain deletion
        destructive_pattern!(
            "postmark-delete-domain",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/domains/|api\.postmarkapp\.com/domains/\d+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark /domains removes a domain configuration.",
            Critical,
            "Deleting a Postmark domain removes DKIM keys and domain verification. Emails \
             sent from this domain will fail authentication checks, affecting deliverability. \
             Re-verification requires DNS changes and propagation time.\n\n\
             Safer alternatives:\n\
             - GET /domains/{id}: Export domain configuration\n\
             - Document DNS records before deletion\n\
             - Verify new domain is working before removing old"
        ),
        // Sender signature deletion
        destructive_pattern!(
            "postmark-delete-sender-signature",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/senders/|api\.postmarkapp\.com/senders/\d+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark /senders removes a sender signature.",
            High,
            "Deleting a sender signature prevents sending from that email address. \
             Applications using this sender will fail until a new signature is verified. \
             Re-verification requires confirming the email address.\n\n\
             Safer alternatives:\n\
             - GET /senders/{id}: Document sender configuration\n\
             - Create and verify new sender before deleting old\n\
             - Update application configurations first"
        ),
        // Webhook deletion
        destructive_pattern!(
            "postmark-delete-webhook",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/webhooks/|api\.postmarkapp\.com/webhooks/\d+.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark /webhooks removes a webhook configuration.",
            Medium,
            "Deleting a webhook stops event notifications to your application. Bounce, \
             delivery, open, click, and spam complaint notifications will not be received. \
             This affects email analytics and automation workflows.\n\n\
             Safer alternatives:\n\
             - GET /webhooks/{id}: Document webhook URL and events\n\
             - Set up new webhook before removing old one\n\
             - Test webhook endpoints before configuration changes"
        ),
        // Suppression deletion (more specific, must come before message-stream)
        destructive_pattern!(
            "postmark-delete-suppression",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/message-streams/[^/]+/suppressions/|api\.postmarkapp\.com/message-streams/[^/]+/suppressions/.*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark suppressions endpoint removes suppression entries.",
            High,
            "Removing suppression entries allows emails to addresses that previously bounced, \
             complained, or unsubscribed. This damages sender reputation and may violate \
             anti-spam regulations like CAN-SPAM and GDPR.\n\n\
             Safer alternatives:\n\
             - GET suppressions: Review reason for suppression\n\
             - Never remove unsubscribe or complaint suppressions\n\
             - Use email verification services before removing bounces"
        ),
        // Message stream deletion (must not have additional path after stream name)
        destructive_pattern!(
            "postmark-delete-message-stream",
            r"(?:-X\s*DELETE|--request(?:=|\s+)DELETE).*api\.postmarkapp\.com/message-streams/[\w-]+(?:\s|$)|api\.postmarkapp\.com/message-streams/[\w-]+(?:\s|$).*(?:-X\s*DELETE|--request(?:=|\s+)DELETE)",
            "DELETE to Postmark /message-streams removes a message stream.",
            High,
            "Deleting a message stream removes all associated statistics, suppressions, and \
             configurations. Applications sending to this stream will fail. Transactional and \
             broadcast streams have different behaviors when deleted.\n\n\
             Safer alternatives:\n\
             - GET /message-streams/{id}: Export stream configuration\n\
             - Review stream statistics before deletion\n\
             - Migrate to new stream before deleting old one"
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
        assert_eq!(pack.id, "email.postmark");
        assert_eq!(pack.name, "Postmark");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"postmark"));
        assert!(pack.keywords.contains(&"api.postmarkapp.com"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // GET requests are allowed (default allow)
        assert_allows(&pack, "curl https://api.postmarkapp.com/servers");
        assert_allows(&pack, "curl https://api.postmarkapp.com/servers/12345");
        assert_allows(&pack, "curl https://api.postmarkapp.com/templates");
        assert_allows(&pack, "curl https://api.postmarkapp.com/senders");
        assert_allows(&pack, "curl https://api.postmarkapp.com/stats/outbound");
        // POST for sending is allowed
        assert_allows(
            &pack,
            "curl -X POST https://api.postmarkapp.com/email -d '{}'",
        );
        assert_allows(
            &pack,
            "curl -X POST https://api.postmarkapp.com/email/batch -d '[]'",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Server deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/servers/12345",
            "postmark-delete-server",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE https://api.postmarkapp.com/servers/12345",
            "postmark-delete-server",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE https://api.postmarkapp.com/servers/12345",
            "postmark-delete-server",
        );
        // Template deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/templates/67890",
            "postmark-delete-template",
        );
        // Domain deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/domains/111",
            "postmark-delete-domain",
        );
        // Sender signature deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/senders/222",
            "postmark-delete-sender-signature",
        );
        // Webhook deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/webhooks/333",
            "postmark-delete-webhook",
        );
        // Message stream deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/message-streams/broadcast",
            "postmark-delete-message-stream",
        );
        // Suppression deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/message-streams/outbound/suppressions/delete",
            "postmark-delete-suppression",
        );
    }

    #[test]
    fn blocks_url_first_ordering() {
        let pack = create_pack();
        // URL before -X DELETE flag (common curl pattern)
        assert_blocks_with_pattern(
            &pack,
            "curl https://api.postmarkapp.com/servers/12345 -X DELETE",
            "postmark-delete-server",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl https://api.postmarkapp.com/templates/67890 -X DELETE",
            "postmark-delete-template",
        );
    }

    #[test]
    fn blocks_template_with_string_alias() {
        let pack = create_pack();
        // Template aliases can be strings, not just numeric IDs
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/templates/my-welcome-template",
            "postmark-delete-template",
        );
        // URL-first with alias
        assert_blocks_with_pattern(
            &pack,
            "curl https://api.postmarkapp.com/templates/password-reset -X DELETE",
            "postmark-delete-template",
        );
    }

    #[test]
    fn blocks_message_stream_with_hyphen() {
        let pack = create_pack();
        // Message stream names can contain hyphens
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.postmarkapp.com/message-streams/my-custom-stream",
            "postmark-delete-message-stream",
        );
    }
}

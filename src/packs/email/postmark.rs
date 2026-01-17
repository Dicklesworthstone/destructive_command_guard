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
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/servers/|api\.postmarkapp\.com/servers/\d+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark /servers removes a server configuration."
        ),
        // Template deletion
        destructive_pattern!(
            "postmark-delete-template",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/templates/|api\.postmarkapp\.com/templates/[^\s/]+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark /templates removes an email template."
        ),
        // Domain deletion
        destructive_pattern!(
            "postmark-delete-domain",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/domains/|api\.postmarkapp\.com/domains/\d+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark /domains removes a domain configuration."
        ),
        // Sender signature deletion
        destructive_pattern!(
            "postmark-delete-sender-signature",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/senders/|api\.postmarkapp\.com/senders/\d+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark /senders removes a sender signature."
        ),
        // Webhook deletion
        destructive_pattern!(
            "postmark-delete-webhook",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/webhooks/|api\.postmarkapp\.com/webhooks/\d+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark /webhooks removes a webhook configuration."
        ),
        // Suppression deletion (more specific, must come before message-stream)
        destructive_pattern!(
            "postmark-delete-suppression",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/message-streams/[^/]+/suppressions/|api\.postmarkapp\.com/message-streams/[^/]+/suppressions/.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark suppressions endpoint removes suppression entries."
        ),
        // Message stream deletion (must not have additional path after stream name)
        destructive_pattern!(
            "postmark-delete-message-stream",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.postmarkapp\.com/message-streams/[\w-]+(?:\s|$)|api\.postmarkapp\.com/message-streams/[\w-]+(?:\s|$).*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Postmark /message-streams removes a message stream."
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

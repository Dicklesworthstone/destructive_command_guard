//! Mailgun pack - protections for destructive Mailgun API operations.
//!
//! Covers destructive operations:
//! - Domain deletion
//! - Route deletion
//! - Mailing list deletion
//! - Template deletion
//! - Webhook deletion
//! - Credential deletion

use crate::destructive_pattern;
use crate::packs::{DestructivePattern, Pack, SafePattern};

/// Create the Mailgun pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "email.mailgun".to_string(),
        name: "Mailgun",
        description: "Protects against destructive Mailgun API operations like domain deletion, \
                      route deletion, and mailing list removal.",
        keywords: &["mailgun", "api.mailgun.net"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

const fn create_safe_patterns() -> Vec<SafePattern> {
    // No safe patterns - this pack uses destructive patterns only.
    // GET/POST requests to Mailgun API endpoints are allowed by default.
    vec![]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Domain deletion (must end after domain name, no further path)
        destructive_pattern!(
            "mailgun-delete-domain",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/domains/[^\s/]+(?:\s|$)|api\.mailgun\.net/v3/domains/[^\s/]+(?:\s|$).*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun /v3/domains removes a domain configuration."
        ),
        // Route deletion
        destructive_pattern!(
            "mailgun-delete-route",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/routes/|api\.mailgun\.net/v3/routes/\w+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun /v3/routes removes an email route."
        ),
        // Mailing list deletion
        destructive_pattern!(
            "mailgun-delete-list",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/lists/|api\.mailgun\.net/v3/lists/[^\s/]+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun /v3/lists removes a mailing list."
        ),
        // Template deletion
        destructive_pattern!(
            "mailgun-delete-template",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/[^/]+/templates/|api\.mailgun\.net/v3/[^/]+/templates/\w+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun templates endpoint removes an email template."
        ),
        // Webhook deletion
        destructive_pattern!(
            "mailgun-delete-webhook",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/domains/[^/]+/webhooks/|api\.mailgun\.net/v3/domains/[^/]+/webhooks/\w+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun webhooks endpoint removes a webhook."
        ),
        // Credential deletion
        destructive_pattern!(
            "mailgun-delete-credential",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/domains/[^/]+/credentials/|api\.mailgun\.net/v3/domains/[^/]+/credentials/[^\s/]+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun credentials endpoint removes SMTP credentials."
        ),
        // Tag deletion
        destructive_pattern!(
            "mailgun-delete-tag",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/[^/]+/tags/|api\.mailgun\.net/v3/[^/]+/tags/\w+.*(?:-X\s*DELETE|--request\s+DELETE)",
            "DELETE to Mailgun tags endpoint removes a tag."
        ),
        // Suppression deletion (bounces, complaints, unsubscribes)
        destructive_pattern!(
            "mailgun-delete-suppression",
            r"(?:-X\s*DELETE|--request\s+DELETE).*api\.mailgun\.net/v3/[^/]+/(?:bounces|complaints|unsubscribes)/",
            "DELETE to Mailgun suppression endpoints removes suppression entries."
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
        assert_eq!(pack.id, "email.mailgun");
        assert_eq!(pack.name, "Mailgun");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"mailgun"));
        assert!(pack.keywords.contains(&"api.mailgun.net"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // GET requests are allowed (default allow)
        assert_allows(&pack, "curl https://api.mailgun.net/v3/domains");
        assert_allows(&pack, "curl https://api.mailgun.net/v3/domains/example.com");
        assert_allows(&pack, "curl https://api.mailgun.net/v3/routes");
        assert_allows(&pack, "curl https://api.mailgun.net/v3/lists");
        assert_allows(&pack, "curl https://api.mailgun.net/v3/example.com/stats");
        // POST for sending is allowed
        assert_allows(
            &pack,
            "curl -X POST https://api.mailgun.net/v3/example.com/messages -d 'to=...'",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Domain deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/domains/example.com",
            "mailgun-delete-domain",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE https://api.mailgun.net/v3/domains/sandbox123.mailgun.org",
            "mailgun-delete-domain",
        );
        // Route deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/routes/abc123",
            "mailgun-delete-route",
        );
        // Mailing list deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/lists/newsletter@example.com",
            "mailgun-delete-list",
        );
        // Template deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/example.com/templates/welcome",
            "mailgun-delete-template",
        );
        // Webhook deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/domains/example.com/webhooks/clicked",
            "mailgun-delete-webhook",
        );
        // Credential deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/domains/example.com/credentials/postmaster@example.com",
            "mailgun-delete-credential",
        );
        // Tag deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/example.com/tags/marketing",
            "mailgun-delete-tag",
        );
        // Suppression deletion
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/example.com/bounces/user@test.com",
            "mailgun-delete-suppression",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/example.com/complaints/user@test.com",
            "mailgun-delete-suppression",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.mailgun.net/v3/example.com/unsubscribes/user@test.com",
            "mailgun-delete-suppression",
        );
    }
}

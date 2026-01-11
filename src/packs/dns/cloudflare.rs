//! Cloudflare DNS pack - protections for destructive DNS operations.
//!
//! Covers destructive CLI/API operations:
//! - Wrangler DNS record deletion
//! - Cloudflare API deletes for DNS records and zones
//! - Terraform destroy targeting Cloudflare DNS resources

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Cloudflare DNS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "dns.cloudflare".to_string(),
        name: "Cloudflare DNS",
        description: "Protects against destructive Cloudflare DNS operations like record deletion, zone deletion, and targeted Terraform destroy.",
        keywords: &[
            "wrangler",
            "cloudflare",
            "api.cloudflare.com",
            "dns-records",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "cloudflare-wrangler-dns-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+dns-records\s+list\b"
        ),
        safe_pattern!(
            "cloudflare-wrangler-whoami",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami\b"
        ),
        safe_pattern!(
            "cloudflare-api-get",
            r"curl\b.*\s-X\s*GET\b.*\bapi\.cloudflare\.com\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "cloudflare-wrangler-dns-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+dns-records\s+delete\b",
            "wrangler dns-records delete removes a Cloudflare DNS record."
        ),
        destructive_pattern!(
            "cloudflare-api-delete-dns-record",
            r"curl\b.*-X\s*DELETE\b.*\bapi\.cloudflare\.com\b[^\s]*?/dns_records/[^\s]+",
            "curl -X DELETE against /dns_records/{id} deletes a Cloudflare DNS record."
        ),
        destructive_pattern!(
            "cloudflare-api-delete-zone",
            r"curl\b.*-X\s*DELETE\b.*\bapi\.cloudflare\.com\b[^\s]*?/zones/[^\s]+",
            "curl -X DELETE against /zones/{id} deletes a Cloudflare zone."
        ),
        destructive_pattern!(
            "cloudflare-terraform-destroy-record",
            r"terraform\s+destroy\s+.*-target=(?:resource\.)?cloudflare_record\.",
            "terraform destroy -target=cloudflare_record deletes specific DNS records."
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
        assert_eq!(pack.id, "dns.cloudflare");
        assert_eq!(pack.name, "Cloudflare DNS");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"wrangler") || pack.keywords.contains(&"cloudflare"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "wrangler dns-records list --zone-id abc");
        assert_safe_pattern_matches(&pack, "wrangler whoami");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.cloudflare.com/client/v4/zones",
        );
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "wrangler dns-records delete --zone-id abc --record-id def",
            "cloudflare-wrangler-dns-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc/dns_records/def",
            "cloudflare-api-delete-dns-record",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc",
            "cloudflare-api-delete-zone",
        );
        assert_blocks_with_pattern(
            &pack,
            "terraform destroy -target=cloudflare_record.main",
            "cloudflare-terraform-destroy-record",
        );
    }
}

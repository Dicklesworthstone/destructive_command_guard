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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
            r"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\bapi\.cloudflare\.com\b[^\s]*?/(?:dns_records|zones)/[^\s]+))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\bapi\.cloudflare\.com\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "cloudflare-wrangler-dns-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+dns-records\s+delete\b",
            "wrangler dns-records delete removes a Cloudflare DNS record.",
            High,
            "Deleting a DNS record can immediately break connectivity to your website, API, \
             or mail server. Propagation is fast on Cloudflare, so traffic may fail within \
             seconds.\n\n\
             Safer alternatives:\n\
             - wrangler dns-records list to review records first\n\
             - Export zone file as backup before deletion\n\
             - Use Cloudflare dashboard for confirmation prompts"
        ),
        destructive_pattern!(
            "cloudflare-api-delete-dns-record",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\bapi\.cloudflare\.com\b[^\s]*?/dns_records/[^\s]+).*",
            "curl -X DELETE against /dns_records/{id} deletes a Cloudflare DNS record.",
            High,
            "API deletion of a DNS record takes effect immediately across Cloudflare's network. \
             There is no confirmation prompt when using curl directly.\n\n\
             Safer alternatives:\n\
             - GET the record first to verify the ID is correct\n\
             - Use Terraform or Pulumi for auditable, reversible changes\n\
             - Export zone configuration as backup before deletion"
        ),
        destructive_pattern!(
            "cloudflare-api-delete-zone",
            r"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\bapi\.cloudflare\.com\b[^\s]*?/zones/[^\s]+).*",
            "curl -X DELETE against /zones/{id} deletes a Cloudflare zone.",
            Critical,
            "Deleting a zone removes ALL DNS records, page rules, firewall rules, and \
             settings for that domain. This can cause complete outage for all services \
             on the domain with no easy recovery.\n\n\
             Safer alternatives:\n\
             - Export full zone configuration first\n\
             - Remove individual records instead of the entire zone\n\
             - Transfer domain to another Cloudflare account if needed"
        ),
        destructive_pattern!(
            "cloudflare-terraform-destroy-record",
            r"terraform\b.*?\s+destroy\s+.*-target=(?:resource\.)?cloudflare_record\.",
            "terraform destroy -target=cloudflare_record deletes specific DNS records.",
            High,
            "Terraform destroy removes DNS records from Cloudflare. While Terraform state \
             tracks the change, the DNS deletion is immediate and can break services.\n\n\
             Safer alternatives:\n\
             - terraform plan -destroy -target=... to preview first\n\
             - Remove from terraform config and run terraform apply instead\n\
             - Use terraform state rm to stop managing without deleting"
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

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET https://api.cloudflare.com/client/v4/zones \
            -X DELETE https://api.cloudflare.com/client/v4/zones/abc/dns_records/def";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "cloudflare-api-delete-dns-record");

        assert_blocks_with_pattern(
            &pack,
            "curl https://api.cloudflare.com/client/v4/zones/abc --request=DELETE",
            "cloudflare-api-delete-zone",
        );
    }

    #[test]
    fn cloudflare_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "wrangler dns-records delete --zone-id abc --record-id def",
            "wrangler dns-records delete removes a Cloudflare DNS record",
        );
        assert_blocks(
            &pack,
            "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc/dns_records/def",
            "curl -X DELETE against /dns_records/{id} deletes a Cloudflare DNS record",
        );
        assert_blocks(
            &pack,
            "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc",
            "curl -X DELETE against /zones/{id} deletes a Cloudflare zone",
        );
        assert_blocks(
            &pack,
            "terraform destroy -target=cloudflare_record.main",
            "terraform destroy -target=cloudflare_record deletes specific DNS records",
        );
    }

    #[test]
    fn cloudflare_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "wrangler dns-records delete --zone-id abc --record-id def",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc/dns_records/def",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE https://api.cloudflare.com/client/v4/zones/abc",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "terraform destroy -target=cloudflare_record.main",
            Severity::High,
        );
    }

    #[test]
    fn cloudflare_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "wrangler dns-records list --zone-id abc");
        assert_safe_pattern_matches(&pack, "wrangler dns-records list");
        assert_safe_pattern_matches(&pack, "wrangler whoami");
        assert_safe_pattern_matches(&pack, "wrangler --config wrangler.toml whoami");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.cloudflare.com/client/v4/zones",
        );
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET https://api.cloudflare.com/client/v4/zones/abc/dns_records",
        );
    }

    #[test]
    fn cloudflare_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "docker ps");
    }
}

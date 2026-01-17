//! Fastly CDN pack - protections for destructive Fastly CLI operations.
//!
//! Covers destructive operations:
//! - Service deletion (`fastly service delete`)
//! - Domain deletion (`fastly domain delete`)
//! - Backend deletion (`fastly backend delete`)
//! - VCL deletion (`fastly vcl delete`)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Fastly CDN pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cdn.fastly".to_string(),
        name: "Fastly CDN",
        description: "Protects against destructive Fastly CLI operations like service, domain, \
                      backend, and VCL deletion.",
        keywords: &["fastly"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Service list/describe
        safe_pattern!("fastly-service-list", r"fastly\s+service\s+list\b"),
        safe_pattern!("fastly-service-describe", r"fastly\s+service\s+describe\b"),
        safe_pattern!("fastly-service-search", r"fastly\s+service\s+search\b"),
        // Domain list
        safe_pattern!("fastly-domain-list", r"fastly\s+domain\s+list\b"),
        safe_pattern!("fastly-domain-describe", r"fastly\s+domain\s+describe\b"),
        // Backend list
        safe_pattern!("fastly-backend-list", r"fastly\s+backend\s+list\b"),
        safe_pattern!("fastly-backend-describe", r"fastly\s+backend\s+describe\b"),
        // VCL list/show
        safe_pattern!("fastly-vcl-list", r"fastly\s+vcl\s+list\b"),
        safe_pattern!("fastly-vcl-describe", r"fastly\s+vcl\s+describe\b"),
        // Version list
        safe_pattern!("fastly-version-list", r"fastly\s+version\s+list\b"),
        // Account/profile
        safe_pattern!("fastly-whoami", r"fastly\s+whoami\b"),
        safe_pattern!("fastly-profile", r"fastly\s+profile\b"),
        // Version/help
        safe_pattern!("fastly-version", r"fastly\s+(?:-v|--version|version)\b"),
        safe_pattern!("fastly-help", r"fastly\s+(?:-h|--help|help)\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Service deletion
        destructive_pattern!(
            "fastly-service-delete",
            r"fastly\s+service\s+delete\b",
            "fastly service delete removes a Fastly service entirely."
        ),
        // Domain deletion
        destructive_pattern!(
            "fastly-domain-delete",
            r"fastly\s+domain\s+delete\b",
            "fastly domain delete removes a domain from a service."
        ),
        // Backend deletion
        destructive_pattern!(
            "fastly-backend-delete",
            r"fastly\s+backend\s+delete\b",
            "fastly backend delete removes a backend origin server."
        ),
        // VCL deletion
        destructive_pattern!(
            "fastly-vcl-delete",
            r"fastly\s+vcl\s+delete\b",
            "fastly vcl delete removes VCL configuration."
        ),
        // Dictionary deletion
        destructive_pattern!(
            "fastly-dictionary-delete",
            r"fastly\s+dictionary\s+delete\b",
            "fastly dictionary delete removes an edge dictionary."
        ),
        // Dictionary item deletion
        destructive_pattern!(
            "fastly-dictionary-item-delete",
            r"fastly\s+dictionary-item\s+delete\b",
            "fastly dictionary-item delete removes dictionary entries."
        ),
        // ACL deletion
        destructive_pattern!(
            "fastly-acl-delete",
            r"fastly\s+acl\s+delete\b",
            "fastly acl delete removes an access control list."
        ),
        // ACL entry deletion
        destructive_pattern!(
            "fastly-acl-entry-delete",
            r"fastly\s+acl-entry\s+delete\b",
            "fastly acl-entry delete removes ACL entries."
        ),
        // Logging endpoint deletion
        destructive_pattern!(
            "fastly-logging-delete",
            r"fastly\s+logging\s+\S+\s+delete\b",
            "fastly logging delete removes logging endpoints."
        ),
        // Service version activation (can cause outages)
        destructive_pattern!(
            "fastly-version-activate",
            r"fastly\s+service\s+version\s+activate\b",
            "fastly service version activate can cause service disruption if misconfigured."
        ),
        // Compute package deletion
        destructive_pattern!(
            "fastly-compute-delete",
            r"fastly\s+compute\s+delete\b",
            "fastly compute delete removes compute package."
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
        assert_eq!(pack.id, "cdn.fastly");
        assert_eq!(pack.name, "Fastly CDN");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"fastly"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Service operations
        assert_safe_pattern_matches(&pack, "fastly service list");
        assert_safe_pattern_matches(&pack, "fastly service describe --service-id abc123");
        assert_safe_pattern_matches(&pack, "fastly service search --name myservice");
        // Domain operations
        assert_safe_pattern_matches(&pack, "fastly domain list");
        assert_safe_pattern_matches(&pack, "fastly domain describe --name example.com");
        // Backend operations
        assert_safe_pattern_matches(&pack, "fastly backend list");
        assert_safe_pattern_matches(&pack, "fastly backend describe --name origin");
        // VCL operations
        assert_safe_pattern_matches(&pack, "fastly vcl list");
        assert_safe_pattern_matches(&pack, "fastly vcl describe --name main");
        // Version operations
        assert_safe_pattern_matches(&pack, "fastly version list");
        // Account info
        assert_safe_pattern_matches(&pack, "fastly whoami");
        assert_safe_pattern_matches(&pack, "fastly profile list");
        // Version/help
        assert_safe_pattern_matches(&pack, "fastly --version");
        assert_safe_pattern_matches(&pack, "fastly -v");
        assert_safe_pattern_matches(&pack, "fastly --help");
        assert_safe_pattern_matches(&pack, "fastly help");
    }

    #[test]
    fn blocks_service_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly service delete --service-id abc123",
            "fastly-service-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "fastly service delete --force",
            "fastly-service-delete",
        );
    }

    #[test]
    fn blocks_domain_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly domain delete --name example.com",
            "fastly-domain-delete",
        );
    }

    #[test]
    fn blocks_backend_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly backend delete --name origin-server",
            "fastly-backend-delete",
        );
    }

    #[test]
    fn blocks_vcl_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "fastly vcl delete --name main", "fastly-vcl-delete");
    }

    #[test]
    fn blocks_dictionary_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly dictionary delete --name config",
            "fastly-dictionary-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "fastly dictionary-item delete --dictionary-id abc --key foo",
            "fastly-dictionary-item-delete",
        );
    }

    #[test]
    fn blocks_acl_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly acl delete --name blocklist",
            "fastly-acl-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "fastly acl-entry delete --acl-id abc --id xyz",
            "fastly-acl-entry-delete",
        );
    }

    #[test]
    fn blocks_logging_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly logging s3 delete --name logs",
            "fastly-logging-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "fastly logging bigquery delete --name analytics",
            "fastly-logging-delete",
        );
    }

    #[test]
    fn blocks_version_activate() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "fastly service version activate --version 5",
            "fastly-version-activate",
        );
    }

    #[test]
    fn blocks_compute_delete() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "fastly compute delete", "fastly-compute-delete");
    }
}

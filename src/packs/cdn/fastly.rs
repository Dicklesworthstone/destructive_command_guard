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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Service list/describe
        safe_pattern!(
            "fastly-service-list",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-service-describe",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+describe(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-service-search",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+search(?=\s|$)"
        ),
        // Domain list
        safe_pattern!(
            "fastly-domain-list",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+domain\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-domain-describe",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+domain\s+describe(?=\s|$)"
        ),
        // Backend list
        safe_pattern!(
            "fastly-backend-list",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+backend\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-backend-describe",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+backend\s+describe(?=\s|$)"
        ),
        // VCL list/show
        safe_pattern!(
            "fastly-vcl-list",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+vcl\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-vcl-describe",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+vcl\s+describe(?=\s|$)"
        ),
        // Version list
        safe_pattern!(
            "fastly-version-list",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+version\s+list(?=\s|$)"
        ),
        // Account/profile
        safe_pattern!(
            "fastly-whoami",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-profile",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+profile(?=\s|$)"
        ),
        // Version/help
        safe_pattern!(
            "fastly-version",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-v|--version|version)(?=\s|$)"
        ),
        safe_pattern!(
            "fastly-help",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-h|--help|help)(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Service deletion
        destructive_pattern!(
            "fastly-service-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+delete\b",
            "fastly service delete removes a Fastly service entirely.",
            Critical,
            "Deleting a Fastly service removes ALL associated domains, backends, VCL, \
             dictionaries, ACLs, and logging configurations. All traffic to this service \
             will immediately fail. Service IDs cannot be reused after deletion.\n\n\
             Safer alternatives:\n\
             - fastly service describe: Review service configuration first\n\
             - Export VCL and configuration for backup\n\
             - Remove domains before deleting to confirm no active traffic"
        ),
        // Domain deletion
        destructive_pattern!(
            "fastly-domain-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+domain\s+delete\b",
            "fastly domain delete removes a domain from a service.",
            High,
            "Removing a domain from a Fastly service immediately stops CDN handling \
             for that domain. Traffic will either fail or fall back to the origin \
             directly, bypassing caching and edge features.\n\n\
             Safer alternatives:\n\
             - fastly domain list: Review all domains on the service\n\
             - Update DNS before removing from Fastly\n\
             - Test with a staging domain first"
        ),
        // Backend deletion
        destructive_pattern!(
            "fastly-backend-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+backend\s+delete\b",
            "fastly backend delete removes a backend origin server.",
            High,
            "Deleting a backend removes an origin server from the service. If VCL or \
             routing rules reference this backend, requests will fail with 503 errors. \
             Health checks and shield configuration are also removed.\n\n\
             Safer alternatives:\n\
             - fastly backend describe: Review backend configuration\n\
             - Update VCL to stop routing to this backend first\n\
             - Add replacement backend before removing the old one"
        ),
        // VCL deletion
        destructive_pattern!(
            "fastly-vcl-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+vcl\s+delete\b",
            "fastly vcl delete removes VCL configuration.",
            High,
            "Deleting VCL removes custom edge logic including routing, caching rules, \
             header manipulation, and security policies. The service may fall back to \
             default behavior or fail if the deleted VCL was the main configuration.\n\n\
             Safer alternatives:\n\
             - fastly vcl describe: Download VCL content first\n\
             - Keep VCL in version control\n\
             - Create new version before deleting from old"
        ),
        // Dictionary deletion
        destructive_pattern!(
            "fastly-dictionary-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+dictionary\s+delete\b",
            "fastly dictionary delete removes an edge dictionary.",
            High,
            "Deleting an edge dictionary removes key-value configuration data used by \
             VCL. If VCL references this dictionary for routing, feature flags, or \
             blocklists, those lookups will fail causing request errors.\n\n\
             Safer alternatives:\n\
             - fastly dictionary-item list: Export dictionary contents\n\
             - Update VCL to remove dictionary references first\n\
             - Create replacement dictionary before deleting"
        ),
        // Dictionary item deletion
        destructive_pattern!(
            "fastly-dictionary-item-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+dictionary-item\s+delete\b",
            "fastly dictionary-item delete removes dictionary entries.",
            Medium,
            "Deleting dictionary items removes edge configuration values. VCL lookups \
             for deleted keys will return empty strings, potentially affecting routing, \
             redirects, or feature flag logic.\n\n\
             Safer alternatives:\n\
             - Review which VCL snippets use this dictionary\n\
             - Set values to empty instead of deleting if VCL expects the key\n\
             - Back up dictionary contents before modifications"
        ),
        // ACL deletion
        destructive_pattern!(
            "fastly-acl-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+acl\s+delete\b",
            "fastly acl delete removes an access control list.",
            High,
            "Deleting an ACL removes IP allowlist or blocklist configuration. Security \
             rules referencing this ACL will no longer match, potentially exposing \
             protected resources or breaking geo-restriction logic.\n\n\
             Safer alternatives:\n\
             - fastly acl-entry list: Export ACL entries first\n\
             - Update VCL to remove ACL references\n\
             - Create replacement ACL before deleting"
        ),
        // ACL entry deletion
        destructive_pattern!(
            "fastly-acl-entry-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+acl-entry\s+delete\b",
            "fastly acl-entry delete removes ACL entries.",
            Medium,
            "Removing ACL entries changes IP matching behavior. Removing an IP from a \
             blocklist allows that IP to access the service. Removing from an allowlist \
             blocks that IP.\n\n\
             Safer alternatives:\n\
             - Review the ACL purpose (allow vs block list)\n\
             - Verify the entry change with the security team\n\
             - Document why the entry is being removed"
        ),
        // Logging endpoint deletion
        destructive_pattern!(
            "fastly-logging-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+logging\s+\S+\s+delete\b",
            "fastly logging delete removes logging endpoints.",
            High,
            "Deleting a logging endpoint stops log delivery to that destination. You \
             will lose visibility into edge traffic, errors, and security events. \
             Compliance and debugging capabilities are affected.\n\n\
             Safer alternatives:\n\
             - Ensure alternative logging is configured\n\
             - Export endpoint configuration for backup\n\
             - Disable endpoint before full deletion"
        ),
        // Service version activation (can cause outages)
        destructive_pattern!(
            "fastly-version-activate",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+version\s+activate\b",
            "fastly service version activate can cause service disruption if misconfigured.",
            High,
            "Activating a service version immediately deploys that configuration to all \
             edge nodes. Misconfigured VCL, missing backends, or broken routing rules \
             will cause immediate outages affecting all traffic.\n\n\
             Safer alternatives:\n\
             - fastly vcl validate: Validate VCL syntax first\n\
             - Use fastly diff to compare with current active version\n\
             - Test in a staging service before production activation"
        ),
        // Compute package deletion
        destructive_pattern!(
            "fastly-compute-delete",
            r"fastly(?:\s+--?\S+(?:\s+\S+)?)*\s+compute\s+delete\b",
            "fastly compute delete removes compute package.",
            Critical,
            "Deleting a Compute@Edge package removes your WASM application from the \
             service. All serverless edge compute functionality stops immediately. \
             The package must be rebuilt and redeployed to restore functionality.\n\n\
             Safer alternatives:\n\
             - Keep package source in version control\n\
             - Deploy replacement package before deleting\n\
             - Use fastly compute describe to review current state"
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

    #[test]
    fn global_flags_do_not_bypass() {
        let pack = create_pack();
        // Fastly CLI accepts --token, --endpoint, --verbose, --api-timeout, etc.
        // before the subcommand. Structured flag-aware pattern must match.
        assert_blocks_with_pattern(
            &pack,
            "fastly --token abc service delete --service-id xyz",
            "fastly-service-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "fastly --verbose --endpoint https://api.fastly.com vcl delete --name main",
            "fastly-vcl-delete",
        );
        assert!(
            pack.check("fastly --token abc service list").is_none(),
            "safe list with token flag should remain safe"
        );
    }
}

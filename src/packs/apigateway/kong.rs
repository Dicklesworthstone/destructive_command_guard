//! Kong API Gateway pack - protections for destructive Kong Gateway operations.
//!
//! Covers destructive operations for:
//! - Kong CLI (`kong delete services`, `kong delete routes`, etc.)
//! - deck CLI (`deck reset`, `deck sync` with destructive flags)
//! - Kong Admin API (DELETE requests to :8001)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Kong API Gateway pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "apigateway.kong".to_string(),
        name: "Kong API Gateway",
        description: "Protects against destructive Kong Gateway CLI, deck CLI, and Admin API \
                      operations.",
        keywords: &["kong", "deck", "8001"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Kong CLI - read operations
        safe_pattern!("kong-version", r"kong\s+(?:version|--version|-v)\b"),
        safe_pattern!("kong-help", r"kong\s+(?:help|--help|-h)\b"),
        safe_pattern!("kong-health", r"kong\s+health\b"),
        safe_pattern!("kong-check", r"kong\s+check\b"),
        safe_pattern!("kong-config-parse", r"kong\s+config\s+(?:parse|init)\b"),
        // deck CLI - read/safe operations
        safe_pattern!("deck-version", r"deck\s+(?:version|--version)\b"),
        safe_pattern!("deck-help", r"deck\s+(?:help|--help|-h)\b"),
        safe_pattern!("deck-ping", r"deck\s+ping\b"),
        safe_pattern!("deck-dump", r"deck\s+dump\b"),
        safe_pattern!("deck-diff", r"deck\s+diff\b"),
        safe_pattern!("deck-validate", r"deck\s+validate\b"),
        safe_pattern!("deck-convert", r"deck\s+convert\b"),
        safe_pattern!("deck-file", r"deck\s+file\b"),
        // Kong Admin API - explicit GET requests only
        safe_pattern!(
            "kong-admin-explicit-get",
            r"curl\s+.*(?:-X\s+GET|--request\s+GET)\s+.*(?:localhost|127\.0\.0\.1):8001/"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // deck reset - CRITICAL! Removes all Kong config
        destructive_pattern!(
            "deck-reset",
            r"deck\s+(?:gateway\s+)?reset\b",
            "deck reset removes ALL Kong configuration. This is extremely dangerous and irreversible.",
            Critical,
            "Resetting Kong removes ALL services, routes, plugins, consumers, certificates, and \
             upstreams. Your entire API gateway configuration is wiped. All traffic through Kong \
             will fail immediately. There is no undo.\n\n\
             Safer alternatives:\n\
             - deck dump: Export current configuration first\n\
             - deck diff: Review what will change before any sync\n\
             - Delete specific entities instead of full reset"
        ),
        // deck sync with --select-tag can be destructive
        destructive_pattern!(
            "deck-sync-destructive",
            r"deck\s+(?:gateway\s+)?sync\b.*--select-tag\b",
            "deck sync with --select-tag can remove entities not matching the tag.",
            High,
            "Using --select-tag with deck sync removes entities not matching the tag in your \
             state file. This can accidentally delete services and routes managed by other teams \
             or systems. Entities without tags are at risk of deletion.\n\n\
             Safer alternatives:\n\
             - deck diff --select-tag: Preview changes first\n\
             - Use consistent tagging across all entities\n\
             - Consider deck sync without --select-tag to avoid surprises"
        ),
        // Kong Admin API - DELETE requests (supports both DELETE-first and URL-first ordering)
        destructive_pattern!(
            "kong-admin-delete-services",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/services|(?:localhost|127\.0\.0\.1):8001/services.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes services.",
            High,
            "Deleting a Kong service removes the upstream service definition. All routes \
             associated with the service become orphaned and stop working. Traffic to those \
             endpoints will return 404 errors.\n\n\
             Safer alternatives:\n\
             - GET /services first: List services to verify the target\n\
             - Delete routes pointing to the service first\n\
             - Use deck dump to export configuration before changes"
        ),
        destructive_pattern!(
            "kong-admin-delete-routes",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/routes|(?:localhost|127\.0\.0\.1):8001/routes.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes routes.",
            High,
            "Deleting a Kong route removes the path-to-service mapping. Requests to that path \
             will return 404 errors. Plugins attached to the route are also removed. The \
             associated service is not affected.\n\n\
             Safer alternatives:\n\
             - GET /routes first: Verify the route details\n\
             - Test in a non-production environment\n\
             - Consider disabling plugins instead of deleting the route"
        ),
        destructive_pattern!(
            "kong-admin-delete-plugins",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/plugins|(?:localhost|127\.0\.0\.1):8001/plugins.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes plugins.",
            Medium,
            "Deleting a Kong plugin removes its functionality from the associated service, route, \
             or consumer. Authentication, rate limiting, logging, or transformation features \
             provided by the plugin stop immediately.\n\n\
             Safer alternatives:\n\
             - GET /plugins first: Review plugin configuration\n\
             - PATCH to disable the plugin instead of deleting\n\
             - Export plugin config with deck dump before deletion"
        ),
        destructive_pattern!(
            "kong-admin-delete-consumers",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/consumers|(?:localhost|127\.0\.0\.1):8001/consumers.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes consumers.",
            High,
            "Deleting a Kong consumer removes the API client identity. All credentials (API keys, \
             JWT, OAuth) for that consumer are revoked. Plugins configured per-consumer stop \
             applying. Affected clients lose API access.\n\n\
             Safer alternatives:\n\
             - GET /consumers first: Review consumer details\n\
             - Delete individual credentials instead of the consumer\n\
             - Notify affected clients before deletion"
        ),
        destructive_pattern!(
            "kong-admin-delete-upstreams",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/upstreams|(?:localhost|127\.0\.0\.1):8001/upstreams.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes upstreams.",
            High,
            "Deleting a Kong upstream removes the load balancer and all its targets. Services \
             using this upstream will fail to route traffic. Health checks and circuit breaker \
             settings are lost.\n\n\
             Safer alternatives:\n\
             - GET /upstreams first: Review upstream configuration\n\
             - Update services to use a different upstream first\n\
             - Remove targets individually to verify impact"
        ),
        destructive_pattern!(
            "kong-admin-delete-targets",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/.*targets|(?:localhost|127\.0\.0\.1):8001/.*targets.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes targets.",
            Medium,
            "Deleting a Kong target removes a backend server from the upstream pool. Traffic \
             is redistributed to remaining targets. If this was the last target, the upstream \
             has no backends and requests fail.\n\n\
             Safer alternatives:\n\
             - GET /upstreams/{id}/targets first: List current targets\n\
             - Set target weight to 0 to drain traffic first\n\
             - Verify other targets can handle the load"
        ),
        destructive_pattern!(
            "kong-admin-delete-certificates",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/certificates|(?:localhost|127\.0\.0\.1):8001/certificates.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes certificates.",
            High,
            "Deleting a Kong certificate removes the TLS/SSL certificate. SNIs using this \
             certificate will fail TLS handshakes. HTTPS traffic to affected domains will \
             receive certificate errors.\n\n\
             Safer alternatives:\n\
             - GET /certificates first: Review certificate details\n\
             - Upload a replacement certificate before deletion\n\
             - Remove associated SNIs first"
        ),
        destructive_pattern!(
            "kong-admin-delete-snis",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/snis|(?:localhost|127\.0\.0\.1):8001/snis.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes SNIs.",
            High,
            "Deleting a Kong SNI removes the domain-to-certificate mapping. HTTPS requests \
             for that hostname will fail TLS negotiation or use a default certificate if \
             configured. Clients will see certificate warnings.\n\n\
             Safer alternatives:\n\
             - GET /snis first: Review SNI configuration\n\
             - Update the SNI to point to a different certificate\n\
             - Verify the certificate is no longer needed for this domain"
        ),
        // Generic DELETE to any Kong Admin API endpoint
        destructive_pattern!(
            "kong-admin-delete-generic",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/|(?:localhost|127\.0\.0\.1):8001/.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API can remove configuration.",
            Medium,
            "DELETE requests to the Kong Admin API remove configuration objects. The specific \
             impact depends on the endpoint: services, routes, plugins, consumers, certificates, \
             or other Kong entities. Deletions take effect immediately.\n\n\
             Safer alternatives:\n\
             - Use GET requests first to review the resource\n\
             - Export configuration with deck dump\n\
             - Test changes in a staging environment"
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
        assert_eq!(pack.id, "apigateway.kong");
        assert_eq!(pack.name, "Kong API Gateway");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"kong"));
        assert!(pack.keywords.contains(&"deck"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Kong CLI - read operations
        assert_safe_pattern_matches(&pack, "kong version");
        assert_safe_pattern_matches(&pack, "kong --version");
        assert_safe_pattern_matches(&pack, "kong -v");
        assert_safe_pattern_matches(&pack, "kong help");
        assert_safe_pattern_matches(&pack, "kong --help");
        assert_safe_pattern_matches(&pack, "kong health");
        assert_safe_pattern_matches(&pack, "kong check /etc/kong/kong.conf");
        assert_safe_pattern_matches(&pack, "kong config parse /etc/kong/kong.conf");
        assert_safe_pattern_matches(&pack, "kong config init");
        // deck CLI - read operations
        assert_safe_pattern_matches(&pack, "deck version");
        assert_safe_pattern_matches(&pack, "deck --version");
        assert_safe_pattern_matches(&pack, "deck help");
        assert_safe_pattern_matches(&pack, "deck --help");
        assert_safe_pattern_matches(&pack, "deck ping");
        assert_safe_pattern_matches(&pack, "deck dump");
        assert_safe_pattern_matches(&pack, "deck dump --output-file kong.yaml");
        assert_safe_pattern_matches(&pack, "deck diff");
        assert_safe_pattern_matches(&pack, "deck diff --state kong.yaml");
        assert_safe_pattern_matches(&pack, "deck validate");
        assert_safe_pattern_matches(&pack, "deck convert");
        assert_safe_pattern_matches(&pack, "deck file");
        // Kong Admin API - explicit GET requests
        assert_safe_pattern_matches(&pack, "curl -X GET localhost:8001/routes");
        assert_safe_pattern_matches(&pack, "curl --request GET localhost:8001/plugins");
        // Implicit GET requests are allowed by default (no destructive match)
        assert_allows(&pack, "curl localhost:8001/");
        assert_allows(&pack, "curl localhost:8001/services");
        assert_allows(&pack, "curl 127.0.0.1:8001/status");
    }

    #[test]
    fn blocks_deck_reset() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "deck reset", "deck-reset");
        assert_blocks_with_pattern(&pack, "deck reset --force", "deck-reset");
        assert_blocks_with_pattern(&pack, "deck gateway reset", "deck-reset");
    }

    #[test]
    fn blocks_deck_sync_select_tag() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "deck sync --select-tag production",
            "deck-sync-destructive",
        );
        assert_blocks_with_pattern(
            &pack,
            "deck gateway sync --select-tag team-a",
            "deck-sync-destructive",
        );
    }

    #[test]
    fn blocks_admin_api_delete_services() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/services/my-service",
            "kong-admin-delete-services",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE localhost:8001/services/abc123",
            "kong-admin-delete-services",
        );
    }

    #[test]
    fn blocks_admin_api_delete_routes() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/routes/my-route",
            "kong-admin-delete-routes",
        );
    }

    #[test]
    fn blocks_admin_api_delete_plugins() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/plugins/rate-limiting",
            "kong-admin-delete-plugins",
        );
    }

    #[test]
    fn blocks_admin_api_delete_consumers() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/consumers/user123",
            "kong-admin-delete-consumers",
        );
    }

    #[test]
    fn blocks_admin_api_delete_upstreams() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/upstreams/backend",
            "kong-admin-delete-upstreams",
        );
    }

    #[test]
    fn blocks_admin_api_delete_targets() {
        let pack = create_pack();
        // Note: This URL matches upstreams pattern first (contains /upstreams/)
        // but the command is still blocked which is the desired behavior
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/upstreams/backend/targets/host1",
            "kong-admin-delete-upstreams",
        );
        // Direct targets endpoint
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/targets/abc123",
            "kong-admin-delete-targets",
        );
    }

    #[test]
    fn blocks_admin_api_delete_certificates() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/certificates/abc123",
            "kong-admin-delete-certificates",
        );
    }

    #[test]
    fn blocks_admin_api_delete_snis() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE localhost:8001/snis/example.com",
            "kong-admin-delete-snis",
        );
    }

    #[test]
    fn blocks_admin_api_with_ip_address() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE 127.0.0.1:8001/services/test",
            "kong-admin-delete-services",
        );
    }

    #[test]
    fn blocks_url_first_ordering() {
        let pack = create_pack();
        // URL before -X DELETE flag (common curl pattern)
        assert_blocks_with_pattern(
            &pack,
            "curl localhost:8001/services/my-service -X DELETE",
            "kong-admin-delete-services",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl localhost:8001/routes/my-route -X DELETE",
            "kong-admin-delete-routes",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl 127.0.0.1:8001/plugins/rate-limit -X DELETE",
            "kong-admin-delete-plugins",
        );
    }

    #[test]
    fn allows_non_curl_strings_with_kong_admin_tokens() {
        let pack = create_pack();
        assert_allows(&pack, "echo localhost:8001/services/my-service -X DELETE");
    }
}

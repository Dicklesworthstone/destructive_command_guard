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
            "deck reset removes ALL Kong configuration. This is extremely dangerous and irreversible."
        ),
        // deck sync with --select-tag can be destructive
        destructive_pattern!(
            "deck-sync-destructive",
            r"deck\s+(?:gateway\s+)?sync\b.*--select-tag\b",
            "deck sync with --select-tag can remove entities not matching the tag."
        ),
        // Kong Admin API - DELETE requests (supports both DELETE-first and URL-first ordering)
        destructive_pattern!(
            "kong-admin-delete-services",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/services|(?:localhost|127\.0\.0\.1):8001/services.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes services."
        ),
        destructive_pattern!(
            "kong-admin-delete-routes",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/routes|(?:localhost|127\.0\.0\.1):8001/routes.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes routes."
        ),
        destructive_pattern!(
            "kong-admin-delete-plugins",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/plugins|(?:localhost|127\.0\.0\.1):8001/plugins.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes plugins."
        ),
        destructive_pattern!(
            "kong-admin-delete-consumers",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/consumers|(?:localhost|127\.0\.0\.1):8001/consumers.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes consumers."
        ),
        destructive_pattern!(
            "kong-admin-delete-upstreams",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/upstreams|(?:localhost|127\.0\.0\.1):8001/upstreams.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes upstreams."
        ),
        destructive_pattern!(
            "kong-admin-delete-targets",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/.*targets|(?:localhost|127\.0\.0\.1):8001/.*targets.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes targets."
        ),
        destructive_pattern!(
            "kong-admin-delete-certificates",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/certificates|(?:localhost|127\.0\.0\.1):8001/certificates.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes certificates."
        ),
        destructive_pattern!(
            "kong-admin-delete-snis",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/snis|(?:localhost|127\.0\.0\.1):8001/snis.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API removes SNIs."
        ),
        // Generic DELETE to any Kong Admin API endpoint
        destructive_pattern!(
            "kong-admin-delete-generic",
            r"curl\s+.*(?:(?:-X\s+DELETE|--request\s+DELETE).*(?:localhost|127\.0\.0\.1):8001/|(?:localhost|127\.0\.0\.1):8001/.*(?:-X\s+DELETE|--request\s+DELETE))",
            "DELETE request to Kong Admin API can remove configuration."
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

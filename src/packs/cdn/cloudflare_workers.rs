//! Cloudflare Workers pack - protections for destructive Wrangler CLI operations.
//!
//! Covers destructive operations:
//! - Worker deletion (`wrangler delete`)
//! - Deployment rollback (`wrangler deployments rollback`)
//! - KV operations (namespace/key/bulk delete)
//! - R2 operations (bucket/object delete)
//! - D1 database deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Cloudflare Workers pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cdn.cloudflare_workers".to_string(),
        name: "Cloudflare Workers",
        description: "Protects against destructive Cloudflare Workers, KV, R2, and D1 operations \
                      via the Wrangler CLI.",
        keywords: &["wrangler"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Account/auth info
        safe_pattern!("wrangler-whoami", r"wrangler\s+whoami\b"),
        // KV read operations
        safe_pattern!("wrangler-kv-get", r"wrangler\s+kv:key\s+get\b"),
        safe_pattern!("wrangler-kv-list", r"wrangler\s+kv:key\s+list\b"),
        safe_pattern!(
            "wrangler-kv-namespace-list",
            r"wrangler\s+kv:namespace\s+list\b"
        ),
        // R2 read operations
        safe_pattern!("wrangler-r2-object-get", r"wrangler\s+r2\s+object\s+get\b"),
        safe_pattern!(
            "wrangler-r2-bucket-list",
            r"wrangler\s+r2\s+bucket\s+list\b"
        ),
        // D1 read operations
        safe_pattern!("wrangler-d1-list", r"wrangler\s+d1\s+list\b"),
        safe_pattern!("wrangler-d1-info", r"wrangler\s+d1\s+info\b"),
        // Development/debugging
        safe_pattern!("wrangler-dev", r"wrangler\s+dev\b"),
        safe_pattern!("wrangler-tail", r"wrangler\s+tail\b"),
        // Version/help
        safe_pattern!("wrangler-version", r"wrangler\s+(?:-v|--version|version)\b"),
        safe_pattern!("wrangler-help", r"wrangler\s+(?:-h|--help|help)\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Worker deletion
        destructive_pattern!(
            "wrangler-delete",
            r"wrangler\s+delete\b",
            "wrangler delete removes a Worker from Cloudflare."
        ),
        // Deployment rollback (can break things)
        destructive_pattern!(
            "wrangler-deployments-rollback",
            r"wrangler\s+deployments\s+rollback\b",
            "wrangler deployments rollback reverts to a previous Worker version."
        ),
        // KV destructive operations
        destructive_pattern!(
            "wrangler-kv-key-delete",
            r"wrangler\s+kv:key\s+delete\b",
            "wrangler kv:key delete removes a key from KV storage."
        ),
        destructive_pattern!(
            "wrangler-kv-namespace-delete",
            r"wrangler\s+kv:namespace\s+delete\b",
            "wrangler kv:namespace delete removes an entire KV namespace."
        ),
        destructive_pattern!(
            "wrangler-kv-bulk-delete",
            r"wrangler\s+kv:bulk\s+delete\b",
            "wrangler kv:bulk delete removes multiple keys from KV storage."
        ),
        // R2 destructive operations
        destructive_pattern!(
            "wrangler-r2-object-delete",
            r"wrangler\s+r2\s+object\s+delete\b",
            "wrangler r2 object delete removes an object from R2 storage."
        ),
        destructive_pattern!(
            "wrangler-r2-bucket-delete",
            r"wrangler\s+r2\s+bucket\s+delete\b",
            "wrangler r2 bucket delete removes an entire R2 bucket."
        ),
        // D1 destructive operations
        destructive_pattern!(
            "wrangler-d1-delete",
            r"wrangler\s+d1\s+delete\b",
            "wrangler d1 delete removes a D1 database."
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
        assert_eq!(pack.id, "cdn.cloudflare_workers");
        assert_eq!(pack.name, "Cloudflare Workers");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"wrangler"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Account info
        assert_safe_pattern_matches(&pack, "wrangler whoami");
        // KV read
        assert_safe_pattern_matches(&pack, "wrangler kv:key get --namespace-id=abc KEY");
        assert_safe_pattern_matches(&pack, "wrangler kv:key list --namespace-id=abc");
        assert_safe_pattern_matches(&pack, "wrangler kv:namespace list");
        // R2 read
        assert_safe_pattern_matches(&pack, "wrangler r2 object get my-bucket/path/to/obj");
        assert_safe_pattern_matches(&pack, "wrangler r2 bucket list");
        // D1 read
        assert_safe_pattern_matches(&pack, "wrangler d1 list");
        assert_safe_pattern_matches(&pack, "wrangler d1 info my-db");
        // Dev/debug
        assert_safe_pattern_matches(&pack, "wrangler dev");
        assert_safe_pattern_matches(&pack, "wrangler tail");
        // Version/help
        assert_safe_pattern_matches(&pack, "wrangler --version");
        assert_safe_pattern_matches(&pack, "wrangler -v");
        assert_safe_pattern_matches(&pack, "wrangler help");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Worker deletion
        assert_blocks_with_pattern(&pack, "wrangler delete", "wrangler-delete");
        assert_blocks_with_pattern(&pack, "wrangler delete my-worker", "wrangler-delete");
        // Deployments
        assert_blocks_with_pattern(
            &pack,
            "wrangler deployments rollback",
            "wrangler-deployments-rollback",
        );
        // KV
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:key delete --namespace-id=abc KEY",
            "wrangler-kv-key-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:namespace delete --namespace-id=abc",
            "wrangler-kv-namespace-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler kv:bulk delete --namespace-id=abc keys.json",
            "wrangler-kv-bulk-delete",
        );
        // R2
        assert_blocks_with_pattern(
            &pack,
            "wrangler r2 object delete bucket/key",
            "wrangler-r2-object-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler r2 bucket delete my-bucket",
            "wrangler-r2-bucket-delete",
        );
        // D1
        assert_blocks_with_pattern(&pack, "wrangler d1 delete my-db", "wrangler-d1-delete");
    }
}

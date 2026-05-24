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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Account/auth info
        safe_pattern!(
            "wrangler-whoami",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s|$)"
        ),
        // KV read operations
        safe_pattern!(
            "wrangler-kv-get",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv:key\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-kv-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv:key\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-kv-namespace-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv:namespace\s+list(?=\s|$)"
        ),
        // R2 read operations
        safe_pattern!(
            "wrangler-r2-object-get",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+object\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-r2-bucket-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+bucket\s+list(?=\s|$)"
        ),
        // D1 read operations
        safe_pattern!(
            "wrangler-d1-list",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+d1\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-d1-info",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+d1\s+info(?=\s|$)"
        ),
        // Development/debugging
        safe_pattern!(
            "wrangler-dev",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+dev(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-tail",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+tail(?=\s|$)"
        ),
        // Version/help
        safe_pattern!(
            "wrangler-version",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-v|--version|version)(?=\s|$)"
        ),
        safe_pattern!(
            "wrangler-help",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-h|--help|help)(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Worker deletion
        destructive_pattern!(
            "wrangler-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "wrangler delete removes a Worker from Cloudflare.",
            Critical,
            "Deleting a Cloudflare Worker immediately stops all edge processing for that \
             Worker. Any routes pointing to it will return errors. Custom domains and \
             bindings (KV, R2, D1) associated with the Worker remain but become orphaned.\n\n\
             Safer alternatives:\n\
             - wrangler deployments list: Review deployment history first\n\
             - Disable routes instead of deleting the Worker\n\
             - Use wrangler tail to verify traffic before deletion"
        ),
        // Deployment rollback (can break things)
        destructive_pattern!(
            "wrangler-deployments-rollback",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+deployments\s+rollback\b",
            "wrangler deployments rollback reverts to a previous Worker version.",
            High,
            "Rolling back a deployment replaces your current Worker code with a previous \
             version. This can reintroduce bugs, break API compatibility, or cause issues \
             if the previous version relies on removed bindings or environment variables.\n\n\
             Safer alternatives:\n\
             - wrangler deployments list: Review available versions first\n\
             - Test the target version in a staging environment\n\
             - Deploy a fix forward instead of rolling back"
        ),
        // KV destructive operations
        destructive_pattern!(
            "wrangler-kv-key-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv:key\s+delete\b",
            "wrangler kv:key delete removes a key from KV storage.",
            Medium,
            "Deleting a KV key immediately removes the data at all edge locations. \
             Applications reading this key will receive null or errors. KV deletions \
             propagate globally within seconds.\n\n\
             Safer alternatives:\n\
             - wrangler kv:key get: Retrieve and backup the value first\n\
             - Set an expiration instead of deleting for temporary data\n\
             - Use KV namespaces for environment separation"
        ),
        destructive_pattern!(
            "wrangler-kv-namespace-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv:namespace\s+delete\b",
            "wrangler kv:namespace delete removes an entire KV namespace.",
            Critical,
            "Deleting a KV namespace permanently removes ALL keys and values within it. \
             Any Workers bound to this namespace will fail when accessing KV. This cannot \
             be undone and all data is lost.\n\n\
             Safer alternatives:\n\
             - wrangler kv:key list: Inventory all keys first\n\
             - Export data before deletion\n\
             - Remove Worker bindings before deleting the namespace"
        ),
        destructive_pattern!(
            "wrangler-kv-bulk-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+kv:bulk\s+delete\b",
            "wrangler kv:bulk delete removes multiple keys from KV storage.",
            High,
            "Bulk delete removes many KV keys at once based on a JSON file. This is \
             efficient but dangerous - a malformed keys file can delete unintended data. \
             All deletions are immediate and irreversible.\n\n\
             Safer alternatives:\n\
             - Review the keys JSON file carefully before execution\n\
             - Test with a single wrangler kv:key delete first\n\
             - Back up affected keys before bulk deletion"
        ),
        // R2 destructive operations
        destructive_pattern!(
            "wrangler-r2-object-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+object\s+delete\b",
            "wrangler r2 object delete removes an object from R2 storage.",
            Medium,
            "Deleting an R2 object permanently removes the file from storage. Any URLs \
             or Workers accessing this object will receive 404 errors. Unlike S3, R2 does \
             not charge for delete operations but data is unrecoverable.\n\n\
             Safer alternatives:\n\
             - wrangler r2 object get: Download the object first\n\
             - Use object lifecycle rules for automatic expiration\n\
             - Move to a separate 'archive' bucket instead of deleting"
        ),
        destructive_pattern!(
            "wrangler-r2-bucket-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+r2\s+bucket\s+delete\b",
            "wrangler r2 bucket delete removes an entire R2 bucket.",
            Critical,
            "Deleting an R2 bucket removes the bucket and ALL objects within it. Workers \
             bound to this bucket will fail. The bucket name becomes available for reuse \
             by any Cloudflare account.\n\n\
             Safer alternatives:\n\
             - wrangler r2 bucket list: Verify the bucket contents\n\
             - Empty the bucket and verify it's truly unused\n\
             - Remove Worker bindings before bucket deletion"
        ),
        // D1 destructive operations
        destructive_pattern!(
            "wrangler-d1-delete",
            r"wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+d1\s+delete\b",
            "wrangler d1 delete removes a D1 database.",
            Critical,
            "Deleting a D1 database permanently removes all tables, data, and schema. \
             Workers bound to this database will fail with binding errors. D1 databases \
             cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - wrangler d1 export: Export the database first\n\
             - wrangler d1 info: Review database details\n\
             - Remove Worker bindings before deletion"
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

    #[test]
    fn global_flags_do_not_bypass() {
        let pack = create_pack();
        // wrangler accepts --config, --cwd, --env, --verbose global flags.
        assert_blocks_with_pattern(
            &pack,
            "wrangler --config wrangler.toml delete my-worker",
            "wrangler-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler --env prod d1 delete my-db",
            "wrangler-d1-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "wrangler --cwd ./project r2 bucket delete my-bucket",
            "wrangler-r2-bucket-delete",
        );
        assert!(
            pack.check("wrangler --env prod whoami").is_none(),
            "safe read with env flag should remain safe"
        );
    }

    #[test]
    fn cloudflare_workers_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "wrangler delete my-worker", "wrangler-delete");
        assert_blocks_with_pattern(
            &pack,
            "wrangler deployments rollback",
            "wrangler-deployments-rollback",
        );
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
        assert_blocks_with_pattern(&pack, "wrangler d1 delete my-db", "wrangler-d1-delete");
    }

    #[test]
    fn cloudflare_workers_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "wrangler delete my-worker", Severity::Critical);
        assert_blocks_with_severity(&pack, "wrangler deployments rollback", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "wrangler kv:key delete --namespace-id=abc KEY",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler kv:namespace delete --namespace-id=abc",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler kv:bulk delete --namespace-id=abc keys.json",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler r2 object delete bucket/key",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "wrangler r2 bucket delete my-bucket",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "wrangler d1 delete my-db", Severity::Critical);
    }

    #[test]
    fn cloudflare_workers_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "wrangler whoami");
        assert_safe_pattern_matches(&pack, "wrangler kv:key get --namespace-id=abc KEY");
        assert_safe_pattern_matches(&pack, "wrangler kv:key list --namespace-id=abc");
        assert_safe_pattern_matches(&pack, "wrangler kv:namespace list");
        assert_safe_pattern_matches(&pack, "wrangler r2 object get my-bucket/path/to/obj");
        assert_safe_pattern_matches(&pack, "wrangler r2 bucket list");
        assert_safe_pattern_matches(&pack, "wrangler d1 list");
        assert_safe_pattern_matches(&pack, "wrangler d1 info my-db");
        assert_safe_pattern_matches(&pack, "wrangler dev");
        assert_safe_pattern_matches(&pack, "wrangler tail");
        assert_safe_pattern_matches(&pack, "wrangler --version");
        assert_safe_pattern_matches(&pack, "wrangler help");
    }

    #[test]
    fn cloudflare_workers_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

//! Algolia pack - protections for destructive Algolia operations.
//!
//! Covers destructive CLI and API patterns:
//! - Index deletion and clearing
//! - Rule/synonym deletions
//! - API key deletions
//! - SDK calls like deleteIndex / clearObjects

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Algolia pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "search.algolia".to_string(),
        name: "Algolia",
        description: "Protects against destructive Algolia operations like deleting indices, clearing objects, \
                      removing rules/synonyms, and deleting API keys.",
        keywords: &["algolia", "algoliasearch"],
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
            "algolia-indices-browse",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+indices\s+browse\b"
        ),
        safe_pattern!(
            "algolia-indices-list",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+indices\s+list\b"
        ),
        safe_pattern!(
            "algolia-search",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+search\b"
        ),
        safe_pattern!(
            "algolia-settings-get",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+settings\s+get\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "algolia-indices-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+indices\s+delete\b",
            "algolia indices delete permanently removes an Algolia index.",
            Critical,
            "Deleting an Algolia index permanently removes all searchable records, settings, \
             rules, and synonyms. Search functionality for applications using this index will \
             fail immediately. Re-indexing may require significant time and resources.\n\n\
             Safer alternatives:\n\
             - algolia indices list: Review indices before deletion\n\
             - Export index data using algolia indices browse\n\
             - Create a replica or copy before deleting"
        ),
        destructive_pattern!(
            "algolia-indices-clear",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+indices\s+clear\b",
            "algolia indices clear removes all objects from an Algolia index.",
            High,
            "Clearing an Algolia index removes all searchable records while preserving settings, \
             rules, and synonyms. Search will return no results until data is re-indexed. \
             This is irreversible without re-indexing from source data.\n\n\
             Safer alternatives:\n\
             - Export objects using algolia indices browse first\n\
             - Use a staging index for testing\n\
             - Delete specific objects instead of clearing all"
        ),
        destructive_pattern!(
            "algolia-rules-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+rules\s+delete\b",
            "algolia rules delete removes index rules.",
            Medium,
            "Deleting Algolia rules removes search customizations like query rewrites, \
             promotions, and filters. Search behavior may change unexpectedly for users \
             relying on these rules for relevant results.\n\n\
             Safer alternatives:\n\
             - algolia rules browse: Export rules before deletion\n\
             - Disable rules temporarily instead of deleting\n\
             - Test rule changes on a replica index first"
        ),
        destructive_pattern!(
            "algolia-synonyms-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+synonyms\s+delete\b",
            "algolia synonyms delete removes synonym entries.",
            Medium,
            "Deleting Algolia synonyms removes word associations that improve search matching. \
             Users searching with alternative terms may no longer find expected results. \
             Synonym configurations can take time to rebuild.\n\n\
             Safer alternatives:\n\
             - algolia synonyms browse: Export synonyms before deletion\n\
             - Test synonym changes on a replica index\n\
             - Document synonym configurations for recovery"
        ),
        destructive_pattern!(
            "algolia-apikeys-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+apikeys\s+delete\b",
            "algolia apikeys delete removes API keys and can break integrations.",
            High,
            "Deleting an Algolia API key immediately revokes access for all applications using \
             it. Search and indexing operations will fail with authentication errors. The key \
             cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - algolia apikeys list: Review keys and their usage\n\
             - Create new API keys before deleting old ones\n\
             - Rotate keys by updating applications first"
        ),
        destructive_pattern!(
            "algolia-sdk-delete-index",
            r"\b(?:algolia|algoliasearch)\b.*\bdeleteIndex\b",
            "Algolia SDK deleteIndex removes an index.",
            Critical,
            "The deleteIndex SDK method permanently removes an Algolia index and all its \
             contents. This includes all records, settings, rules, and synonyms. Production \
             search functionality will fail immediately.\n\n\
             Safer alternatives:\n\
             - Use browseObjects to export data first\n\
             - Copy to a backup index before deleting\n\
             - Add confirmation prompts in application code"
        ),
        destructive_pattern!(
            "algolia-sdk-clear-objects",
            r"\b(?:algolia|algoliasearch)\b.*\bclearObjects\b",
            "Algolia SDK clearObjects removes all records from an index.",
            High,
            "The clearObjects SDK method removes all searchable records from an index while \
             keeping configuration intact. Search results will be empty until re-indexing \
             completes. This cannot be undone.\n\n\
             Safer alternatives:\n\
             - Export objects using browseObjects first\n\
             - Use deleteObjects for targeted removal\n\
             - Test on a replica index before production"
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
        assert_eq!(pack.id, "search.algolia");
        assert_eq!(pack.name, "Algolia");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"algolia"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "algolia indices browse products");
        assert_safe_pattern_matches(&pack, "algolia indices list");
        assert_safe_pattern_matches(&pack, "algolia search products query");
        assert_safe_pattern_matches(&pack, "algolia settings get products");
    }

    #[test]
    fn blocks_cli_deletes() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "algolia indices delete products",
            "algolia-indices-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "algolia indices clear products",
            "algolia-indices-clear",
        );
        assert_blocks_with_pattern(
            &pack,
            "algolia rules delete products",
            "algolia-rules-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "algolia synonyms delete products",
            "algolia-synonyms-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "algolia apikeys delete key_123",
            "algolia-apikeys-delete",
        );
    }

    #[test]
    fn blocks_sdk_deletes() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "node -e \"const client = algoliasearch('app','key'); client.deleteIndex('prod');\"",
            "algolia-sdk-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "node -e \"algolia.clearObjects('products')\"",
            "algolia-sdk-clear-objects",
        );
    }

    #[test]
    fn algolia_blocks_with_correct_severity() {
        let pack = create_pack();
        // Critical - index deletion (CLI and SDK)
        assert_blocks_with_severity(&pack, "algolia indices delete products", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "node -e \"const client = algoliasearch('app','key'); client.deleteIndex('prod');\"",
            Severity::Critical,
        );
        // High - index clear, apikeys delete, SDK clearObjects
        assert_blocks_with_severity(&pack, "algolia indices clear products", Severity::High);
        assert_blocks_with_severity(&pack, "algolia apikeys delete key_123", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "node -e \"algolia.clearObjects('products')\"",
            Severity::High,
        );
        // Medium - rules delete, synonyms delete
        assert_blocks_with_severity(&pack, "algolia rules delete products", Severity::Medium);
        assert_blocks_with_severity(&pack, "algolia synonyms delete products", Severity::Medium);
    }

    #[test]
    fn algolia_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

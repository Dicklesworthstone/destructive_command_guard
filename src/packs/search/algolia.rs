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
            "algolia indices delete permanently removes an Algolia index."
        ),
        destructive_pattern!(
            "algolia-indices-clear",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+indices\s+clear\b",
            "algolia indices clear removes all objects from an Algolia index."
        ),
        destructive_pattern!(
            "algolia-rules-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+rules\s+delete\b",
            "algolia rules delete removes index rules."
        ),
        destructive_pattern!(
            "algolia-synonyms-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+synonyms\s+delete\b",
            "algolia synonyms delete removes synonym entries."
        ),
        destructive_pattern!(
            "algolia-apikeys-delete",
            r"algolia(?:\s+--?\S+(?:\s+\S+)?)*\s+apikeys\s+delete\b",
            "algolia apikeys delete removes API keys and can break integrations."
        ),
        destructive_pattern!(
            "algolia-sdk-delete-index",
            r"\b(?:algolia|algoliasearch)\b.*\bdeleteIndex\b",
            "Algolia SDK deleteIndex removes an index."
        ),
        destructive_pattern!(
            "algolia-sdk-clear-objects",
            r"\b(?:algolia|algoliasearch)\b.*\bclearObjects\b",
            "Algolia SDK clearObjects removes all records from an index."
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
}

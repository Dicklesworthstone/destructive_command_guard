//! Meilisearch pack - protections for destructive Meilisearch operations.
//!
//! Covers destructive REST operations via curl/httpie:
//! - Index deletion
//! - Document deletion
//! - Delete-batch
//! - API key deletion

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Meilisearch pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "search.meilisearch".to_string(),
        name: "Meilisearch",
        description: "Protects against destructive Meilisearch REST API operations like index deletion, \
                      document deletion, delete-batch, and API key removal.",
        keywords: &["meili", "meilisearch", "7700", "/indexes", "/keys"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "meili-curl-get-stats",
            r#"curl\b.*-X\s*GET\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/stats\b"#
        ),
        safe_pattern!(
            "meili-curl-get-health",
            r#"curl\b.*-X\s*GET\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/health\b"#
        ),
        safe_pattern!(
            "meili-curl-get-version",
            r#"curl\b.*-X\s*GET\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/version\b"#
        ),
        safe_pattern!(
            "meili-curl-search",
            r#"curl\b.*-X\s*POST\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/]+/search\b"#
        ),
        safe_pattern!(
            "meili-http-get-stats",
            r"http\s+GET\s+(?:https?://)?\S*(?:meili|:7700)\S*/stats\b"
        ),
        safe_pattern!(
            "meili-http-get-health",
            r"http\s+GET\s+(?:https?://)?\S*(?:meili|:7700)\S*/health\b"
        ),
        safe_pattern!(
            "meili-http-get-version",
            r"http\s+GET\s+(?:https?://)?\S*(?:meili|:7700)\S*/version\b"
        ),
        safe_pattern!(
            "meili-http-search",
            r"http\s+POST\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/search\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "meili-curl-delete-document",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents/[^\s/?]+"#,
            "curl -X DELETE against /documents/{id} removes a document from Meilisearch."
        ),
        destructive_pattern!(
            "meili-curl-delete-documents",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents\b"#,
            "curl -X DELETE against /documents removes documents from Meilisearch."
        ),
        destructive_pattern!(
            "meili-curl-delete-batch",
            r#"curl\b.*-X\s*POST\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents/delete-batch\b"#,
            "curl -X POST to /documents/delete-batch deletes documents in bulk."
        ),
        destructive_pattern!(
            "meili-curl-delete-key",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/keys/[^\s/?]+"#,
            "curl -X DELETE against /keys removes a Meilisearch API key."
        ),
        destructive_pattern!(
            "meili-curl-delete-index",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+(?:[\s?'\"]|$)"#,
            "curl -X DELETE against /indexes/{uid} deletes a Meilisearch index."
        ),
        destructive_pattern!(
            "meili-http-delete-document",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/documents/\S+",
            "http DELETE against /documents/{id} removes a document from Meilisearch."
        ),
        destructive_pattern!(
            "meili-http-delete-documents",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/documents\b",
            "http DELETE against /documents removes documents from Meilisearch."
        ),
        destructive_pattern!(
            "meili-http-delete-batch",
            r"http\s+POST\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/documents/delete-batch\b",
            "http POST to /documents/delete-batch deletes documents in bulk."
        ),
        destructive_pattern!(
            "meili-http-delete-key",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/keys/\S+",
            "http DELETE against /keys removes a Meilisearch API key."
        ),
        destructive_pattern!(
            "meili-http-delete-index",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+(?:[\s?]|$)",
            "http DELETE against /indexes/{uid} deletes a Meilisearch index."
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
        assert_eq!(pack.id, "search.meilisearch");
        assert_eq!(pack.name, "Meilisearch");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"meilisearch") || pack.keywords.contains(&"meili"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_queries() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/health");
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/stats");
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/version");
        assert_safe_pattern_matches(
            &pack,
            "curl -X POST http://localhost:7700/indexes/products/search",
        );
        assert_safe_pattern_matches(&pack, "http GET :7700/health");
        assert_safe_pattern_matches(&pack, "http POST :7700/indexes/products/search");
    }

    #[test]
    fn blocks_destructive_calls() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products",
            "meili-curl-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products/documents",
            "meili-curl-delete-documents",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products/documents/123",
            "meili-curl-delete-document",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:7700/indexes/products/documents/delete-batch",
            "meili-curl-delete-batch",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/keys/abc",
            "meili-curl-delete-key",
        );
        assert_blocks_with_pattern(
            &pack,
            "http DELETE :7700/indexes/products",
            "meili-http-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "http POST :7700/indexes/products/documents/delete-batch",
            "meili-http-delete-batch",
        );
    }
}

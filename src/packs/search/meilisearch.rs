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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
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
        // More specific patterns first
        destructive_pattern!(
            "meili-curl-delete-document",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents/[^\s/?]+"#,
            "curl -X DELETE against /documents/{id} removes a document from Meilisearch.",
            Medium,
            "Deleting a single document removes it from search results immediately. While \
             less destructive than bulk operations, applications expecting this document \
             will receive errors or empty results.\n\n\
             Safer alternatives:\n\
             - GET /indexes/{uid}/documents/{id}: Verify document first\n\
             - Export document content before deletion\n\
             - Use soft delete field in documents instead"
        ),
        destructive_pattern!(
            "meili-curl-delete-documents",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents(?:[\s?'"]|$)"#,
            "curl -X DELETE against /documents removes documents from Meilisearch.",
            High,
            "Deleting all documents removes every record from the index while preserving \
             settings and configuration. Search will return no results until re-indexing. \
             This cannot be undone.\n\n\
             Safer alternatives:\n\
             - GET /indexes/{uid}/documents: Export documents first\n\
             - Create a snapshot or dump before deletion\n\
             - Use delete-batch for targeted removal instead"
        ),
        destructive_pattern!(
            "meili-curl-delete-batch",
            r#"curl\b.*-X\s*POST\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents/delete-batch\b"#,
            "curl -X POST to /documents/delete-batch deletes documents in bulk.",
            High,
            "Batch delete removes multiple documents by their IDs in a single operation. \
             This is irreversible and affects all documents matching the provided IDs. \
             Verify the ID list carefully before executing.\n\n\
             Safer alternatives:\n\
             - GET documents by ID to verify content first\n\
             - Export matching documents before deletion\n\
             - Test with a small batch before processing all"
        ),
        destructive_pattern!(
            "meili-curl-delete-key",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/keys/[^\s/?]+"#,
            "curl -X DELETE against /keys removes a Meilisearch API key.",
            High,
            "Deleting an API key immediately revokes access for all applications using it. \
             Search and indexing operations will fail with authentication errors. The key \
             cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - GET /keys: List and document keys before deletion\n\
             - Create replacement key before deleting old one\n\
             - Update applications with new key first"
        ),
        // Generic index deletion last
        destructive_pattern!(
            "meili-curl-delete-index",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+(?:[\s?'"]|$)"#,
            "curl -X DELETE against /indexes/{uid} deletes a Meilisearch index.",
            Critical,
            "Deleting a Meilisearch index permanently removes all documents, settings, \
             filterable attributes, and ranking rules. Search functionality for applications \
             using this index will fail immediately.\n\n\
             Safer alternatives:\n\
             - GET /indexes/{uid}: Export index settings first\n\
             - Create a dump with POST /dumps for backup\n\
             - Re-index from source data after verification"
        ),
        // HTTPie variants
        destructive_pattern!(
            "meili-http-delete-document",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/documents/\S+",
            "http DELETE against /documents/{id} removes a document from Meilisearch.",
            Medium,
            "Deleting a single document removes it from search results immediately. While \
             less destructive than bulk operations, applications expecting this document \
             will receive errors or empty results.\n\n\
             Safer alternatives:\n\
             - GET /indexes/{uid}/documents/{id}: Verify document first\n\
             - Export document content before deletion\n\
             - Use soft delete field in documents instead"
        ),
        destructive_pattern!(
            "meili-http-delete-documents",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/documents(?:[\s?]|$)",
            "http DELETE against /documents removes documents from Meilisearch.",
            High,
            "Deleting all documents removes every record from the index while preserving \
             settings and configuration. Search will return no results until re-indexing. \
             This cannot be undone.\n\n\
             Safer alternatives:\n\
             - GET /indexes/{uid}/documents: Export documents first\n\
             - Create a snapshot or dump before deletion\n\
             - Use delete-batch for targeted removal instead"
        ),
        destructive_pattern!(
            "meili-http-delete-batch",
            r"http\s+POST\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+/documents/delete-batch\b",
            "http POST to /documents/delete-batch deletes documents in bulk.",
            High,
            "Batch delete removes multiple documents by their IDs in a single operation. \
             This is irreversible and affects all documents matching the provided IDs. \
             Verify the ID list carefully before executing.\n\n\
             Safer alternatives:\n\
             - GET documents by ID to verify content first\n\
             - Export matching documents before deletion\n\
             - Test with a small batch before processing all"
        ),
        destructive_pattern!(
            "meili-http-delete-key",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/keys/\S+",
            "http DELETE against /keys removes a Meilisearch API key.",
            High,
            "Deleting an API key immediately revokes access for all applications using it. \
             Search and indexing operations will fail with authentication errors. The key \
             cannot be recovered after deletion.\n\n\
             Safer alternatives:\n\
             - GET /keys: List and document keys before deletion\n\
             - Create replacement key before deleting old one\n\
             - Update applications with new key first"
        ),
        destructive_pattern!(
            "meili-http-delete-index",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:meili|:7700)\S*/indexes/\S+(?:[\s?]|$)",
            "http DELETE against /indexes/{uid} deletes a Meilisearch index.",
            Critical,
            "Deleting a Meilisearch index permanently removes all documents, settings, \
             filterable attributes, and ranking rules. Search functionality for applications \
             using this index will fail immediately.\n\n\
             Safer alternatives:\n\
             - GET /indexes/{uid}: Export index settings first\n\
             - Create a dump with POST /dumps for backup\n\
             - Re-index from source data after verification"
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

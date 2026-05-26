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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "meili-curl-get-stats",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*(?:meili|:7700)))(?!(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*documents/delete-batch\b))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/stats\b"#
        ),
        safe_pattern!(
            "meili-curl-get-health",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*(?:meili|:7700)))(?!(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*documents/delete-batch\b))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/health\b"#
        ),
        safe_pattern!(
            "meili-curl-get-version",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*(?:meili|:7700)))(?!(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*documents/delete-batch\b))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/version\b"#
        ),
        safe_pattern!(
            "meili-curl-search",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*(?:meili|:7700)))(?!(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*documents/delete-batch\b))curl\b.*(?:-X\s*|--request(?:=|\s+))POST\b.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/]+/search\b"#
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

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // More specific patterns first
        destructive_pattern!(
            "meili-curl-delete-document",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents/[^\s/?]+).*"#,
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
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents(?:[\s?'"]|$)).*"#,
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
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+/documents/delete-batch\b).*"#,
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
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/keys/[^\s/?]+).*"#,
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
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:meili|:7700)[^\s'\"]*/indexes/[^\s/?]+(?:[\s?'"]|$)).*"#,
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
    use crate::packs::Severity;
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
        assert_safe_pattern_matches(&pack, "curl --request=GET http://localhost:7700/health");
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/stats");
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/version");
        assert_safe_pattern_matches(
            &pack,
            "curl -X POST http://localhost:7700/indexes/products/search",
        );
        assert_safe_pattern_matches(
            &pack,
            "curl --request POST http://localhost:7700/indexes/products/search",
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
            "curl --request=DELETE http://localhost:7700/indexes/products",
            "meili-curl-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products/documents",
            "meili-curl-delete-documents",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE http://localhost:7700/indexes/products/documents",
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
            "curl http://localhost:7700/indexes/products/documents/delete-batch --request=POST",
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

    #[test]
    fn curl_safe_patterns_do_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let get_then_delete = "curl -X GET http://localhost:7700/health -X DELETE http://localhost:7700/indexes/products";

        assert_no_safe_match(&pack, get_then_delete);
        assert_blocks_with_pattern(&pack, get_then_delete, "meili-curl-delete-index");

        let search_then_delete_batch = "curl -X POST http://localhost:7700/indexes/products/search \
            -X POST http://localhost:7700/indexes/products/documents/delete-batch";

        assert_no_safe_match(&pack, search_then_delete_batch);
        assert_blocks_with_pattern(&pack, search_then_delete_batch, "meili-curl-delete-batch");

        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:7700/keys/abc -X DELETE",
            "meili-curl-delete-key",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:7700/keys/abc --request=DELETE",
            "meili-curl-delete-key",
        );

        let request_delete_command = "curl -X GET http://localhost:7700/health \
            --request DELETE http://localhost:7700/indexes/products";

        assert_no_safe_match(&pack, request_delete_command);
        assert_blocks_with_pattern(&pack, request_delete_command, "meili-curl-delete-index");
    }

    #[test]
    fn meilisearch_blocks_each_destructive_pattern() {
        let pack = create_pack();
        // curl patterns
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/movies/documents/42",
            "meili-curl-delete-document",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/movies/documents",
            "meili-curl-delete-documents",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:7700/indexes/movies/documents/delete-batch",
            "meili-curl-delete-batch",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/keys/mykey123",
            "meili-curl-delete-key",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/movies",
            "meili-curl-delete-index",
        );
        // HTTPie patterns
        assert_blocks_with_pattern(
            &pack,
            "http DELETE :7700/indexes/movies/documents/42",
            "meili-http-delete-document",
        );
        assert_blocks_with_pattern(
            &pack,
            "http DELETE :7700/indexes/movies/documents",
            "meili-http-delete-documents",
        );
        assert_blocks_with_pattern(
            &pack,
            "http POST :7700/indexes/movies/documents/delete-batch",
            "meili-http-delete-batch",
        );
        assert_blocks_with_pattern(
            &pack,
            "http DELETE :7700/keys/mykey123",
            "meili-http-delete-key",
        );
        assert_blocks_with_pattern(
            &pack,
            "http DELETE :7700/indexes/movies",
            "meili-http-delete-index",
        );
    }

    #[test]
    fn meilisearch_blocks_with_correct_severity() {
        let pack = create_pack();
        // Critical - index deletion
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "http DELETE :7700/indexes/products",
            Severity::Critical,
        );
        // High - documents deletion, delete-batch, key deletion
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products/documents",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X POST http://localhost:7700/indexes/products/documents/delete-batch",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://localhost:7700/keys/abc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "http DELETE :7700/indexes/products/documents",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "http POST :7700/indexes/products/documents/delete-batch",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "http DELETE :7700/keys/abc", Severity::High);
        // Medium - single document deletion
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://localhost:7700/indexes/products/documents/123",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "http DELETE :7700/indexes/products/documents/123",
            Severity::Medium,
        );
    }

    #[test]
    fn meilisearch_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/stats");
        assert_safe_pattern_matches(&pack, "curl --request GET http://localhost:7700/stats");
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/health");
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:7700/version");
        assert_safe_pattern_matches(
            &pack,
            "curl -X POST http://localhost:7700/indexes/products/search",
        );
        assert_safe_pattern_matches(&pack, "http GET :7700/stats");
        assert_safe_pattern_matches(&pack, "http GET :7700/health");
        assert_safe_pattern_matches(&pack, "http GET :7700/version");
        assert_safe_pattern_matches(&pack, "http POST :7700/indexes/products/search");
    }

    #[test]
    fn meilisearch_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

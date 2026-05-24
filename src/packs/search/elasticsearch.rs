//! Elasticsearch pack - protections for destructive Elasticsearch API operations.
//!
//! Covers destructive REST operations via curl/httpie:
//! - Index deletion
//! - Document deletion
//! - Delete-by-query
//! - Index close
//! - Cluster settings updates

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Elasticsearch pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "search.elasticsearch".to_string(),
        name: "Elasticsearch",
        description: "Protects against destructive Elasticsearch REST API operations like index deletion, \
                      delete-by-query, index close, and cluster setting changes.",
        keywords: &[
            "elasticsearch",
            "curl",
            "http",
            "9200",
            "_search",
            "_cluster",
            "_cat",
            "_doc",
            "_all",
            "_delete_by_query",
        ],
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
            "es-curl-get-search",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:DELETE|POST|PUT)\b)(?=.*(?:elastic|:9200)))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/(?:[^\s/]+/)?(?:_search|_count|_mapping|_settings)\b"#
        ),
        safe_pattern!(
            "es-curl-get-cat",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:DELETE|POST|PUT)\b)(?=.*(?:elastic|:9200)))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/_cat/\S+"#
        ),
        safe_pattern!(
            "es-curl-get-cluster-health",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:DELETE|POST|PUT)\b)(?=.*(?:elastic|:9200)))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/_cluster/health\b"#
        ),
        safe_pattern!(
            "es-http-get-search",
            r"http\s+GET\s+(?:https?://)?\S*(?:elastic|:9200)\S*/(?:\S+/)?(?:_search|_count|_mapping|_settings)\b"
        ),
        safe_pattern!(
            "es-http-get-cat",
            r"http\s+GET\s+(?:https?://)?\S*(?:elastic|:9200)\S*/_cat/\S+"
        ),
        safe_pattern!(
            "es-http-get-cluster-health",
            r"http\s+GET\s+(?:https?://)?\S*(?:elastic|:9200)\S*/_cluster/health\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "es-curl-delete-doc",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/[a-z0-9][a-z0-9._-]*/_doc/[^\s/?]+).*"#,
            "curl -X DELETE against /_doc deletes a document from Elasticsearch.",
            Medium,
            "Deleting a document removes it from the index. The document ID becomes \
             available for reuse. Applications expecting this document will receive \
             404 errors. Search results will no longer include this document.\n\n\
             Safer alternatives:\n\
             - GET the document first to verify\n\
             - Use document versioning for conflict detection\n\
             - Index a tombstone document instead of deleting"
        ),
        destructive_pattern!(
            "es-curl-delete-by-query",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/[a-z0-9][a-z0-9._-]*/_delete_by_query\b).*"#,
            "curl -X POST to _delete_by_query deletes documents matching the query.",
            High,
            "Delete-by-query removes all documents matching the query criteria. A \
             malformed query can delete far more documents than intended. The operation \
             runs asynchronously and cannot be easily cancelled once started.\n\n\
             Safer alternatives:\n\
             - Run the query with _search first to preview matches\n\
             - Use scroll_size to limit batch size\n\
             - Set wait_for_completion=false and monitor progress"
        ),
        destructive_pattern!(
            "es-curl-close-index",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)/_close\b).*"#,
            "curl -X POST to _close closes an index, making it unavailable for reads/writes.",
            High,
            "Closing an index blocks all read and write operations. Applications will \
             receive errors when accessing closed indices. Closed indices still consume \
             disk space but release memory. Use _all with extreme caution.\n\n\
             Safer alternatives:\n\
             - GET /_cat/indices to review indices first\n\
             - Close specific indices rather than patterns\n\
             - Use index lifecycle management for automated handling"
        ),
        destructive_pattern!(
            "es-curl-delete-index",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)(?:[\s?'"]|$)).*"#,
            "curl -X DELETE against an Elasticsearch index (or _all/*) deletes data permanently.",
            Critical,
            "Deleting an index permanently removes all documents, mappings, and settings. \
             Using _all or * wildcards can delete multiple indices at once. This operation \
             is immediate and irreversible. Data cannot be recovered without snapshots.\n\n\
             Safer alternatives:\n\
             - GET /_cat/indices to review before deletion\n\
             - Create a snapshot before deleting\n\
             - Disable action.destructive_requires_name for safety"
        ),
        destructive_pattern!(
            "es-curl-cluster-settings",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))PUT\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:elastic|:9200)[^\s'\"]*/_cluster/settings\b).*"#,
            "curl -X PUT to /_cluster/settings changes cluster settings and can be dangerous.",
            High,
            "Cluster settings affect all nodes and can impact stability, performance, \
             and data integrity. Persistent settings survive restarts. Changes to \
             allocation, recovery, or shard settings can trigger data movement.\n\n\
             Safer alternatives:\n\
             - GET /_cluster/settings to review current values\n\
             - Use transient settings for testing\n\
             - Test changes on non-production clusters first"
        ),
        destructive_pattern!(
            "es-http-delete-doc",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:elastic|:9200)\S*/[a-z0-9][a-z0-9._-]*/_doc/[^\s/?]+",
            "http DELETE against /_doc deletes a document from Elasticsearch.",
            Medium,
            "Deleting a document removes it from the index. The document ID becomes \
             available for reuse. Applications expecting this document will receive \
             404 errors. Search results will no longer include this document.\n\n\
             Safer alternatives:\n\
             - GET the document first to verify\n\
             - Use document versioning for conflict detection\n\
             - Index a tombstone document instead of deleting"
        ),
        destructive_pattern!(
            "es-http-delete-by-query",
            r"http\s+POST\s+(?:https?://)?\S*(?:elastic|:9200)\S*/[a-z0-9][a-z0-9._-]*/_delete_by_query\b",
            "http POST to _delete_by_query deletes documents matching the query.",
            High,
            "Delete-by-query removes all documents matching the query criteria. A \
             malformed query can delete far more documents than intended. The operation \
             runs asynchronously and cannot be easily cancelled once started.\n\n\
             Safer alternatives:\n\
             - Run the query with _search first to preview matches\n\
             - Use scroll_size to limit batch size\n\
             - Set wait_for_completion=false and monitor progress"
        ),
        destructive_pattern!(
            "es-http-close-index",
            r"http\s+POST\s+(?:https?://)?\S*(?:elastic|:9200)\S*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)/_close\b",
            "http POST to _close closes an index, making it unavailable for reads/writes.",
            High,
            "Closing an index blocks all read and write operations. Applications will \
             receive errors when accessing closed indices. Closed indices still consume \
             disk space but release memory. Use _all with extreme caution.\n\n\
             Safer alternatives:\n\
             - GET /_cat/indices to review indices first\n\
             - Close specific indices rather than patterns\n\
             - Use index lifecycle management for automated handling"
        ),
        destructive_pattern!(
            "es-http-delete-index",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:elastic|:9200)\S*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)(?:[\s?]|$)",
            "http DELETE against an Elasticsearch index (or _all/*) deletes data permanently.",
            Critical,
            "Deleting an index permanently removes all documents, mappings, and settings. \
             Using _all or * wildcards can delete multiple indices at once. This operation \
             is immediate and irreversible. Data cannot be recovered without snapshots.\n\n\
             Safer alternatives:\n\
             - GET /_cat/indices to review before deletion\n\
             - Create a snapshot before deleting\n\
             - Disable action.destructive_requires_name for safety"
        ),
        destructive_pattern!(
            "es-http-cluster-settings",
            r"http\s+PUT\s+(?:https?://)?\S*(?:elastic|:9200)\S*/_cluster/settings\b",
            "http PUT to /_cluster/settings changes cluster settings and can be dangerous.",
            High,
            "Cluster settings affect all nodes and can impact stability, performance, \
             and data integrity. Persistent settings survive restarts. Changes to \
             allocation, recovery, or shard settings can trigger data movement.\n\n\
             Safer alternatives:\n\
             - GET /_cluster/settings to review current values\n\
             - Use transient settings for testing\n\
             - Test changes on non-production clusters first"
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
        assert_eq!(pack.id, "search.elasticsearch");
        assert_eq!(pack.name, "Elasticsearch");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"elasticsearch"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_gets() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "curl -X GET http://localhost:9200/_cluster/health");
        assert_safe_pattern_matches(
            &pack,
            "curl -X GET http://localhost:9200/my-index/_search?q=*",
        );
        assert_safe_pattern_matches(
            &pack,
            "curl --request=GET http://localhost:9200/my-index/_search?q=*",
        );
        assert_safe_pattern_matches(&pack, "http GET :9200/_cat/indices?v");
        assert_safe_pattern_matches(&pack, "http GET http://localhost:9200/my-index/_count");
    }

    #[test]
    fn blocks_index_deletes() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:9200/my-index",
            "es-curl-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:9200/_all",
            "es-curl-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE http://localhost:9200/my-index",
            "es-curl-delete-index",
        );
        assert_blocks_with_pattern(&pack, "http DELETE :9200/my-index", "es-http-delete-index");
    }

    #[test]
    fn blocks_document_and_query_deletes() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:9200/my-index/_doc/123",
            "es-curl-delete-doc",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE http://localhost:9200/my-index/_doc/123",
            "es-curl-delete-doc",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_delete_by_query",
            "es-curl-delete-by-query",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request POST http://localhost:9200/my-index/_delete_by_query",
            "es-curl-delete-by-query",
        );
        assert_blocks_with_pattern(
            &pack,
            "http POST :9200/my-index/_delete_by_query",
            "es-http-delete-by-query",
        );
    }

    #[test]
    fn blocks_close_and_cluster_settings() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_close",
            "es-curl-close-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "http POST :9200/my-index/_close",
            "es-http-close-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X PUT http://localhost:9200/_cluster/settings",
            "es-curl-cluster-settings",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:9200/_cluster/settings --request=PUT",
            "es-curl-cluster-settings",
        );
        assert_blocks_with_pattern(
            &pack,
            "http PUT http://localhost:9200/_cluster/settings",
            "es-http-cluster-settings",
        );
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET http://localhost:9200/_cluster/health \
            -X DELETE http://localhost:9200/my-index";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "es-curl-delete-index");

        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:9200/my-index/_delete_by_query -X POST",
            "es-curl-delete-by-query",
        );

        let request_delete_command = "curl -X GET http://localhost:9200/_cluster/health \
            --request DELETE http://localhost:9200/my-index";

        assert_no_safe_match(&pack, request_delete_command);
        assert_blocks_with_pattern(&pack, request_delete_command, "es-curl-delete-index");
    }
}

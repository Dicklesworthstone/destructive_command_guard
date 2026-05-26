//! `OpenSearch` pack - protections for destructive `OpenSearch` operations.
//!
//! Covers destructive REST operations via curl/httpie and AWS CLI:
//! - Index deletion
//! - Index close
//! - `OpenSearch` domain deletion / connection removal

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `OpenSearch` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "search.opensearch".to_string(),
        name: "OpenSearch",
        description: "Protects against destructive OpenSearch REST API operations and AWS CLI domain deletions.",
        keywords: &[
            "opensearch",
            "aws",
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
            "os-curl-get-search",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:DELETE|POST)\b)(?=.*(?:opensearch|:9200)))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/(?:[^\s/]+/)?(?:_search|_count|_mapping|_settings)\b"#
        ),
        safe_pattern!(
            "os-curl-get-cat",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:DELETE|POST)\b)(?=.*(?:opensearch|:9200)))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/_cat/\S+"#
        ),
        safe_pattern!(
            "os-curl-get-cluster-health",
            r#"(?i)^(?!(?=.*(?:-X\s*|--request(?:=|\s+))(?:DELETE|POST)\b)(?=.*(?:opensearch|:9200)))curl\b.*(?:-X\s*|--request(?:=|\s+))GET\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/_cluster/health\b"#
        ),
        safe_pattern!(
            "os-http-get-search",
            r"http\s+GET\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/(?:\S+/)?(?:_search|_count|_mapping|_settings)\b"
        ),
        safe_pattern!(
            "os-http-get-cat",
            r"http\s+GET\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/_cat/\S+"
        ),
        safe_pattern!(
            "os-http-get-cluster-health",
            r"http\s+GET\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/_cluster/health\b"
        ),
        safe_pattern!(
            "aws-opensearch-describe-domain",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+describe-domain\b"
        ),
        safe_pattern!(
            "aws-opensearch-list-domain-names",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+list-domain-names\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "os-curl-delete-doc",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*?(?:opensearch|:9200)[^\s'\"]*?/[a-z0-9][a-z0-9._-]*/_doc/[^\s/?]+).*"#,
            "curl -X DELETE against /_doc deletes a document from OpenSearch.",
            Medium,
            "Deleting individual documents removes them from search results immediately. \
             While less destructive than bulk operations, this can affect applications \
             expecting the document to exist.\n\n\
             Safer alternatives:\n\
             - GET the document first to verify content\n\
             - Use _update API to mark as deleted instead\n\
             - Ensure document ID is correct before deletion"
        ),
        destructive_pattern!(
            "os-curl-delete-by-query",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/[a-z0-9][a-z0-9._-]*/_delete_by_query\b).*"#,
            "curl -X POST to _delete_by_query deletes documents matching the query.",
            High,
            "The _delete_by_query endpoint can delete large numbers of documents at once. \
             A poorly constructed query can remove more data than intended. This operation \
             cannot be easily undone.\n\n\
             Safer alternatives:\n\
             - Use _search with same query first to preview matches\n\
             - Add conflicts=abort to stop on version conflicts\n\
             - Use scroll_size to process in smaller batches"
        ),
        destructive_pattern!(
            "os-curl-close-index",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)/_close\b).*"#,
            "curl -X POST to _close closes an index, making it unavailable for reads/writes.",
            High,
            "Closing an index makes it completely unavailable for search and indexing. \
             Applications will receive errors until the index is reopened. Using _all or * \
             can close all indices at once.\n\n\
             Safer alternatives:\n\
             - Check index status with _cat/indices first\n\
             - Use specific index names instead of wildcards\n\
             - Verify no active applications depend on the index"
        ),
        destructive_pattern!(
            "os-curl-delete-index",
            r#"(?i)\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))DELETE\b)(?=.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)(?:\b|[/?])).*"#,
            "curl -X DELETE against an OpenSearch index (or _all/*) deletes data permanently.",
            Critical,
            "Deleting an OpenSearch index permanently removes all documents, mappings, and \
             settings. Using _all or * patterns can delete multiple indices at once. This \
             action cannot be undone without restoring from a snapshot.\n\n\
             Safer alternatives:\n\
             - _cat/indices: List indices before deletion\n\
             - Create a snapshot before deleting\n\
             - Close the index first if just archiving"
        ),
        destructive_pattern!(
            "os-http-delete-doc",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/[a-z0-9][a-z0-9._-]*/_doc/[^\s/?]+",
            "http DELETE against /_doc deletes a document from OpenSearch.",
            Medium,
            "Deleting individual documents removes them from search results immediately. \
             While less destructive than bulk operations, this can affect applications \
             expecting the document to exist.\n\n\
             Safer alternatives:\n\
             - GET the document first to verify content\n\
             - Use _update API to mark as deleted instead\n\
             - Ensure document ID is correct before deletion"
        ),
        destructive_pattern!(
            "os-http-delete-by-query",
            r"http\s+POST\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/[a-z0-9][a-z0-9._-]*/_delete_by_query\b",
            "http POST to _delete_by_query deletes documents matching the query.",
            High,
            "The _delete_by_query endpoint can delete large numbers of documents at once. \
             A poorly constructed query can remove more data than intended. This operation \
             cannot be easily undone.\n\n\
             Safer alternatives:\n\
             - Use _search with same query first to preview matches\n\
             - Add conflicts=abort to stop on version conflicts\n\
             - Use scroll_size to process in smaller batches"
        ),
        destructive_pattern!(
            "os-http-close-index",
            r"http\s+POST\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)/_close\b",
            "http POST to _close closes an index, making it unavailable for reads/writes.",
            High,
            "Closing an index makes it completely unavailable for search and indexing. \
             Applications will receive errors until the index is reopened. Using _all or * \
             can close all indices at once.\n\n\
             Safer alternatives:\n\
             - Check index status with _cat/indices first\n\
             - Use specific index names instead of wildcards\n\
             - Verify no active applications depend on the index"
        ),
        destructive_pattern!(
            "os-http-delete-index",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)(?:[\s?]|$)",
            "http DELETE against an OpenSearch index (or _all/*) deletes data permanently.",
            Critical,
            "Deleting an OpenSearch index permanently removes all documents, mappings, and \
             settings. Using _all or * patterns can delete multiple indices at once. This \
             action cannot be undone without restoring from a snapshot.\n\n\
             Safer alternatives:\n\
             - _cat/indices: List indices before deletion\n\
             - Create a snapshot before deleting\n\
             - Close the index first if just archiving"
        ),
        destructive_pattern!(
            "aws-opensearch-delete-domain",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-domain\b",
            "aws opensearch delete-domain permanently deletes an OpenSearch domain.",
            Critical,
            "Deleting an OpenSearch domain removes the entire cluster including all indices, \
             data, and configuration. This is irreversible and affects all applications using \
             the domain. Automated snapshots may also be deleted.\n\n\
             Safer alternatives:\n\
             - aws opensearch describe-domain: Review domain configuration\n\
             - Create a manual snapshot before deletion\n\
             - Export data to S3 for long-term retention"
        ),
        destructive_pattern!(
            "aws-opensearch-delete-inbound-connection",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-inbound-connection\b",
            "aws opensearch delete-inbound-connection removes an OpenSearch connection.",
            High,
            "Deleting an inbound connection removes cross-cluster connectivity. Applications \
             performing cross-cluster searches or replication will fail. The connection must \
             be re-established from the source domain.\n\n\
             Safer alternatives:\n\
             - List connections to understand dependencies\n\
             - Verify no active cross-cluster operations\n\
             - Update applications to use alternative data sources"
        ),
        destructive_pattern!(
            "aws-opensearch-delete-outbound-connection",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-outbound-connection\b",
            "aws opensearch delete-outbound-connection removes an OpenSearch connection.",
            High,
            "Deleting an outbound connection removes cross-cluster connectivity from this \
             domain. Any cross-cluster searches or replication to other domains will fail. \
             Re-establishing requires a new connection request.\n\n\
             Safer alternatives:\n\
             - List connections to understand what will be affected\n\
             - Coordinate with teams using connected domains\n\
             - Test connection removal in a non-production environment"
        ),
        destructive_pattern!(
            "aws-opensearch-delete-package",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-package\b",
            "aws opensearch delete-package removes an OpenSearch package.",
            Medium,
            "Deleting a package removes custom plugins, dictionaries, or scripts. Domains \
             using this package may experience errors or degraded functionality. The package \
             must be re-uploaded if needed again.\n\n\
             Safer alternatives:\n\
             - List domains using this package first\n\
             - Dissociate package from domains before deletion\n\
             - Keep a copy of package contents for recovery"
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
        assert_eq!(pack.id, "search.opensearch");
        assert_eq!(pack.name, "OpenSearch");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"opensearch"));

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
        assert_safe_pattern_matches(&pack, "aws opensearch describe-domain --domain-name test");
        assert_safe_pattern_matches(&pack, "aws opensearch list-domain-names");
    }

    #[test]
    fn blocks_rest_deletes_and_close() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:9200/my-index",
            "os-curl-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request=DELETE http://localhost:9200/my-index",
            "os-curl-delete-index",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X DELETE http://localhost:9200/my-index/_doc/123",
            "os-curl-delete-doc",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl --request DELETE http://localhost:9200/my-index/_doc/123",
            "os-curl-delete-doc",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_delete_by_query",
            "os-curl-delete-by-query",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:9200/my-index/_delete_by_query --request=POST",
            "os-curl-delete-by-query",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_close",
            "os-curl-close-index",
        );
        assert_blocks_with_pattern(&pack, "http DELETE :9200/my-index", "os-http-delete-index");
        assert_blocks_with_pattern(
            &pack,
            "http POST :9200/my-index/_close",
            "os-http-close-index",
        );
    }

    #[test]
    fn curl_get_safe_pattern_does_not_mask_destructive_api_methods() {
        let pack = create_pack();
        let command = "curl -X GET http://localhost:9200/_cluster/health \
            -X DELETE http://localhost:9200/my-index";

        assert_no_safe_match(&pack, command);
        assert_blocks_with_pattern(&pack, command, "os-curl-delete-index");

        assert_blocks_with_pattern(
            &pack,
            "curl http://localhost:9200/my-index/_delete_by_query -X POST",
            "os-curl-delete-by-query",
        );

        let request_delete_command = "curl -X GET http://localhost:9200/_cluster/health \
            --request DELETE http://localhost:9200/my-index";

        assert_no_safe_match(&pack, request_delete_command);
        assert_blocks_with_pattern(&pack, request_delete_command, "os-curl-delete-index");
    }

    #[test]
    fn blocks_aws_deletions() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "aws opensearch delete-domain --domain-name prod",
            "aws-opensearch-delete-domain",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws opensearch delete-inbound-connection --connection-id abc",
            "aws-opensearch-delete-inbound-connection",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws opensearch delete-outbound-connection --connection-id def",
            "aws-opensearch-delete-outbound-connection",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws opensearch delete-package --package-id pkg-123",
            "aws-opensearch-delete-package",
        );
    }

    #[test]
    fn opensearch_blocks_with_correct_severity() {
        let pack = create_pack();
        // Critical - index deletion (curl, httpie), domain deletion
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://localhost:9200/my-index",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "http DELETE :9200/my-index", Severity::Critical);
        assert_blocks_with_severity(
            &pack,
            "aws opensearch delete-domain --domain-name prod",
            Severity::Critical,
        );
        // High - delete-by-query, close index, connections
        assert_blocks_with_severity(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_delete_by_query",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_close",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "http POST :9200/my-index/_delete_by_query",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "http POST :9200/my-index/_close", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "aws opensearch delete-inbound-connection --connection-id abc",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws opensearch delete-outbound-connection --connection-id def",
            Severity::High,
        );
        // Medium - single doc deletion, package deletion
        assert_blocks_with_severity(
            &pack,
            "curl -X DELETE http://localhost:9200/my-index/_doc/123",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "http DELETE :9200/my-index/_doc/123",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "aws opensearch delete-package --package-id pkg-123",
            Severity::Medium,
        );
    }

    #[test]
    fn opensearch_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "os-curl-get-search",
            r#"curl\b.*-X\s*GET\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/(?:[^\s/]+/)?(?:_search|_count|_mapping|_settings)\b"#
        ),
        safe_pattern!(
            "os-curl-get-cat",
            r#"curl\b.*-X\s*GET\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/_cat/\S+"#
        ),
        safe_pattern!(
            "os-curl-get-cluster-health",
            r#"curl\b.*-X\s*GET\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/_cluster/health\b"#
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
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*?(?:opensearch|:9200)[^\s'\"]*?/[a-z0-9][a-z0-9._-]*/_doc/[^\s/?]+"#,
            "curl -X DELETE against /_doc deletes a document from OpenSearch."
        ),
        destructive_pattern!(
            "os-curl-delete-by-query",
            r#"curl\b.*-X\s*POST\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/[a-z0-9][a-z0-9._-]*/_delete_by_query\b"#,
            "curl -X POST to _delete_by_query deletes documents matching the query."
        ),
        destructive_pattern!(
            "os-curl-close-index",
            r#"curl\b.*-X\s*POST\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)/_close\b"#,
            "curl -X POST to _close closes an index, making it unavailable for reads/writes."
        ),
        destructive_pattern!(
            "os-curl-delete-index",
            r#"curl\b.*-X\s*DELETE\b.*\b(?:https?://)?[^\s'\"]*(?:opensearch|:9200)[^\s'\"]*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)(?:\b|[/?])"#,
            "curl -X DELETE against an OpenSearch index (or _all/*) deletes data permanently."
        ),
        destructive_pattern!(
            "os-http-delete-doc",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/[a-z0-9][a-z0-9._-]*/_doc/[^\s/?]+",
            "http DELETE against /_doc deletes a document from OpenSearch."
        ),
        destructive_pattern!(
            "os-http-delete-by-query",
            r"http\s+POST\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/[a-z0-9][a-z0-9._-]*/_delete_by_query\b",
            "http POST to _delete_by_query deletes documents matching the query."
        ),
        destructive_pattern!(
            "os-http-close-index",
            r"http\s+POST\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)/_close\b",
            "http POST to _close closes an index, making it unavailable for reads/writes."
        ),
        destructive_pattern!(
            "os-http-delete-index",
            r"http\s+DELETE\s+(?:https?://)?\S*(?:opensearch|:9200)\S*/(?:_all|\*|[a-z0-9][a-z0-9._-]*)(?:[\s?]|$)",
            "http DELETE against an OpenSearch index (or _all/*) deletes data permanently."
        ),
        destructive_pattern!(
            "aws-opensearch-delete-domain",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-domain\b",
            "aws opensearch delete-domain permanently deletes an OpenSearch domain."
        ),
        destructive_pattern!(
            "aws-opensearch-delete-inbound-connection",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-inbound-connection\b",
            "aws opensearch delete-inbound-connection removes an OpenSearch connection."
        ),
        destructive_pattern!(
            "aws-opensearch-delete-outbound-connection",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-outbound-connection\b",
            "aws opensearch delete-outbound-connection removes an OpenSearch connection."
        ),
        destructive_pattern!(
            "aws-opensearch-delete-package",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+opensearch\s+delete-package\b",
            "aws opensearch delete-package removes an OpenSearch package."
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
            "curl -X DELETE http://localhost:9200/my-index/_doc/123",
            "os-curl-delete-doc",
        );
        assert_blocks_with_pattern(
            &pack,
            "curl -X POST http://localhost:9200/my-index/_delete_by_query",
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
}

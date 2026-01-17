//! AWS `CloudFront` pack - protections for destructive `CloudFront` CLI operations.
//!
//! Covers destructive operations:
//! - Distribution deletion (`aws cloudfront delete-distribution`)
//! - Cache policy deletion (`aws cloudfront delete-cache-policy`)
//! - Origin request policy deletion (`aws cloudfront delete-origin-request-policy`)
//! - Function deletion (`aws cloudfront delete-function`)
//! - Cache invalidation (costly, can affect caching)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS `CloudFront` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cdn.cloudfront".to_string(),
        name: "AWS CloudFront",
        description: "Protects against destructive AWS CloudFront operations like deleting \
                      distributions, cache policies, and functions.",
        keywords: &["cloudfront"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // List operations
        safe_pattern!(
            "cloudfront-list-distributions",
            r"aws\s+cloudfront\s+list-distributions\b"
        ),
        safe_pattern!(
            "cloudfront-list-cache-policies",
            r"aws\s+cloudfront\s+list-cache-policies\b"
        ),
        safe_pattern!(
            "cloudfront-list-origin-request-policies",
            r"aws\s+cloudfront\s+list-origin-request-policies\b"
        ),
        safe_pattern!(
            "cloudfront-list-functions",
            r"aws\s+cloudfront\s+list-functions\b"
        ),
        safe_pattern!(
            "cloudfront-list-invalidations",
            r"aws\s+cloudfront\s+list-invalidations\b"
        ),
        // Get operations
        safe_pattern!(
            "cloudfront-get-distribution",
            r"aws\s+cloudfront\s+get-distribution\b"
        ),
        safe_pattern!(
            "cloudfront-get-distribution-config",
            r"aws\s+cloudfront\s+get-distribution-config\b"
        ),
        safe_pattern!(
            "cloudfront-get-cache-policy",
            r"aws\s+cloudfront\s+get-cache-policy\b"
        ),
        safe_pattern!(
            "cloudfront-get-origin-request-policy",
            r"aws\s+cloudfront\s+get-origin-request-policy\b"
        ),
        safe_pattern!(
            "cloudfront-get-function",
            r"aws\s+cloudfront\s+get-function\b"
        ),
        safe_pattern!(
            "cloudfront-get-invalidation",
            r"aws\s+cloudfront\s+get-invalidation\b"
        ),
        // Describe operations
        safe_pattern!(
            "cloudfront-describe-function",
            r"aws\s+cloudfront\s+describe-function\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Distribution deletion
        destructive_pattern!(
            "cloudfront-delete-distribution",
            r"aws\s+cloudfront\s+delete-distribution\b",
            "aws cloudfront delete-distribution removes a CloudFront distribution."
        ),
        // Cache policy deletion
        destructive_pattern!(
            "cloudfront-delete-cache-policy",
            r"aws\s+cloudfront\s+delete-cache-policy\b",
            "aws cloudfront delete-cache-policy removes a cache policy."
        ),
        // Origin request policy deletion
        destructive_pattern!(
            "cloudfront-delete-origin-request-policy",
            r"aws\s+cloudfront\s+delete-origin-request-policy\b",
            "aws cloudfront delete-origin-request-policy removes an origin request policy."
        ),
        // Function deletion
        destructive_pattern!(
            "cloudfront-delete-function",
            r"aws\s+cloudfront\s+delete-function\b",
            "aws cloudfront delete-function removes a CloudFront function."
        ),
        // Response headers policy deletion
        destructive_pattern!(
            "cloudfront-delete-response-headers-policy",
            r"aws\s+cloudfront\s+delete-response-headers-policy\b",
            "aws cloudfront delete-response-headers-policy removes a response headers policy."
        ),
        // Key group deletion
        destructive_pattern!(
            "cloudfront-delete-key-group",
            r"aws\s+cloudfront\s+delete-key-group\b",
            "aws cloudfront delete-key-group removes a key group used for signed URLs."
        ),
        // Invalidation (has cost implications)
        destructive_pattern!(
            "cloudfront-create-invalidation",
            r"aws\s+cloudfront\s+create-invalidation\b",
            "aws cloudfront create-invalidation creates a cache invalidation (has cost implications)."
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
        assert_eq!(pack.id, "cdn.cloudfront");
        assert_eq!(pack.name, "AWS CloudFront");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"cloudfront"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // List operations
        assert_safe_pattern_matches(&pack, "aws cloudfront list-distributions");
        assert_safe_pattern_matches(&pack, "aws cloudfront list-cache-policies");
        assert_safe_pattern_matches(&pack, "aws cloudfront list-origin-request-policies");
        assert_safe_pattern_matches(&pack, "aws cloudfront list-functions");
        assert_safe_pattern_matches(
            &pack,
            "aws cloudfront list-invalidations --distribution-id ABC",
        );
        // Get operations
        assert_safe_pattern_matches(&pack, "aws cloudfront get-distribution --id ABC");
        assert_safe_pattern_matches(&pack, "aws cloudfront get-distribution-config --id ABC");
        assert_safe_pattern_matches(&pack, "aws cloudfront get-cache-policy --id XYZ");
        assert_safe_pattern_matches(&pack, "aws cloudfront get-origin-request-policy --id XYZ");
        assert_safe_pattern_matches(&pack, "aws cloudfront get-function --name myfunc");
        assert_safe_pattern_matches(
            &pack,
            "aws cloudfront get-invalidation --distribution-id ABC --id INV",
        );
        assert_safe_pattern_matches(&pack, "aws cloudfront describe-function --name myfunc");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Distribution deletion
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront delete-distribution --id ABC --if-match ETAG",
            "cloudfront-delete-distribution",
        );
        // Cache policy deletion
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront delete-cache-policy --id XYZ",
            "cloudfront-delete-cache-policy",
        );
        // Origin request policy deletion
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront delete-origin-request-policy --id XYZ",
            "cloudfront-delete-origin-request-policy",
        );
        // Function deletion
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront delete-function --name myfunc --if-match ETAG",
            "cloudfront-delete-function",
        );
        // Response headers policy deletion
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront delete-response-headers-policy --id ABC",
            "cloudfront-delete-response-headers-policy",
        );
        // Key group deletion
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront delete-key-group --id ABC",
            "cloudfront-delete-key-group",
        );
        // Invalidation (costly)
        assert_blocks_with_pattern(
            &pack,
            "aws cloudfront create-invalidation --distribution-id ABC --paths '/*'",
            "cloudfront-create-invalidation",
        );
    }
}

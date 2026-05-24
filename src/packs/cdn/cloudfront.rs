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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // List operations
        safe_pattern!(
            "cloudfront-list-distributions",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+list-distributions\b"
        ),
        safe_pattern!(
            "cloudfront-list-cache-policies",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+list-cache-policies\b"
        ),
        safe_pattern!(
            "cloudfront-list-origin-request-policies",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+list-origin-request-policies\b"
        ),
        safe_pattern!(
            "cloudfront-list-functions",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+list-functions\b"
        ),
        safe_pattern!(
            "cloudfront-list-invalidations",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+list-invalidations\b"
        ),
        // Get operations
        safe_pattern!(
            "cloudfront-get-distribution",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+get-distribution\b"
        ),
        safe_pattern!(
            "cloudfront-get-distribution-config",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+get-distribution-config\b"
        ),
        safe_pattern!(
            "cloudfront-get-cache-policy",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+get-cache-policy\b"
        ),
        safe_pattern!(
            "cloudfront-get-origin-request-policy",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+get-origin-request-policy\b"
        ),
        safe_pattern!(
            "cloudfront-get-function",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+get-function\b"
        ),
        safe_pattern!(
            "cloudfront-get-invalidation",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+get-invalidation\b"
        ),
        // Describe operations
        safe_pattern!(
            "cloudfront-describe-function",
            r"\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cloudfront\s+describe-function\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Distribution deletion
        destructive_pattern!(
            "cloudfront-delete-distribution",
            r"\baws\b.*?\bcloudfront\s+delete-distribution\b",
            "aws cloudfront delete-distribution removes a CloudFront distribution.",
            Critical,
            "Deleting a CloudFront distribution removes your CDN endpoint. All traffic \
             to the distribution URL will fail. You must first disable the distribution \
             and wait for propagation. Associated origins, behaviors, and cache settings \
             are lost.\n\n\
             Safer alternatives:\n\
             - aws cloudfront get-distribution: Review configuration first\n\
             - Disable the distribution before deleting\n\
             - Export the distribution config for backup"
        ),
        // Cache policy deletion
        destructive_pattern!(
            "cloudfront-delete-cache-policy",
            r"\baws\b.*?\bcloudfront\s+delete-cache-policy\b",
            "aws cloudfront delete-cache-policy removes a cache policy.",
            High,
            "Deleting a cache policy fails if any distribution behaviors reference it. \
             If deletion succeeds, any caching optimizations you configured are lost. \
             Custom TTLs, cache keys, and compression settings must be recreated.\n\n\
             Safer alternatives:\n\
             - aws cloudfront get-cache-policy: Review policy settings first\n\
             - Check which distributions use this policy\n\
             - Create a replacement policy before deleting"
        ),
        // Origin request policy deletion
        destructive_pattern!(
            "cloudfront-delete-origin-request-policy",
            r"\baws\b.*?\bcloudfront\s+delete-origin-request-policy\b",
            "aws cloudfront delete-origin-request-policy removes an origin request policy.",
            High,
            "Deleting an origin request policy removes header, query string, and cookie \
             forwarding configuration. Origins may receive different requests than \
             expected, potentially breaking authentication or content negotiation.\n\n\
             Safer alternatives:\n\
             - aws cloudfront get-origin-request-policy: Review settings first\n\
             - Verify no distributions reference this policy\n\
             - Create replacement before deletion"
        ),
        // Function deletion
        destructive_pattern!(
            "cloudfront-delete-function",
            r"\baws\b.*?\bcloudfront\s+delete-function\b",
            "aws cloudfront delete-function removes a CloudFront function.",
            High,
            "Deleting a CloudFront Function removes edge compute logic. Any distributions \
             using this function will lose URL rewriting, header manipulation, or other \
             transformations. Function code is not recoverable after deletion.\n\n\
             Safer alternatives:\n\
             - aws cloudfront get-function: Download function code first\n\
             - Remove function associations from distributions first\n\
             - Test replacements before deleting the original"
        ),
        // Response headers policy deletion
        destructive_pattern!(
            "cloudfront-delete-response-headers-policy",
            r"\baws\b.*?\bcloudfront\s+delete-response-headers-policy\b",
            "aws cloudfront delete-response-headers-policy removes a response headers policy.",
            High,
            "Deleting a response headers policy removes security headers like CORS, \
             Content-Security-Policy, and HSTS settings. Browsers may block cross-origin \
             requests or report security warnings after deletion.\n\n\
             Safer alternatives:\n\
             - Review which distributions use this policy\n\
             - Test your site without these headers in staging\n\
             - Create a replacement policy before deleting"
        ),
        // Key group deletion
        destructive_pattern!(
            "cloudfront-delete-key-group",
            r"\baws\b.*?\bcloudfront\s+delete-key-group\b",
            "aws cloudfront delete-key-group removes a key group used for signed URLs.",
            Critical,
            "Deleting a key group breaks signed URL and signed cookie validation. \
             Users with existing signed URLs will lose access to protected content. \
             Any distributions using this key group for restricted content will deny \
             all requests.\n\n\
             Safer alternatives:\n\
             - Rotate keys by adding new keys before removing old ones\n\
             - Verify no distributions reference this key group\n\
             - Update applications to use new signing keys first"
        ),
        // Invalidation (has cost implications)
        destructive_pattern!(
            "cloudfront-create-invalidation",
            r"\baws\b.*?\bcloudfront\s+create-invalidation\b",
            "aws cloudfront create-invalidation creates a cache invalidation (has cost implications).",
            Medium,
            "Cache invalidations have cost implications after the first 1,000 paths per \
             month. Wildcard invalidations (/*) count as one path but clear the entire \
             cache, causing origin load spikes. Frequent invalidations defeat CDN benefits.\n\n\
             Safer alternatives:\n\
             - Use versioned URLs (file.v2.js) instead of invalidation\n\
             - Invalidate specific paths rather than wildcards\n\
             - Set appropriate Cache-Control headers at the origin"
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
    fn aws_global_flags_do_not_bypass() {
        // `aws --profile X --region Y cloudfront delete-distribution` is the
        // canonical class bug: global flags on `aws` before the service name.
        let pack = create_pack();
        let matched = pack
            .check("aws --profile prod cloudfront delete-distribution --id ABC --if-match E")
            .expect("global flag before service should still be blocked");
        assert_eq!(matched.name, Some("cloudfront-delete-distribution"));

        let matched = pack
            .check("aws --region us-west-2 --profile prod cloudfront delete-function --name x")
            .expect("multiple global flags should still be blocked");
        assert_eq!(matched.name, Some("cloudfront-delete-function"));

        assert!(
            pack.check("aws --profile prod cloudfront list-distributions")
                .is_none(),
            "safe list command with global flag should still be allowed"
        );
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

    #[test]
    fn arg_named_like_safe_subcommand_does_not_bypass() {
        // A positional arg (e.g. `--id list-distributions`) must not pose
        // as the safe subcommand. The flag-walker in safe patterns walks
        // flag tokens only, so arg values with hyphenated "list-/get-"
        // names cannot short-circuit a destructive call.
        let pack = create_pack();
        let matched = pack
            .check("aws cloudfront delete-distribution --id list-distributions --if-match ETAG")
            .expect("arg value literally named `list-distributions` must not bypass the block");
        assert_eq!(matched.name, Some("cloudfront-delete-distribution"));
    }
}

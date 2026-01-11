//! `MinIO` pack - protections for destructive `MinIO` Client (mc) operations.
//!
//! Covers destructive operations:
//! - Bucket removal (mc rb)
//! - Object deletion (mc rm)
//! - Admin bucket deletion
//! - Mirror with remove

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `MinIO` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "storage.minio".to_string(),
        name: "MinIO",
        description: "Protects against destructive MinIO Client (mc) operations like bucket \
                      removal, object deletion, and admin operations.",
        keywords: &["mc"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // List operations
        safe_pattern!("mc-ls", r"\bmc\s+(?:--\S+\s+)*ls\b"),
        // Read operations
        safe_pattern!("mc-cat", r"\bmc\s+(?:--\S+\s+)*cat\b"),
        safe_pattern!("mc-head", r"\bmc\s+(?:--\S+\s+)*head\b"),
        safe_pattern!("mc-stat", r"\bmc\s+(?:--\S+\s+)*stat\b"),
        // Copy operations (non-destructive)
        safe_pattern!("mc-cp", r"\bmc\s+(?:--\S+\s+)*cp\b"),
        // Diff/compare
        safe_pattern!("mc-diff", r"\bmc\s+(?:--\S+\s+)*diff\b"),
        // Find
        safe_pattern!("mc-find", r"\bmc\s+(?:--\S+\s+)*find\b"),
        // Disk usage
        safe_pattern!("mc-du", r"\bmc\s+(?:--\S+\s+)*du\b"),
        // Version/help
        safe_pattern!("mc-version", r"\bmc\s+(?:--\S+\s+)*version\b"),
        safe_pattern!("mc-help", r"\bmc\s+(?:--\S+\s+)*(?:--help|-h)\b"),
        // Admin info (read-only)
        safe_pattern!("mc-admin-info", r"\bmc\s+(?:--\S+\s+)*admin\s+info\b"),
        safe_pattern!(
            "mc-admin-user-list",
            r"\bmc\s+(?:--\S+\s+)*admin\s+user\s+list\b"
        ),
        safe_pattern!(
            "mc-admin-policy-list",
            r"\bmc\s+(?:--\S+\s+)*admin\s+policy\s+list\b"
        ),
        // Alias management (config, not data)
        safe_pattern!("mc-alias-list", r"\bmc\s+(?:--\S+\s+)*alias\s+list\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Bucket removal
        destructive_pattern!(
            "mc-rb",
            r"\bmc\s+(?:--\S+\s+)*rb\b",
            "mc rb removes a MinIO bucket."
        ),
        // Object removal
        destructive_pattern!(
            "mc-rm",
            r"\bmc\s+(?:--\S+\s+)*rm\b",
            "mc rm deletes objects from MinIO."
        ),
        // Admin bucket delete
        destructive_pattern!(
            "mc-admin-bucket-delete",
            r"\bmc\s+(?:--\S+\s+)*admin\s+bucket\s+(?:delete|remove)\b",
            "mc admin bucket delete removes a bucket via admin API."
        ),
        // Mirror with remove (sync with delete)
        destructive_pattern!(
            "mc-mirror-remove",
            r"\bmc\s+(?:--\S+\s+)*mirror\b.*--remove\b",
            "mc mirror --remove deletes destination objects not in source."
        ),
        // Admin user remove
        destructive_pattern!(
            "mc-admin-user-remove",
            r"\bmc\s+(?:--\S+\s+)*admin\s+user\s+(?:remove|disable)\b",
            "mc admin user remove/disable affects user access."
        ),
        // Admin policy remove
        destructive_pattern!(
            "mc-admin-policy-remove",
            r"\bmc\s+(?:--\S+\s+)*admin\s+policy\s+(?:remove|unset)\b",
            "mc admin policy remove/unset modifies access policies."
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
        assert_eq!(pack.id, "storage.minio");
        assert_eq!(pack.name, "MinIO");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"mc"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // List operations
        assert_safe_pattern_matches(&pack, "mc ls myminio/bucket");
        assert_safe_pattern_matches(&pack, "mc --json ls myminio/bucket");
        // Read operations
        assert_safe_pattern_matches(&pack, "mc cat myminio/bucket/file.txt");
        assert_safe_pattern_matches(&pack, "mc head myminio/bucket/file.txt");
        assert_safe_pattern_matches(&pack, "mc stat myminio/bucket/file.txt");
        // Copy operations
        assert_safe_pattern_matches(&pack, "mc cp localfile myminio/bucket/");
        assert_safe_pattern_matches(&pack, "mc cp myminio/bucket/file.txt ./local");
        // Diff
        assert_safe_pattern_matches(&pack, "mc diff myminio/bucket1 myminio/bucket2");
        // Find
        assert_safe_pattern_matches(&pack, "mc find myminio/bucket --name '*.txt'");
        // Disk usage
        assert_safe_pattern_matches(&pack, "mc du myminio/bucket");
        // Version/help
        assert_safe_pattern_matches(&pack, "mc version");
        assert_safe_pattern_matches(&pack, "mc --help");
        // Admin info
        assert_safe_pattern_matches(&pack, "mc admin info myminio");
        assert_safe_pattern_matches(&pack, "mc admin user list myminio");
        assert_safe_pattern_matches(&pack, "mc admin policy list myminio");
        // Alias
        assert_safe_pattern_matches(&pack, "mc alias list");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Bucket removal
        assert_blocks_with_pattern(&pack, "mc rb myminio/bucket", "mc-rb");
        assert_blocks_with_pattern(&pack, "mc rb --force myminio/bucket", "mc-rb");
        assert_blocks_with_pattern(&pack, "mc --json rb myminio/bucket", "mc-rb");
        // Object removal
        assert_blocks_with_pattern(&pack, "mc rm myminio/bucket/file.txt", "mc-rm");
        assert_blocks_with_pattern(&pack, "mc rm --recursive myminio/bucket/", "mc-rm");
        assert_blocks_with_pattern(&pack, "mc rm --force myminio/bucket/file.txt", "mc-rm");
        // Admin bucket delete
        assert_blocks_with_pattern(
            &pack,
            "mc admin bucket delete myminio bucket",
            "mc-admin-bucket-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "mc admin bucket remove myminio bucket",
            "mc-admin-bucket-delete",
        );
        // Mirror with remove
        assert_blocks_with_pattern(
            &pack,
            "mc mirror --remove myminio/src myminio/dst",
            "mc-mirror-remove",
        );
        assert_blocks_with_pattern(
            &pack,
            "mc mirror myminio/src myminio/dst --remove",
            "mc-mirror-remove",
        );
        // Admin user operations
        assert_blocks_with_pattern(
            &pack,
            "mc admin user remove myminio username",
            "mc-admin-user-remove",
        );
        assert_blocks_with_pattern(
            &pack,
            "mc admin user disable myminio username",
            "mc-admin-user-remove",
        );
        // Admin policy operations
        assert_blocks_with_pattern(
            &pack,
            "mc admin policy remove myminio policyname",
            "mc-admin-policy-remove",
        );
        assert_blocks_with_pattern(
            &pack,
            "mc admin policy unset myminio policyname",
            "mc-admin-policy-remove",
        );
    }
}

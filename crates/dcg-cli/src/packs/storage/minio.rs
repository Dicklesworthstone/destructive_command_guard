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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand so a remote/path/user-name containing
    // the subcommand keyword as a substring (e.g. `ls-archive/bucket`,
    // `cp-mirror/data`, `admin-info-pw`) doesn't short-circuit destructive
    // mc ops via the safe rule.
    vec![
        // List operations
        safe_pattern!("mc-ls", r"\bmc\s+(?:--?\S+\s+)*ls(?=\s|$)"),
        // Read operations
        safe_pattern!("mc-cat", r"\bmc\s+(?:--?\S+\s+)*cat(?=\s|$)"),
        safe_pattern!("mc-head", r"\bmc\s+(?:--?\S+\s+)*head(?=\s|$)"),
        safe_pattern!("mc-stat", r"\bmc\s+(?:--?\S+\s+)*stat(?=\s|$)"),
        // Copy operations (non-destructive)
        safe_pattern!("mc-cp", r"\bmc\s+(?:--?\S+\s+)*cp(?=\s|$)"),
        // Diff/compare
        safe_pattern!("mc-diff", r"\bmc\s+(?:--?\S+\s+)*diff(?=\s|$)"),
        // Find
        safe_pattern!("mc-find", r"\bmc\s+(?:--?\S+\s+)*find(?=\s|$)"),
        // Disk usage
        safe_pattern!("mc-du", r"\bmc\s+(?:--?\S+\s+)*du(?=\s|$)"),
        // Version/help
        safe_pattern!("mc-version", r"\bmc\s+(?:--?\S+\s+)*version(?=\s|$)"),
        safe_pattern!("mc-help", r"\bmc\s+(?:--?\S+\s+)*(?:--help|-h)\b"),
        // Admin info (read-only)
        safe_pattern!(
            "mc-admin-info",
            r"\bmc\s+(?:--?\S+\s+)*admin\s+info(?=\s|$)"
        ),
        safe_pattern!(
            "mc-admin-user-list",
            r"\bmc\s+(?:--?\S+\s+)*admin\s+user\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "mc-admin-policy-list",
            r"\bmc\s+(?:--?\S+\s+)*admin\s+policy\s+list(?=\s|$)"
        ),
        // Alias management (config, not data)
        safe_pattern!(
            "mc-alias-list",
            r"\bmc\s+(?:--?\S+\s+)*alias\s+list(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Bucket removal
        destructive_pattern!(
            "mc-rb",
            r"\bmc\s+(?:--?\S+\s+)*rb\b",
            "mc rb removes a MinIO bucket.",
            Critical,
            "Removing a MinIO bucket deletes the bucket and all objects within it. With \
             --force, objects are deleted without confirmation. Applications referencing \
             this bucket will fail immediately.\n\n\
             Safer alternatives:\n\
             - mc ls: List bucket contents first\n\
             - mc cp --recursive: Backup to another location\n\
             - Enable versioning or object locking before testing"
        ),
        // Object removal
        destructive_pattern!(
            "mc-rm",
            r"\bmc\s+(?:--?\S+\s+)*rm\b",
            "mc rm deletes objects from MinIO.",
            High,
            "Deleting MinIO objects permanently removes data unless versioning is enabled. \
             With --recursive, entire directory trees are deleted. With --force, no \
             confirmation is requested.\n\n\
             Safer alternatives:\n\
             - mc ls: Preview files to be deleted\n\
             - mc cp: Backup objects before deletion\n\
             - Enable bucket versioning for recovery"
        ),
        // Admin bucket delete
        destructive_pattern!(
            "mc-admin-bucket-delete",
            r"\bmc\s+(?:--?\S+\s+)*admin\s+bucket\s+(?:delete|remove)\b",
            "mc admin bucket delete removes a bucket via admin API.",
            Critical,
            "The admin bucket delete command bypasses normal bucket deletion restrictions. \
             This can remove buckets that are protected or non-empty. The operation is \
             immediate and cannot be undone.\n\n\
             Safer alternatives:\n\
             - mc admin info: Review cluster configuration\n\
             - mc ls: Verify bucket contents first\n\
             - Use standard mc rb for safer deletion"
        ),
        // Mirror with remove (sync with delete)
        destructive_pattern!(
            "mc-mirror-remove",
            r"\bmc\s+(?:--?\S+\s+)*mirror\b.*--remove\b",
            "mc mirror --remove deletes destination objects not in source.",
            High,
            "The --remove flag deletes objects from the destination that don't exist in \
             the source. If source and destination are swapped, or source is empty, this \
             can result in complete data loss at the destination.\n\n\
             Safer alternatives:\n\
             - mc diff: Preview differences before mirroring\n\
             - mc mirror without --remove: Only adds/updates\n\
             - Backup destination before mirroring"
        ),
        // Admin user remove
        destructive_pattern!(
            "mc-admin-user-remove",
            r"\bmc\s+(?:--?\S+\s+)*admin\s+user\s+(?:remove|disable)\b",
            "mc admin user remove/disable affects user access.",
            High,
            "Removing or disabling a MinIO user revokes their access to all buckets and \
             policies. Applications using this user's credentials will fail to authenticate. \
             Service accounts created by this user may also be affected.\n\n\
             Safer alternatives:\n\
             - mc admin user info: Review user permissions first\n\
             - mc admin user disable: Disable instead of remove\n\
             - Rotate credentials before removing user"
        ),
        // Admin policy remove
        destructive_pattern!(
            "mc-admin-policy-remove",
            r"\bmc\s+(?:--?\S+\s+)*admin\s+policy\s+(?:remove|unset)\b",
            "mc admin policy remove/unset modifies access policies.",
            Medium,
            "Removing or unsetting a policy affects all users and groups assigned to it. \
             Users may unexpectedly lose access to buckets they need. Policy changes take \
             effect immediately.\n\n\
             Safer alternatives:\n\
             - mc admin policy info: Review policy details\n\
             - mc admin user list: Check who uses this policy\n\
             - Create replacement policy before removing old one"
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

    #[test]
    fn single_dash_flag_does_not_bypass() {
        // mc supports `-q` (quiet), `-j` (json output). The old
        // `(?:--\S+\s+)*` required `--` so single-dash forms fell through.
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "mc -q rb myminio/bucket", "mc-rb");
        assert_blocks_with_pattern(&pack, "mc -j rm myminio/bucket/file", "mc-rm");
    }

    #[test]
    fn minio_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "mc rb myminio/bucket",
            "mc rb removes a MinIO bucket",
        );
        assert_blocks(
            &pack,
            "mc rb --force myminio/bucket",
            "mc rb removes a MinIO bucket",
        );
        assert_blocks(
            &pack,
            "mc rm myminio/bucket/file.txt",
            "mc rm deletes objects from MinIO",
        );
        assert_blocks(
            &pack,
            "mc rm --recursive myminio/bucket/",
            "mc rm deletes objects from MinIO",
        );
        assert_blocks(
            &pack,
            "mc admin bucket delete myminio bucket",
            "mc admin bucket delete removes a bucket via admin API",
        );
        assert_blocks(
            &pack,
            "mc admin bucket remove myminio bucket",
            "mc admin bucket delete removes a bucket via admin API",
        );
        assert_blocks(
            &pack,
            "mc mirror --remove myminio/src myminio/dst",
            "mc mirror --remove deletes destination objects not in source",
        );
        assert_blocks(
            &pack,
            "mc admin user remove myminio username",
            "mc admin user remove/disable affects user access",
        );
        assert_blocks(
            &pack,
            "mc admin user disable myminio username",
            "mc admin user remove/disable affects user access",
        );
        assert_blocks(
            &pack,
            "mc admin policy remove myminio policyname",
            "mc admin policy remove/unset modifies access policies",
        );
        assert_blocks(
            &pack,
            "mc admin policy unset myminio policyname",
            "mc admin policy remove/unset modifies access policies",
        );
    }

    #[test]
    fn minio_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "mc rb myminio/bucket", Severity::Critical);
        assert_blocks_with_severity(&pack, "mc rm myminio/bucket/file.txt", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "mc admin bucket delete myminio bucket",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "mc mirror --remove myminio/src myminio/dst",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "mc admin user remove myminio username",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "mc admin policy remove myminio policyname",
            Severity::Medium,
        );
    }

    #[test]
    fn minio_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "mc ls myminio/bucket");
        assert_safe_pattern_matches(&pack, "mc cat myminio/bucket/file.txt");
        assert_safe_pattern_matches(&pack, "mc head myminio/bucket/file.txt");
        assert_safe_pattern_matches(&pack, "mc stat myminio/bucket/file.txt");
        assert_safe_pattern_matches(&pack, "mc cp localfile myminio/bucket/");
        assert_safe_pattern_matches(&pack, "mc diff myminio/bucket1 myminio/bucket2");
        assert_safe_pattern_matches(&pack, "mc find myminio/bucket --name '*.txt'");
        assert_safe_pattern_matches(&pack, "mc du myminio/bucket");
        assert_safe_pattern_matches(&pack, "mc version");
        assert_safe_pattern_matches(&pack, "mc --help");
        assert_safe_pattern_matches(&pack, "mc admin info myminio");
        assert_safe_pattern_matches(&pack, "mc admin user list myminio");
        assert_safe_pattern_matches(&pack, "mc admin policy list myminio");
        assert_safe_pattern_matches(&pack, "mc alias list");
    }

    #[test]
    fn minio_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "docker ps");
    }
}

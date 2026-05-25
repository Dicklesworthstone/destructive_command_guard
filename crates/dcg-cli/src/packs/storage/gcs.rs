//! Google Cloud Storage pack - protections for destructive GCS operations.
//!
//! Covers destructive operations:
//! - Bucket removal (gsutil rb, gcloud storage buckets delete)
//! - Object deletion (gsutil rm, gcloud storage rm)
//! - Recursive delete operations
//! - GA and release-track gcloud storage forms

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Google Cloud Storage pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "storage.gcs".to_string(),
        name: "Google Cloud Storage",
        description: "Protects against destructive GCS operations like bucket removal, \
                      object deletion, and recursive deletes.",
        keywords: &["gsutil", "gcloud"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand so a bucket/path containing the
    // subcommand keyword as a substring (e.g. `gs://ls-archive`,
    // `gs://cp-mirror/data`) doesn't short-circuit destructive gsutil
    // or gcloud storage ops via the safe rule.
    vec![
        // gsutil read operations
        safe_pattern!("gsutil-ls", r"gsutil\s+(?:-[a-zA-Z]+\s+)*ls(?=\s|$)"),
        safe_pattern!("gsutil-cat", r"gsutil\s+(?:-[a-zA-Z]+\s+)*cat(?=\s|$)"),
        safe_pattern!("gsutil-stat", r"gsutil\s+(?:-[a-zA-Z]+\s+)*stat(?=\s|$)"),
        safe_pattern!("gsutil-du", r"gsutil\s+(?:-[a-zA-Z]+\s+)*du(?=\s|$)"),
        safe_pattern!("gsutil-hash", r"gsutil\s+(?:-[a-zA-Z]+\s+)*hash(?=\s|$)"),
        safe_pattern!(
            "gsutil-version",
            r"gsutil\s+(?:-[a-zA-Z]+\s+)*version(?=\s|$)"
        ),
        safe_pattern!("gsutil-help", r"gsutil\s+(?:-[a-zA-Z]+\s+)*help(?=\s|$)"),
        // gsutil copy (read-only use)
        safe_pattern!("gsutil-cp", r"gsutil\s+(?:-[a-zA-Z]+\s+)*cp(?=\s|$)"),
        // gcloud storage read operations
        safe_pattern!(
            "gcloud-storage-buckets-list",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+buckets\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-storage-buckets-describe",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+buckets\s+describe(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-storage-objects-list",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+objects\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-storage-objects-describe",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+objects\s+describe(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-storage-ls",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+ls(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-storage-cat",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+cat(?=\s|$)"
        ),
        safe_pattern!(
            "gcloud-storage-cp",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+cp(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // gsutil bucket removal
        destructive_pattern!(
            "gsutil-rb",
            r"gsutil\b.*?\brb(?=\s|$)",
            "gsutil rb removes a GCS bucket.",
            Critical,
            "Removing a GCS bucket deletes the bucket and potentially all objects within it. \
             Bucket names are globally unique and may not be immediately available for reuse. \
             Applications and services referencing this bucket will fail.\n\n\
             Safer alternatives:\n\
             - gsutil ls gs://bucket: List bucket contents first\n\
             - gsutil -m cp -r gs://bucket ./backup: Backup contents locally\n\
             - Enable object versioning before testing deletions"
        ),
        // gsutil object removal. Require `rm` to be followed by whitespace
        // or end-of-string so `rm.txt` filenames in unrelated gsutil
        // invocations don't false-match.
        destructive_pattern!(
            "gsutil-rm",
            r"gsutil\b.*?\brm(?=\s|$)",
            "gsutil rm deletes objects from GCS.",
            High,
            "Deleting GCS objects permanently removes data unless versioning is enabled. \
             With -r flag, entire directory trees are deleted recursively. Without \
             versioning, deleted objects cannot be recovered.\n\n\
             Safer alternatives:\n\
             - gsutil ls: Preview what will be deleted\n\
             - Enable bucket versioning for recovery options\n\
             - gsutil mv: Move to archive bucket instead of deleting"
        ),
        // gsutil rsync with delete
        destructive_pattern!(
            "gsutil-rsync-delete",
            r"gsutil\b.*?\brsync\b.*\s+-d\b",
            "gsutil rsync -d deletes destination objects not in source.",
            High,
            "The -d flag with gsutil rsync deletes destination objects that don't exist \
             in the source. If source and destination are swapped, or source is empty, \
             this can result in total data loss at the destination.\n\n\
             Safer alternatives:\n\
             - gsutil rsync -n -d: Dry run to preview deletions\n\
             - gsutil rsync without -d: Only adds/updates, never deletes\n\
             - Backup destination before syncing"
        ),
        // gcloud storage bucket deletion
        destructive_pattern!(
            "gcloud-storage-buckets-delete",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+buckets\s+delete\b",
            "gcloud storage buckets delete removes a GCS bucket.",
            Critical,
            "Deleting a GCS bucket removes the bucket configuration and all objects within it \
             (if --recursive is used). The globally unique bucket name may not be immediately \
             reclaimable. All dependent applications will fail.\n\n\
             Safer alternatives:\n\
             - gcloud storage buckets describe: Review bucket configuration\n\
             - gcloud storage cp -r: Backup contents before deletion\n\
             - Remove objects first to understand data being deleted"
        ),
        // gcloud storage object deletion
        destructive_pattern!(
            "gcloud-storage-objects-delete",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+objects\s+delete\b",
            "gcloud storage objects delete removes objects from GCS.",
            High,
            "Deleting GCS objects permanently removes data. Without object versioning, \
             deleted files cannot be recovered. Production data should be backed up \
             before deletion.\n\n\
             Safer alternatives:\n\
             - gcloud storage objects describe: Verify object before deletion\n\
             - Enable bucket versioning for soft deletes\n\
             - Move to archive storage class instead of deleting"
        ),
        // gcloud storage rm
        destructive_pattern!(
            "gcloud-storage-rm",
            r"gcloud\b(?:\s+--?\S+(?:\s+\S+)?)*(?:\s+(?:alpha|beta)(?:\s+--?\S+(?:\s+\S+)?)*)?\s+storage\s+rm\b",
            "gcloud storage rm removes objects from GCS.",
            High,
            "The rm command deletes objects and can recursively remove entire bucket \
             contents. Deleted objects are permanently lost unless versioning is enabled. \
             Wildcards can unexpectedly match more files than intended.\n\n\
             Safer alternatives:\n\
             - gcloud storage ls: Preview files matching pattern\n\
             - Enable bucket versioning before testing\n\
             - gcloud storage mv: Move to archive bucket instead"
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
        assert_eq!(pack.id, "storage.gcs");
        assert_eq!(pack.name, "Google Cloud Storage");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"gsutil"));
        assert!(pack.keywords.contains(&"gcloud"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // gsutil read operations
        assert_safe_pattern_matches(&pack, "gsutil ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gsutil -m ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gsutil cat gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gsutil stat gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gsutil du -s gs://bucket");
        assert_safe_pattern_matches(&pack, "gsutil hash gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gsutil version");
        assert_safe_pattern_matches(&pack, "gsutil help");
        assert_safe_pattern_matches(&pack, "gsutil cp gs://bucket/file ./local");
        // gcloud storage read operations
        assert_safe_pattern_matches(&pack, "gcloud storage buckets list");
        assert_safe_pattern_matches(&pack, "gcloud storage buckets describe gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud storage objects list gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud storage objects describe gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gcloud storage ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud storage cat gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gcloud storage cp gs://bucket/file ./local");
        assert_safe_pattern_matches(&pack, "gcloud --project prod storage buckets list");
        assert_safe_pattern_matches(&pack, "gcloud alpha storage buckets list");
        assert_safe_pattern_matches(&pack, "gcloud alpha --project prod storage buckets list");
        assert_safe_pattern_matches(&pack, "gcloud beta storage ls gs://bucket");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // gsutil destructive
        assert_blocks_with_pattern(&pack, "gsutil rb gs://bucket", "gsutil-rb");
        assert_blocks_with_pattern(&pack, "gsutil -f rb gs://bucket", "gsutil-rb");
        assert_blocks_with_pattern(&pack, "gsutil rm gs://bucket/file", "gsutil-rm");
        assert_blocks_with_pattern(&pack, "gsutil -m rm -r gs://bucket", "gsutil-rm");

        // Should NOT match: `rb` and `rm` appearing as substrings in filenames
        // of unrelated subcommands (e.g. `gsutil cors set rb.json`).
        assert!(
            pack.check("gsutil cors set rb.json").is_none(),
            "gsutil cors set rb.json should not false-match gsutil-rb"
        );
        assert!(
            pack.check("gsutil cp rm.txt gs://bucket/").is_none(),
            "gsutil cp rm.txt should not false-match gsutil-rm"
        );
        assert_blocks_with_pattern(
            &pack,
            "gsutil rsync -d gs://src gs://dst",
            "gsutil-rsync-delete",
        );
        // gcloud storage destructive
        assert_blocks_with_pattern(
            &pack,
            "gcloud storage buckets delete gs://bucket",
            "gcloud-storage-buckets-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud storage objects delete gs://bucket/file",
            "gcloud-storage-objects-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud storage rm gs://bucket/file",
            "gcloud-storage-rm",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud --project prod storage rm gs://bucket/file",
            "gcloud-storage-rm",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud alpha storage buckets delete gs://bucket",
            "gcloud-storage-buckets-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud alpha --project prod storage buckets delete gs://bucket",
            "gcloud-storage-buckets-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "gcloud beta storage rm gs://bucket/file",
            "gcloud-storage-rm",
        );
    }

    #[test]
    fn gcs_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "gsutil rb gs://bucket",
            "gsutil rb removes a GCS bucket",
        );
        assert_blocks(
            &pack,
            "gsutil -f rb gs://bucket",
            "gsutil rb removes a GCS bucket",
        );
        assert_blocks(
            &pack,
            "gsutil rm gs://bucket/file",
            "gsutil rm deletes objects from GCS",
        );
        assert_blocks(
            &pack,
            "gsutil -m rm -r gs://bucket",
            "gsutil rm deletes objects from GCS",
        );
        assert_blocks(
            &pack,
            "gsutil rsync -d gs://src gs://dst",
            "gsutil rsync -d deletes destination objects not in source",
        );
        assert_blocks(
            &pack,
            "gcloud storage buckets delete gs://bucket",
            "gcloud storage buckets delete removes a GCS bucket",
        );
        assert_blocks(
            &pack,
            "gcloud storage objects delete gs://bucket/file",
            "gcloud storage objects delete removes objects from GCS",
        );
        assert_blocks(
            &pack,
            "gcloud storage rm gs://bucket/file",
            "gcloud storage rm removes objects from GCS",
        );
        assert_blocks(
            &pack,
            "gcloud alpha storage rm gs://bucket/file",
            "gcloud storage rm removes objects from GCS",
        );
        assert_blocks(
            &pack,
            "gcloud alpha --project prod storage rm gs://bucket/file",
            "gcloud storage rm removes objects from GCS",
        );
    }

    #[test]
    fn gcs_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "gsutil rb gs://bucket", Severity::Critical);
        assert_blocks_with_severity(&pack, "gsutil rm gs://bucket/file", Severity::High);
        assert_blocks_with_severity(&pack, "gsutil rsync -d gs://src gs://dst", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gcloud storage buckets delete gs://bucket",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "gcloud storage objects delete gs://bucket/file",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "gcloud storage rm gs://bucket/file", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "gcloud alpha storage buckets delete gs://bucket",
            Severity::Critical,
        );
    }

    #[test]
    fn gcs_all_safe_patterns_match() {
        let pack = create_pack();
        // gsutil safe patterns
        assert_safe_pattern_matches(&pack, "gsutil ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gsutil cat gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gsutil stat gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gsutil du gs://bucket");
        assert_safe_pattern_matches(&pack, "gsutil hash gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gsutil version");
        assert_safe_pattern_matches(&pack, "gsutil help");
        assert_safe_pattern_matches(&pack, "gsutil cp gs://bucket/file ./local");
        // gcloud storage safe patterns
        assert_safe_pattern_matches(&pack, "gcloud storage buckets list");
        assert_safe_pattern_matches(&pack, "gcloud storage buckets describe gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud storage objects list gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud storage objects describe gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gcloud storage ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud storage cat gs://bucket/file");
        assert_safe_pattern_matches(&pack, "gcloud storage cp gs://bucket/file ./local");
        assert_safe_pattern_matches(&pack, "gcloud --project prod storage ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud alpha storage ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud alpha --project prod storage ls gs://bucket");
        assert_safe_pattern_matches(&pack, "gcloud beta storage buckets describe gs://bucket");
    }

    #[test]
    fn gcs_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "docker ps");
    }
}

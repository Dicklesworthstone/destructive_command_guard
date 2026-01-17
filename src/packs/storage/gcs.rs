//! Google Cloud Storage pack - protections for destructive GCS operations.
//!
//! Covers destructive operations:
//! - Bucket removal (gsutil rb, gcloud storage buckets delete)
//! - Object deletion (gsutil rm, gcloud storage rm)
//! - Recursive delete operations

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
        keywords: &["gsutil", "gcloud storage"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // gsutil read operations
        safe_pattern!("gsutil-ls", r"gsutil\s+(?:-[a-zA-Z]+\s+)*ls\b"),
        safe_pattern!("gsutil-cat", r"gsutil\s+(?:-[a-zA-Z]+\s+)*cat\b"),
        safe_pattern!("gsutil-stat", r"gsutil\s+(?:-[a-zA-Z]+\s+)*stat\b"),
        safe_pattern!("gsutil-du", r"gsutil\s+(?:-[a-zA-Z]+\s+)*du\b"),
        safe_pattern!("gsutil-hash", r"gsutil\s+(?:-[a-zA-Z]+\s+)*hash\b"),
        safe_pattern!("gsutil-version", r"gsutil\s+(?:-[a-zA-Z]+\s+)*version\b"),
        safe_pattern!("gsutil-help", r"gsutil\s+(?:-[a-zA-Z]+\s+)*help\b"),
        // gsutil copy (read-only use)
        safe_pattern!("gsutil-cp", r"gsutil\s+(?:-[a-zA-Z]+\s+)*cp\b"),
        // gcloud storage read operations
        safe_pattern!(
            "gcloud-storage-buckets-list",
            r"gcloud\s+storage\s+buckets\s+list\b"
        ),
        safe_pattern!(
            "gcloud-storage-buckets-describe",
            r"gcloud\s+storage\s+buckets\s+describe\b"
        ),
        safe_pattern!(
            "gcloud-storage-objects-list",
            r"gcloud\s+storage\s+objects\s+list\b"
        ),
        safe_pattern!(
            "gcloud-storage-objects-describe",
            r"gcloud\s+storage\s+objects\s+describe\b"
        ),
        safe_pattern!("gcloud-storage-ls", r"gcloud\s+storage\s+ls\b"),
        safe_pattern!("gcloud-storage-cat", r"gcloud\s+storage\s+cat\b"),
        safe_pattern!("gcloud-storage-cp", r"gcloud\s+storage\s+cp\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // gsutil bucket removal
        destructive_pattern!(
            "gsutil-rb",
            r"gsutil\s+(?:-[a-zA-Z]+\s+)*rb\b",
            "gsutil rb removes a GCS bucket."
        ),
        // gsutil object removal
        destructive_pattern!(
            "gsutil-rm",
            r"gsutil\s+(?:-[a-zA-Z]+\s+)*rm\b",
            "gsutil rm deletes objects from GCS."
        ),
        // gsutil rsync with delete
        destructive_pattern!(
            "gsutil-rsync-delete",
            r"gsutil\s+(?:-[a-zA-Z]+\s+)*rsync\b.*\s+-d\b",
            "gsutil rsync -d deletes destination objects not in source."
        ),
        // gcloud storage bucket deletion
        destructive_pattern!(
            "gcloud-storage-buckets-delete",
            r"gcloud\s+storage\s+buckets\s+delete\b",
            "gcloud storage buckets delete removes a GCS bucket."
        ),
        // gcloud storage object deletion
        destructive_pattern!(
            "gcloud-storage-objects-delete",
            r"gcloud\s+storage\s+objects\s+delete\b",
            "gcloud storage objects delete removes objects from GCS."
        ),
        // gcloud storage rm
        destructive_pattern!(
            "gcloud-storage-rm",
            r"gcloud\s+storage\s+rm\b",
            "gcloud storage rm removes objects from GCS."
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
        assert_eq!(pack.id, "storage.gcs");
        assert_eq!(pack.name, "Google Cloud Storage");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"gsutil"));

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
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // gsutil destructive
        assert_blocks_with_pattern(&pack, "gsutil rb gs://bucket", "gsutil-rb");
        assert_blocks_with_pattern(&pack, "gsutil -f rb gs://bucket", "gsutil-rb");
        assert_blocks_with_pattern(&pack, "gsutil rm gs://bucket/file", "gsutil-rm");
        assert_blocks_with_pattern(&pack, "gsutil -m rm -r gs://bucket", "gsutil-rm");
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
    }
}

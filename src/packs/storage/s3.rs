//! `AWS S3` pack - protections for destructive bucket and object operations.
//!
//! Covers destructive CLI operations:
//! - Bucket removal
//! - Recursive object deletion
//! - API object deletion
//! - Sync with delete

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `AWS S3` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "storage.s3".to_string(),
        name: "AWS S3",
        description: "Protects against destructive S3 operations like bucket removal, recursive deletes, and sync --delete.",
        keywords: &[
            "s3",
            "s3api",
            "rb",
            "delete-bucket",
            "delete-object",
            "delete-objects",
            "--delete",
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
    // `(?=\s|$)` on each subcommand so a bucket/key path containing the
    // subcommand keyword as a substring doesn't short-circuit destructive
    // s3/s3api ops. `s3api-head-object(?=\s|$)` also prevents matching the
    // prefix of unrelated subcommands like `head-object-v5` (hypothetical).
    vec![
        safe_pattern!("s3-list", r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+ls(?=\s|$)"),
        safe_pattern!("s3-copy", r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+cp(?=\s|$)"),
        safe_pattern!(
            "s3-presign",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+presign(?=\s|$)"
        ),
        safe_pattern!("s3-mb", r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+mb(?=\s|$)"),
        safe_pattern!(
            "s3-rm-dryrun",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+rm(?=\s|$)[^\n;&|]*\s--dryrun(?=\s|$)"
        ),
        safe_pattern!(
            "s3-sync-delete-dryrun",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+sync(?=\s|$)[^\n;&|]*\s--delete(?=\s|$)[^\n;&|]*\s--dryrun(?=\s|$)"
        ),
        safe_pattern!(
            "s3-sync-dryrun-delete",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+sync(?=\s|$)[^\n;&|]*\s--dryrun(?=\s|$)[^\n;&|]*\s--delete(?=\s|$)"
        ),
        safe_pattern!(
            "s3api-list-objects",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3api\s+list-objects(?:-v2)?(?=\s|$)"
        ),
        safe_pattern!(
            "s3api-get-object",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3api\s+get-object(?=\s|$)"
        ),
        safe_pattern!(
            "s3api-head-object",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3api\s+head-object(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "s3-rb",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+rb\b",
            "aws s3 rb removes an S3 bucket and is destructive.",
            Critical,
            "Removing an S3 bucket deletes the bucket and optionally all objects within \
             it (with --force). Bucket names are globally unique and may be claimed by \
             others after deletion. Versioned objects require additional cleanup.\n\n\
             Safer alternatives:\n\
             - aws s3 ls: Review bucket contents first\n\
             - Empty the bucket before removal\n\
             - Enable bucket versioning for recovery options"
        ),
        destructive_pattern!(
            "s3-rm",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+rm\b",
            "aws s3 rm deletes S3 objects and is destructive.",
            High,
            "The rm command deletes objects from S3. With --recursive, it deletes all \
             objects under a prefix. For versioned buckets, this creates delete markers; \
             for unversioned buckets, data is permanently lost.\n\n\
             Safer alternatives:\n\
             - aws s3 ls: Review objects before deletion\n\
             - Use --dryrun to preview what will be deleted\n\
             - Enable versioning for recovery options"
        ),
        destructive_pattern!(
            "s3-sync-delete",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3\s+sync\b(?:\s+[^\n]*)?\s+--delete\b",
            "aws s3 sync --delete removes destination objects not in source.",
            High,
            "The --delete flag removes files from the destination that don't exist in \
             the source. This can accidentally delete important data if source and \
             destination are swapped or if source is empty.\n\n\
             Safer alternatives:\n\
             - aws s3 sync --dryrun: Preview changes first\n\
             - Omit --delete for additive-only sync\n\
             - Back up destination before syncing"
        ),
        destructive_pattern!(
            "s3api-delete-bucket",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3api\s+delete-bucket\b",
            "aws s3api delete-bucket permanently deletes a bucket.",
            Critical,
            "The delete-bucket API removes an S3 bucket. The bucket must be empty \
             (including all versions and delete markers). Once deleted, the bucket \
             name becomes available globally and may be claimed by others.\n\n\
             Safer alternatives:\n\
             - aws s3api list-objects-v2: Verify bucket is empty\n\
             - aws s3api list-object-versions: Check for versions\n\
             - Use lifecycle policies for managed cleanup"
        ),
        destructive_pattern!(
            "s3api-delete-object",
            // `(?=\s|$)` so unrelated subcommands that start with
            // `delete-object` — e.g. `delete-object-tagging` (which only
            // removes tags, not the object) — don't false-match this rule.
            // The batch `delete-objects` (plural) has its own pattern below.
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3api\s+delete-object(?=\s|$)",
            "aws s3api delete-object permanently deletes an object.",
            Medium,
            "Deleting an object removes it from S3. For versioned buckets, this creates \
             a delete marker. Specifying a version-id permanently deletes that specific \
             version. Unversioned objects are immediately and permanently deleted.\n\n\
             Safer alternatives:\n\
             - aws s3api head-object: Verify object exists\n\
             - Use bucket versioning for recovery\n\
             - Copy to backup location before deletion"
        ),
        destructive_pattern!(
            "s3api-delete-objects",
            r"aws(?:\s+--?\S+(?:\s+\S+)?)*\s+s3api\s+delete-objects\b",
            "aws s3api delete-objects permanently deletes multiple objects.",
            High,
            "Batch deletion removes up to 1,000 objects per request. A malformed delete \
             JSON file can remove unintended objects. Deletions are processed in \
             parallel and cannot be easily stopped once started.\n\n\
             Safer alternatives:\n\
             - Review the delete JSON file carefully\n\
             - Test with a single object first\n\
             - Enable versioning before bulk deletions"
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
        assert_eq!(pack.id, "storage.s3");
        assert_eq!(pack.name, "AWS S3");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"s3"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws s3 ls");
        assert_safe_pattern_matches(&pack, "aws s3 cp file s3://bucket/key");
        assert_safe_pattern_matches(&pack, "aws s3 presign s3://bucket/key");
        assert_safe_pattern_matches(&pack, "aws s3 mb s3://new-bucket");
        assert_safe_pattern_matches(&pack, "aws s3 rm s3://bucket/key --dryrun");
        assert_safe_pattern_matches(&pack, "aws s3 rm s3://bucket --recursive --dryrun");
        assert_safe_pattern_matches(&pack, "aws s3 sync ./dist s3://bucket --delete --dryrun");
        assert_safe_pattern_matches(&pack, "aws s3 sync ./dist s3://bucket --dryrun --delete");
        assert_safe_pattern_matches(&pack, "aws s3api list-objects-v2 --bucket bucket");
        assert_safe_pattern_matches(&pack, "aws s3api get-object --bucket b --key k out");
        assert_safe_pattern_matches(&pack, "aws s3api head-object --bucket b --key k");
        assert_allows(&pack, "aws s3 sync s3://src s3://dest");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "aws s3 rb s3://bucket", "s3-rb");
        assert_blocks_with_pattern(&pack, "aws s3 rb s3://bucket --force", "s3-rb");
        assert_blocks_with_pattern(&pack, "aws s3 rm s3://bucket/key", "s3-rm");
        assert_blocks_with_pattern(&pack, "aws s3 rm s3://bucket --recursive", "s3-rm");
        assert_blocks_with_pattern(
            &pack,
            "aws s3 sync s3://src s3://dest --delete",
            "s3-sync-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws s3api delete-bucket --bucket bucket",
            "s3api-delete-bucket",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws s3api delete-object --bucket bucket --key key",
            "s3api-delete-object",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws s3api delete-objects --bucket bucket --delete file://d.json",
            "s3api-delete-objects",
        );
    }

    #[test]
    fn s3_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws s3 rb s3://my-bucket",
            "aws s3 rb removes an S3 bucket",
        );
        assert_blocks(
            &pack,
            "aws s3 rb s3://my-bucket --force",
            "aws s3 rb removes an S3 bucket",
        );
        assert_blocks(
            &pack,
            "aws s3 rm s3://bucket/key",
            "aws s3 rm deletes S3 objects",
        );
        assert_blocks(
            &pack,
            "aws s3 rm s3://bucket --recursive",
            "aws s3 rm deletes S3 objects",
        );
        assert_blocks(
            &pack,
            "aws s3 sync s3://src s3://dest --delete",
            "aws s3 sync --delete removes destination objects",
        );
        assert_blocks(
            &pack,
            "aws s3api delete-bucket --bucket bucket",
            "aws s3api delete-bucket permanently deletes a bucket",
        );
        assert_blocks(
            &pack,
            "aws s3api delete-object --bucket bucket --key key",
            "aws s3api delete-object permanently deletes an object",
        );
        assert_blocks(
            &pack,
            "aws s3api delete-objects --bucket bucket --delete file://d.json",
            "aws s3api delete-objects permanently deletes multiple objects",
        );
    }

    #[test]
    fn s3_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "aws s3 rb s3://my-bucket", Severity::Critical);
        assert_blocks_with_severity(&pack, "aws s3 rm s3://bucket/key", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "aws s3 sync s3://src s3://dest --delete",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "aws s3api delete-bucket --bucket bucket",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "aws s3api delete-object --bucket b --key k",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "aws s3api delete-objects --bucket b --delete file://d.json",
            Severity::High,
        );
    }

    #[test]
    fn s3_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "aws s3 ls");
        assert_safe_pattern_matches(&pack, "aws s3 ls s3://bucket");
        assert_safe_pattern_matches(&pack, "aws s3 cp file.txt s3://bucket/key");
        assert_safe_pattern_matches(&pack, "aws s3 presign s3://bucket/key");
        assert_safe_pattern_matches(&pack, "aws s3 mb s3://new-bucket");
        assert_safe_pattern_matches(&pack, "aws s3 rm s3://bucket/key --dryrun");
        assert_safe_pattern_matches(&pack, "aws s3 rm s3://bucket --recursive --dryrun");
        assert_safe_pattern_matches(&pack, "aws s3 sync ./dist s3://bucket --delete --dryrun");
        assert_safe_pattern_matches(&pack, "aws s3 sync ./dist s3://bucket --dryrun --delete");
        assert_safe_pattern_matches(&pack, "aws s3api list-objects-v2 --bucket bucket");
        assert_safe_pattern_matches(&pack, "aws s3api list-objects --bucket bucket");
        assert_safe_pattern_matches(&pack, "aws s3api get-object --bucket b --key k out");
        assert_safe_pattern_matches(&pack, "aws s3api head-object --bucket b --key k");
    }

    #[test]
    fn s3_dryrun_false_does_not_bypass_destructive_patterns() {
        let pack = create_pack();
        assert_no_safe_match(&pack, "aws s3 rm s3://bucket/key --dryrun=false");
        assert_blocks_with_pattern(&pack, "aws s3 rm s3://bucket/key --dryrun=false", "s3-rm");
        assert_no_safe_match(&pack, "aws s3 rm s3://bucket/key --no-dryrun");
        assert_blocks_with_pattern(&pack, "aws s3 rm s3://bucket/key --no-dryrun", "s3-rm");
        assert_no_safe_match(
            &pack,
            "aws s3 sync ./dist s3://bucket --delete --dryrun=false",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws s3 sync ./dist s3://bucket --delete --dryrun=false",
            "s3-sync-delete",
        );
        assert_no_safe_match(
            &pack,
            "aws s3 sync ./dist s3://bucket --dryrun=false --delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "aws s3 sync ./dist s3://bucket --dryrun=false --delete",
            "s3-sync-delete",
        );
    }

    #[test]
    fn s3_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "docker ps");
    }
}

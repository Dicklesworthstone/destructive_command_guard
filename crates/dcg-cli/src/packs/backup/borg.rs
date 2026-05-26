//! `BorgBackup` pack - protections for destructive archive operations.
//!
//! Covers destructive CLI operations:
//! - Archive and repository deletion
//! - Prune/compact cleanup
//! - Archive recreate (can drop data)
//! - Break-lock operations

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `BorgBackup` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "backup.borg".to_string(),
        name: "BorgBackup",
        description: "Protects against destructive borg operations like delete, prune, compact, and recreate.",
        keywords: &["borg"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand so an archive name containing the
    // subcommand keyword as a substring (e.g. `list-archives`,
    // `info-backup`) doesn't short-circuit destructive borg ops via the
    // safe rule.
    vec![
        safe_pattern!("borg-list", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+list(?=\s|$)"),
        safe_pattern!("borg-info", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+info(?=\s|$)"),
        safe_pattern!("borg-diff", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)"),
        safe_pattern!(
            "borg-check",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+check(?=\s|$)"
        ),
        safe_pattern!(
            "borg-create",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+create(?=\s|$)"
        ),
        safe_pattern!(
            "borg-extract",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+extract(?=\s|$)"
        ),
        safe_pattern!(
            "borg-mount",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+mount(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "borg-delete",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "borg delete removes archives or entire repositories.",
            Critical,
            "Deleting borg archives or repositories permanently removes backup data. Without \
             the archive, you cannot restore files to that point in time. If you delete the \
             entire repository, all backup history is lost and cannot be recovered.\n\n\
             Safer alternatives:\n\
             - borg list: Review archives before deletion\n\
             - borg info: Check archive details and size\n\
             - borg export-tar: Export archive contents before deletion\n\
             - Use --dry-run to preview what would be deleted"
        ),
        destructive_pattern!(
            "borg-prune",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+prune\b",
            "borg prune removes archives based on retention rules.",
            High,
            "Pruning removes archives that don't match retention rules. Misconfigured retention \
             policies can delete more archives than intended. Once pruned, those backup points \
             cannot be restored. Space is not reclaimed until borg compact is run.\n\n\
             Safer alternatives:\n\
             - borg prune --dry-run: Preview which archives would be removed\n\
             - borg list: Review current archives before pruning\n\
             - Double-check retention flags (--keep-daily, --keep-weekly, etc.)"
        ),
        destructive_pattern!(
            "borg-compact",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+compact\b",
            "borg compact reclaims space after deletions.",
            Medium,
            "Compacting permanently removes data segments that are no longer referenced after \
             delete or prune operations. Before compacting, deleted data could theoretically \
             be recovered. After compacting, the data is permanently gone and disk space is \
             reclaimed.\n\n\
             Safer alternatives:\n\
             - borg list: Verify intended archives still exist\n\
             - borg check: Verify repository integrity before compacting\n\
             - Ensure all pruning was intentional before compacting"
        ),
        destructive_pattern!(
            "borg-recreate",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+recreate\b",
            "borg recreate can drop data from archives.",
            High,
            "Recreate modifies existing archives by recompressing or excluding files. Using \
             --exclude or --exclude-from can permanently remove files from the archive. The \
             original archive state cannot be recovered after recreation completes.\n\n\
             Safer alternatives:\n\
             - borg recreate --dry-run: Preview changes without applying\n\
             - borg create: Create a new archive instead of modifying existing\n\
             - borg export-tar: Export archive before recreation for backup"
        ),
        destructive_pattern!(
            "borg-break-lock",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+break-lock\b",
            "borg break-lock forces removal of repository locks.",
            Medium,
            "Breaking locks removes lock files that protect against concurrent access. If \
             another borg process is actually running (not a stale lock), breaking the lock \
             can cause repository corruption. Only use when certain no other operation is \
             in progress.\n\n\
             Safer alternatives:\n\
             - Check for running borg processes (ps aux | grep borg)\n\
             - Wait for existing operations to complete\n\
             - Verify lock is stale (check lock file timestamp)"
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
        assert_eq!(pack.id, "backup.borg");
        assert_eq!(pack.name, "BorgBackup");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"borg"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "borg list ::");
        assert_safe_pattern_matches(&pack, "borg info repo::archive");
        assert_safe_pattern_matches(&pack, "borg diff repo::a repo::b");
        assert_safe_pattern_matches(&pack, "borg check repo");
        assert_safe_pattern_matches(&pack, "borg create repo::archive /srv/app");
        assert_safe_pattern_matches(&pack, "borg extract repo::archive");
        assert_safe_pattern_matches(&pack, "borg mount repo::archive /mnt/backup");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "borg delete repo::old", "borg-delete");
        assert_blocks_with_pattern(&pack, "borg prune repo", "borg-prune");
        assert_blocks_with_pattern(&pack, "borg compact repo", "borg-compact");
        assert_blocks_with_pattern(
            &pack,
            "borg recreate repo::archive --exclude /tmp",
            "borg-recreate",
        );
        assert_blocks_with_pattern(&pack, "borg break-lock repo", "borg-break-lock");
    }

    #[test]
    fn borg_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "borg delete repo::old",
            "borg delete removes archives",
        );
        assert_blocks(&pack, "borg prune repo", "borg prune removes archives");
        assert_blocks(&pack, "borg compact repo", "borg compact reclaims space");
        assert_blocks(
            &pack,
            "borg recreate repo::archive --exclude /tmp",
            "borg recreate can drop data",
        );
        assert_blocks(
            &pack,
            "borg break-lock repo",
            "borg break-lock forces removal",
        );
    }

    #[test]
    fn borg_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "borg delete repo::old", Severity::Critical);
        assert_blocks_with_severity(&pack, "borg prune repo", Severity::High);
        assert_blocks_with_severity(&pack, "borg compact repo", Severity::Medium);
        assert_blocks_with_severity(
            &pack,
            "borg recreate repo::archive --exclude /tmp",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "borg break-lock repo", Severity::Medium);
    }

    #[test]
    fn borg_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "borg list");
        assert_safe_pattern_matches(&pack, "borg info repo");
        assert_safe_pattern_matches(&pack, "borg diff repo::a repo::b");
        assert_safe_pattern_matches(&pack, "borg check repo");
        assert_safe_pattern_matches(&pack, "borg create repo::archive /data");
        assert_safe_pattern_matches(&pack, "borg extract repo::archive");
        assert_safe_pattern_matches(&pack, "borg mount repo::archive /mnt");
        // With flags before subcommand
        assert_safe_pattern_matches(&pack, "borg --verbose list ::");
        assert_safe_pattern_matches(&pack, "borg -v info repo::archive");
    }

    #[test]
    fn borg_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
    }
}

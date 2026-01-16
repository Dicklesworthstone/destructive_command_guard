//! `Restic` pack - protections for destructive backup operations.
//!
//! Covers destructive CLI operations:
//! - Snapshot removal (forget)
//! - Prune operations
//! - Key removal
//! - Unlock remove-all
//! - Cache cleanup

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Restic` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "backup.restic".to_string(),
        name: "Restic",
        description: "Protects against destructive restic operations like forgetting snapshots, pruning data, removing keys, and cache cleanup.",
        keywords: &["restic"],
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
            "restic-snapshots",
            r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+snapshots\b"
        ),
        safe_pattern!("restic-ls", r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+ls\b"),
        safe_pattern!("restic-stats", r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+stats\b"),
        safe_pattern!("restic-check", r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+check\b"),
        safe_pattern!("restic-diff", r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+diff\b"),
        safe_pattern!("restic-find", r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+find\b"),
        safe_pattern!(
            "restic-backup",
            r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+backup\b"
        ),
        safe_pattern!(
            "restic-restore",
            r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+restore\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "restic-forget",
            r"restic\b.*\sforget\b",
            "restic forget removes snapshots and can permanently delete backup data."
        ),
        destructive_pattern!(
            "restic-prune",
            r"restic\b.*\sprune\b",
            "restic prune removes unreferenced data and is irreversible."
        ),
        destructive_pattern!(
            "restic-key-remove",
            r"restic\b.*\skey\b.*\sremove\b",
            "restic key remove deletes encryption keys and can make backups unrecoverable."
        ),
        destructive_pattern!(
            "restic-unlock-remove-all",
            r"restic\b.*\sunlock\b.*\s--remove-all\b",
            "restic unlock --remove-all force-removes repository locks."
        ),
        destructive_pattern!(
            "restic-cache-cleanup",
            r"restic\b.*\scache\b.*\s--cleanup\b",
            "restic cache --cleanup removes cached data from disk."
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
        assert_eq!(pack.id, "backup.restic");
        assert_eq!(pack.name, "Restic");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"restic"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "restic snapshots");
        assert_safe_pattern_matches(&pack, "restic ls latest");
        assert_safe_pattern_matches(&pack, "restic stats --mode restore-size");
        assert_safe_pattern_matches(&pack, "restic check --read-data");
        assert_safe_pattern_matches(&pack, "restic diff snap1 snap2");
        assert_safe_pattern_matches(&pack, "restic find --name config.yml");
        assert_safe_pattern_matches(&pack, "restic backup /srv/app");
        assert_safe_pattern_matches(&pack, "restic restore latest --target /tmp/out");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "restic forget latest", "restic-forget");
        assert_blocks_with_pattern(
            &pack,
            "restic forget --keep-last 3 --prune",
            "restic-forget",
        );
        assert_blocks_with_pattern(&pack, "restic prune", "restic-prune");
        assert_blocks_with_pattern(&pack, "restic key remove 1", "restic-key-remove");
        assert_blocks_with_pattern(
            &pack,
            "restic unlock --remove-all",
            "restic-unlock-remove-all",
        );
        assert_blocks_with_pattern(&pack, "restic cache --cleanup", "restic-cache-cleanup");
    }
}

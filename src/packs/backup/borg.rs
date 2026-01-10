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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("borg-list", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+list\b"),
        safe_pattern!("borg-info", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+info\b"),
        safe_pattern!("borg-diff", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+diff\b"),
        safe_pattern!("borg-check", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+check\b"),
        safe_pattern!("borg-create", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+create\b"),
        safe_pattern!("borg-extract", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+extract\b"),
        safe_pattern!("borg-mount", r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+mount\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "borg-delete",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "borg delete removes archives or entire repositories."
        ),
        destructive_pattern!(
            "borg-prune",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+prune\b",
            "borg prune removes archives based on retention rules."
        ),
        destructive_pattern!(
            "borg-compact",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+compact\b",
            "borg compact reclaims space after deletions."
        ),
        destructive_pattern!(
            "borg-recreate",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+recreate\b",
            "borg recreate can drop data from archives."
        ),
        destructive_pattern!(
            "borg-break-lock",
            r"borg(?:\s+--?\S+(?:\s+\S+)?)*\s+break-lock\b",
            "borg break-lock forces removal of repository locks."
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
}

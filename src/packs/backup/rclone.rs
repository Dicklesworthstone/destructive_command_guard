//! `Rclone` pack - protections for destructive sync operations.
//!
//! Covers destructive CLI operations:
//! - Sync (deletes destination files not in source)
//! - Delete/purge/cleanup
//! - Dedupe (can remove duplicates)
//! - Move (deletes source after copy)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Rclone` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "backup.rclone".to_string(),
        name: "Rclone",
        description: "Protects against destructive rclone operations like sync, delete, purge, dedupe, and move.",
        keywords: &["rclone"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("rclone-copy", r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+copy\b"),
        safe_pattern!("rclone-ls", r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+ls\b"),
        safe_pattern!("rclone-lsd", r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+lsd\b"),
        safe_pattern!("rclone-lsl", r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+lsl\b"),
        safe_pattern!("rclone-size", r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+size\b"),
        safe_pattern!("rclone-check", r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+check\b"),
        safe_pattern!(
            "rclone-config",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+config\b"
        ),
        safe_pattern!("rclone-dry-run", r"rclone\b(?:\s+\S+)*\s+--dry-run\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "rclone-sync",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+sync\b",
            "rclone sync deletes destination files not present in the source."
        ),
        destructive_pattern!(
            "rclone-delete",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "rclone delete removes files and directories from the target."
        ),
        destructive_pattern!(
            "rclone-deletefile",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+deletefile\b",
            "rclone deletefile removes a single file from the target."
        ),
        destructive_pattern!(
            "rclone-purge",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+purge\b",
            "rclone purge deletes a path and all its contents."
        ),
        destructive_pattern!(
            "rclone-cleanup",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+cleanup\b",
            "rclone cleanup removes old/malformed uploads."
        ),
        destructive_pattern!(
            "rclone-dedupe",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+dedupe\b",
            "rclone dedupe can delete or rename duplicate files."
        ),
        destructive_pattern!(
            "rclone-move",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+move\b",
            "rclone move deletes source files after copying."
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
        assert_eq!(pack.id, "backup.rclone");
        assert_eq!(pack.name, "Rclone");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"rclone"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rclone copy src: dest:");
        assert_safe_pattern_matches(&pack, "rclone ls remote:bucket");
        assert_safe_pattern_matches(&pack, "rclone lsd remote:bucket");
        assert_safe_pattern_matches(&pack, "rclone lsl remote:bucket");
        assert_safe_pattern_matches(&pack, "rclone size remote:bucket");
        assert_safe_pattern_matches(&pack, "rclone check src: dest:");
        assert_safe_pattern_matches(&pack, "rclone config");
        assert_safe_pattern_matches(&pack, "rclone sync src: dest: --dry-run");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "rclone sync src: dest:", "rclone-sync");
        assert_blocks_with_pattern(&pack, "rclone delete remote:bucket", "rclone-delete");
        assert_blocks_with_pattern(
            &pack,
            "rclone deletefile remote:bucket/file.txt",
            "rclone-deletefile",
        );
        assert_blocks_with_pattern(&pack, "rclone purge remote:bucket", "rclone-purge");
        assert_blocks_with_pattern(&pack, "rclone cleanup remote:", "rclone-cleanup");
        assert_blocks_with_pattern(&pack, "rclone dedupe remote:", "rclone-dedupe");
        assert_blocks_with_pattern(&pack, "rclone move src: dest:", "rclone-move");
    }
}

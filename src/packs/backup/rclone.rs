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
            "rclone sync deletes destination files not present in the source.",
            Critical,
            "rclone sync makes destination match source exactly:\n\n\
             - Files in destination not in source are DELETED\n\
             - This is a one-way sync (source -> destination)\n\
             - Use --dry-run to preview changes first\n\
             - Consider 'rclone copy' for non-destructive transfer\n\n\
             Preview: rclone sync source: dest: --dry-run"
        ),
        destructive_pattern!(
            "rclone-delete",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "rclone delete removes files and directories from the target.",
            Critical,
            "rclone delete removes files from remote:\n\n\
             - Deletes files matching the path/filter\n\
             - Does not delete directories (use purge for that)\n\
             - Use --dry-run to preview deletions\n\
             - Filters (--include/--exclude) affect what's deleted\n\n\
             Preview: rclone delete remote:path --dry-run"
        ),
        destructive_pattern!(
            "rclone-deletefile",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+deletefile\b",
            "rclone deletefile removes a single file from the target.",
            High,
            "rclone deletefile removes a single file:\n\n\
             - Deletes exactly one specified file\n\
             - More targeted than 'rclone delete'\n\
             - Cannot be undone without backup\n\n\
             Lower risk than bulk delete but still permanent"
        ),
        destructive_pattern!(
            "rclone-purge",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+purge\b",
            "rclone purge deletes a path and all its contents.",
            Critical,
            "rclone purge removes directory and ALL contents:\n\n\
             - Deletes the specified path completely\n\
             - Removes all files AND subdirectories\n\
             - More destructive than 'rclone delete'\n\
             - Cannot be undone without backup\n\n\
             List contents first: rclone ls remote:path"
        ),
        destructive_pattern!(
            "rclone-cleanup",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+cleanup\b",
            "rclone cleanup removes old/malformed uploads.",
            Medium,
            "rclone cleanup removes incomplete uploads:\n\n\
             - Removes old/incomplete multipart uploads\n\
             - Cleans up failed transfer artifacts\n\
             - May interrupt in-progress uploads\n\n\
             Generally safe but check for active uploads first"
        ),
        destructive_pattern!(
            "rclone-dedupe",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+dedupe\b",
            "rclone dedupe can delete or rename duplicate files.",
            High,
            "rclone dedupe handles duplicate files:\n\n\
             - Can delete duplicates (--dedupe-mode oldest/newest)\n\
             - Can rename duplicates to unique names\n\
             - Interactive mode lets you choose per-file\n\
             - Use --dry-run to preview actions\n\n\
             Preview: rclone dedupe remote:path --dry-run"
        ),
        destructive_pattern!(
            "rclone-move",
            r"rclone(?:\s+--?\S+(?:\s+\S+)?)*\s+move\b",
            "rclone move deletes source files after copying.",
            High,
            "rclone move transfers and deletes source:\n\n\
             - Copies files to destination\n\
             - Deletes source files after successful copy\n\
             - Use --dry-run to preview the operation\n\
             - Consider 'rclone copy' to preserve source\n\n\
             Preview: rclone move source: dest: --dry-run"
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

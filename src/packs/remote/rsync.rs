//! `rsync` pack - protections for destructive remote sync operations.
//!
//! Covers destructive CLI operations:
//! - delete flags (including --del and --delete-* variants)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `rsync` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "remote.rsync".to_string(),
        name: "rsync",
        description: "Protects against destructive rsync operations like --delete and its variants.",
        keywords: &["rsync"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("rsync-dry-run", r"rsync\b.*\s--dry-run\b"),
        safe_pattern!("rsync-short-dry-run", r"rsync\b.*\s+-[A-Za-z]*n[A-Za-z]*\b"),
        safe_pattern!("rsync-list-only", r"rsync\b.*\s--list-only\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "rsync-delete",
            r"rsync\b.*\s--delete(?:-[a-z-]+)?\b",
            "rsync --delete removes destination files not present in source."
        ),
        destructive_pattern!(
            "rsync-del-short",
            r"rsync\b.*\s--del\b",
            "rsync --del is a short alias for --delete and is destructive."
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
        assert_eq!(pack.id, "remote.rsync");
        assert_eq!(pack.name, "rsync");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"rsync"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "rsync --dry-run src/ dest/");
        assert_safe_pattern_matches(&pack, "rsync -avzn src/ dest/");
        assert_safe_pattern_matches(&pack, "rsync --list-only src/ dest/");
        assert_allows(&pack, "rsync -avz src/ dest/");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "rsync --delete src/ dest/", "rsync-delete");
        assert_blocks_with_pattern(&pack, "rsync --delete-before src/ dest/", "rsync-delete");
        assert_blocks_with_pattern(&pack, "rsync --delete-excluded src/ dest/", "rsync-delete");
        assert_blocks_with_pattern(&pack, "rsync --del src/ dest/", "rsync-del-short");
        assert_safe_pattern_matches(&pack, "rsync --delete --dry-run src/ dest/");
    }
}

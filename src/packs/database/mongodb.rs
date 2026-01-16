//! `MongoDB` patterns - protections against destructive mongo commands.
//!
//! This includes patterns for:
//! - dropDatabase/dropCollection commands
//! - db.collection.remove({}) without criteria
//! - mongosh destructive operations

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `MongoDB` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.mongodb".to_string(),
        name: "MongoDB",
        description: "Protects against destructive MongoDB operations like dropDatabase, \
                      dropCollection, and remove without criteria",
        keywords: &[
            "mongo",
            "mongosh",
            "dropDatabase",
            "dropCollection",
            "deleteMany",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // find operations are safe
        safe_pattern!("mongo-find", r"\.find\s*\("),
        // count operations are safe
        safe_pattern!("mongo-count", r"\.count(?:Documents)?\s*\("),
        // aggregate operations are safe (read-only)
        safe_pattern!("mongo-aggregate", r"\.aggregate\s*\("),
        // mongodump without --drop is safe (backup only)
        safe_pattern!("mongodump-no-drop", r"mongodump\s+(?!.*--drop)"),
        // explain is safe
        safe_pattern!("mongo-explain", r"\.explain\s*\("),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // dropDatabase
        destructive_pattern!(
            "drop-database",
            r"\.dropDatabase\s*\(",
            "dropDatabase permanently deletes the entire database."
        ),
        // dropCollection / drop()
        destructive_pattern!(
            "drop-collection",
            r"\.drop\s*\(\s*\)|\.dropCollection\s*\(",
            "drop/dropCollection permanently deletes the collection."
        ),
        // remove({}) / deleteMany({}) with empty filter
        destructive_pattern!(
            "delete-all",
            r"\.(?:remove|deleteMany)\s*\(\s*\{\s*\}\s*\)",
            "remove({}) or deleteMany({}) deletes ALL documents. Add filter criteria."
        ),
        // mongorestore --drop
        destructive_pattern!(
            "mongorestore-drop",
            r"mongorestore\s+.*--drop",
            "mongorestore --drop deletes existing data before restoring."
        ),
        // db.collection.drop()
        destructive_pattern!(
            "collection-drop",
            r"db\.[a-zA-Z_][a-zA-Z0-9_]*\.drop\s*\(",
            "collection.drop() permanently deletes the collection."
        ),
    ]
}

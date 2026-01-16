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
            "dropDatabase permanently deletes the entire database.",
            Critical,
            "dropDatabase() removes the current database completely:\n\n\
             - All collections are dropped\n\
             - All indexes are removed\n\
             - All documents are gone\n\
             - Users scoped to the database lose access\n\n\
             This cannot be undone. The database can be recreated but data is lost.\n\n\
             Backup first:\n  \
             mongodump --db=dbname --out=/path/to/backup\n\n\
             List databases:\n  \
             show dbs"
        ),
        // dropCollection / drop()
        destructive_pattern!(
            "drop-collection",
            r"\.drop\s*\(\s*\)|\.dropCollection\s*\(",
            "drop/dropCollection permanently deletes the collection.",
            High,
            "drop() removes the entire collection:\n\n\
             - All documents are deleted\n\
             - All indexes are removed\n\
             - Schema validation rules are lost\n\
             - Cannot be undone\n\n\
             Backup collection first:\n  \
             mongodump --db=dbname --collection=collname\n\n\
             Count documents before dropping:\n  \
             db.collection.countDocuments()"
        ),
        // remove({}) / deleteMany({}) with empty filter
        destructive_pattern!(
            "delete-all",
            r"\.(?:remove|deleteMany)\s*\(\s*\{\s*\}\s*\)",
            "remove({}) or deleteMany({}) deletes ALL documents. Add filter criteria.",
            High,
            "An empty filter {} matches ALL documents in the collection:\n\n\
             - deleteMany({}) removes every document\n\
             - remove({}) (deprecated) does the same\n\
             - Collection structure and indexes remain\n\n\
             If you want to delete everything, drop() is faster.\n\
             Otherwise, add filter criteria:\n  \
             db.collection.deleteMany({ status: 'expired' })\n\n\
             Preview what would be deleted:\n  \
             db.collection.countDocuments({})  // All documents!\n  \
             db.collection.find({}).limit(10)  // Sample docs"
        ),
        // mongorestore --drop
        destructive_pattern!(
            "mongorestore-drop",
            r"mongorestore\s+.*--drop",
            "mongorestore --drop deletes existing data before restoring.",
            High,
            "mongorestore --drop drops collections before restoring them:\n\n\
             - Existing data is deleted first\n\
             - If restore fails partway, data may be lost\n\
             - Only affects collections being restored\n\n\
             Safer approaches:\n\
             - Restore to a different database first\n\
             - Use --nsExclude to skip certain collections\n\
             - Remove --drop and handle conflicts manually\n\n\
             Test restore:\n  \
             mongorestore --db=test_restore --drop /backup/path"
        ),
        // db.collection.drop()
        destructive_pattern!(
            "collection-drop",
            r"db\.[a-zA-Z_][a-zA-Z0-9_]*\.drop\s*\(",
            "collection.drop() permanently deletes the collection.",
            High,
            "db.<collection>.drop() is the most common way to delete a collection:\n\n\
             - All documents in the collection are deleted\n\
             - Indexes on the collection are removed\n\
             - Cannot be undone\n\n\
             Before dropping:\n  \
             db.collection.stats()           // Size and document count\n  \
             db.collection.find().limit(5)   // Sample documents\n\n\
             Backup:\n  \
             mongodump --db=mydb --collection=mycollection"
        ),
    ]
}

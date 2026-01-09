//! Redis patterns - protections against destructive redis-cli commands.
//!
//! This includes patterns for:
//! - FLUSHALL/FLUSHDB commands
//! - DEL with wildcards
//! - CONFIG RESETSTAT
//! - DEBUG commands

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Redis pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "database.redis".to_string(),
        name: "Redis",
        description: "Protects against destructive Redis operations like FLUSHALL, \
                      FLUSHDB, and mass key deletion",
        keywords: &["redis", "FLUSHALL", "FLUSHDB", "DEBUG"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // GET/MGET operations are safe
        safe_pattern!("redis-get", r"(?i)\b(?:GET|MGET)\b"),
        // SCAN is safe (cursor-based iteration)
        safe_pattern!("redis-scan", r"(?i)\bSCAN\b"),
        // INFO is safe (server info)
        safe_pattern!("redis-info", r"(?i)\bINFO\b"),
        // KEYS (read-only, though potentially slow)
        safe_pattern!("redis-keys", r"(?i)\bKEYS\b"),
        // DBSIZE is safe
        safe_pattern!("redis-dbsize", r"(?i)\bDBSIZE\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // FLUSHALL - deletes all keys in all databases
        destructive_pattern!(
            "flushall",
            r"(?i)\bFLUSHALL\b",
            "FLUSHALL permanently deletes ALL keys in ALL databases."
        ),
        // FLUSHDB - deletes all keys in current database
        destructive_pattern!(
            "flushdb",
            r"(?i)\bFLUSHDB\b",
            "FLUSHDB permanently deletes ALL keys in the current database."
        ),
        // DEBUG SEGFAULT - crashes the server
        destructive_pattern!(
            "debug-crash",
            r"(?i)\bDEBUG\s+(?:SEGFAULT|CRASH)\b",
            "DEBUG SEGFAULT/CRASH will crash the Redis server."
        ),
        // DEBUG SLEEP can cause availability issues
        destructive_pattern!(
            "debug-sleep",
            r"(?i)\bDEBUG\s+SLEEP\b",
            "DEBUG SLEEP blocks the Redis server and can cause availability issues."
        ),
        // SHUTDOWN without NOSAVE
        destructive_pattern!(
            "shutdown",
            r"(?i)\bSHUTDOWN\b(?!\s+NOSAVE)",
            "SHUTDOWN stops the Redis server. Use carefully."
        ),
        // CONFIG SET with dangerous options
        destructive_pattern!(
            "config-dangerous",
            r"(?i)\bCONFIG\s+SET\s+(?:dir|dbfilename|slaveof|replicaof)\b",
            "CONFIG SET for dir/dbfilename/slaveof can be used for security attacks."
        ),
    ]
}

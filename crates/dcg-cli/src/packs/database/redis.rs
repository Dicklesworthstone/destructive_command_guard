//! Redis patterns - protections against destructive redis-cli commands.
//!
//! This includes patterns for:
//! - FLUSHALL/FLUSHDB commands
//! - KEYS/SCAN piped into DEL/UNLINK for mass key deletion
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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Each safe pattern carries a start-anchored negative lookahead that refuses
    // to match when ANY destructive Redis keyword is also present in the
    // command. Without this anchor, the lookahead only checks AFTER the current
    // match position, so a compound command like
    //   redis-cli FLUSHALL && redis-cli GET key
    // could still match the safe `GET` when evaluated starting at the `&&`.
    // The start anchor forces the lookahead to scan from position 0 of the
    // entire command.
    vec![
        // GET/MGET operations are safe
        safe_pattern!(
            "redis-get",
            r"(?i)^(?!.*\b(?:FLUSHALL|FLUSHDB|DEBUG|SHUTDOWN|CONFIG\s+(?:SET|REWRITE|RESETSTAT)|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK))\b).*\b(?:GET|MGET)\b"
        ),
        // SCAN is safe (cursor-based iteration)
        safe_pattern!(
            "redis-scan",
            r"(?i)^(?!.*\b(?:FLUSHALL|FLUSHDB|DEBUG|SHUTDOWN|CONFIG\s+(?:SET|REWRITE|RESETSTAT)|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK))\b).*\bSCAN\b"
        ),
        // INFO is safe (server info)
        safe_pattern!(
            "redis-info",
            r"(?i)^(?!.*\b(?:FLUSHALL|FLUSHDB|DEBUG|SHUTDOWN|CONFIG\s+(?:SET|REWRITE|RESETSTAT)|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK))\b).*\bINFO\b"
        ),
        // KEYS (read-only, though potentially slow)
        safe_pattern!(
            "redis-keys",
            r"(?i)^(?!.*\b(?:FLUSHALL|FLUSHDB|DEBUG|SHUTDOWN|CONFIG\s+(?:SET|REWRITE|RESETSTAT)|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK))\b).*\bKEYS\b"
        ),
        // DBSIZE is safe
        safe_pattern!(
            "redis-dbsize",
            r"(?i)^(?!.*\b(?:FLUSHALL|FLUSHDB|DEBUG|SHUTDOWN|CONFIG\s+(?:SET|REWRITE|RESETSTAT)|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK))\b).*\bDBSIZE\b"
        ),
        // CONFIG GET is read-only (only meaningful if no destructive CONFIG SET).
        // The negative lookahead already filters destructive CONFIG subcommands.
        safe_pattern!(
            "redis-config-get",
            r"(?i)^(?!.*\b(?:FLUSHALL|FLUSHDB|DEBUG|SHUTDOWN|CONFIG\s+(?:SET|REWRITE|RESETSTAT)|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK))\b).*\bCONFIG\s+GET\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // FLUSHALL - deletes all keys in all databases
        destructive_pattern!(
            "flushall",
            r"(?i)\bFLUSHALL\b",
            "FLUSHALL permanently deletes ALL keys in ALL databases.",
            Critical,
            "FLUSHALL removes every key from every database (0-15 by default):\n\n\
             - All cached data is lost\n\
             - All session data is gone\n\
             - All queues are emptied\n\
             - Affects ALL databases, not just current\n\n\
             This is instant and cannot be undone. RDB/AOF backups are not affected \
             until the next save.\n\n\
             Check database sizes first:\n  \
             INFO keyspace\n  \
             DBSIZE\n\n\
             Consider:\n  \
             FLUSHDB  # Only current database\n  \
             DEL key1 key2  # Specific keys"
        ),
        // FLUSHDB - deletes all keys in current database
        destructive_pattern!(
            "flushdb",
            r"(?i)\bFLUSHDB\b",
            "FLUSHDB permanently deletes ALL keys in the current database.",
            High,
            "FLUSHDB removes all keys from the currently selected database:\n\n\
             - All keys in this database are deleted\n\
             - Other databases (0-15) are unaffected\n\
             - Instant execution, no confirmation\n\
             - Cannot be undone\n\n\
             Check current database and key count:\n  \
             CLIENT INFO          # Shows current DB\n  \
             DBSIZE               # Keys in current DB\n  \
             KEYS '*' | head -20  # Sample keys (slow on large DBs)\n\n\
             Prefer audited per-key cleanup with a dry run and backup."
        ),
        // CONFIG RESETSTAT - erases operational counters used for diagnosis
        destructive_pattern!(
            "config-resetstat",
            r"(?i)\bCONFIG\s+RESETSTAT\b",
            "CONFIG RESETSTAT clears Redis runtime counters and can hide recent incidents.",
            Medium,
            "CONFIG RESETSTAT resets Redis statistics reported by INFO:\n\n\
             - Command counters and error counters are cleared\n\
             - Recent operational evidence can be lost\n\
             - Capacity and incident analysis becomes harder\n\n\
             Capture INFO and monitoring data first, then run this manually only when \
             resetting observability counters is intentional."
        ),
        destructive_pattern!(
            "mass-delete-pipeline",
            r"(?i)\bredis-cli\b.*\b(?:KEYS\b|--scan\b|SCAN\b).*\|\s*xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL|UNLINK)\b",
            "Redis KEYS/SCAN piped to DEL/UNLINK can delete many keys at once.",
            High,
            "Piping Redis key enumeration into DEL or UNLINK can delete every matching key:\n\n\
             - redis-cli KEYS '*' | xargs redis-cli DEL removes all returned keys\n\
             - redis-cli --scan --pattern 'prefix:*' | xargs redis-cli UNLINK removes a whole key namespace\n\
             - This bypasses Redis's lack of wildcard DEL by expanding keys client-side\n\n\
             Safer alternatives:\n  \
             redis-cli --scan --pattern 'prefix:*' | head -50  # inspect first\n  \
             Count and back up affected keys before selective deletion\n  \
             Prefer application-owned cleanup tooling with dry-run support"
        ),
        // DEBUG SEGFAULT - crashes the server
        destructive_pattern!(
            "debug-crash",
            r"(?i)\bDEBUG\s+(?:SEGFAULT|CRASH)\b",
            "DEBUG SEGFAULT/CRASH will crash the Redis server.",
            Critical,
            "DEBUG SEGFAULT/CRASH intentionally crashes the Redis server:\n\n\
             - Server process terminates immediately\n\
             - All connections are dropped\n\
             - Unsaved data may be lost\n\
             - Services depending on Redis fail\n\n\
             This is meant for testing crash recovery, not production use.\n\n\
             These commands should be disabled in production:\n  \
             CONFIG SET debug-command no\n  \
             rename-command DEBUG \"\"  # In redis.conf"
        ),
        // DEBUG SLEEP can cause availability issues
        destructive_pattern!(
            "debug-sleep",
            r"(?i)\bDEBUG\s+SLEEP\b",
            "DEBUG SLEEP blocks the Redis server and can cause availability issues.",
            High,
            "DEBUG SLEEP blocks the Redis server for the specified duration:\n\n\
             - All client connections freeze\n\
             - No commands are processed\n\
             - Cluster may mark node as failed\n\
             - Can trigger failover in Sentinel setups\n\n\
             This is meant for testing timeouts, not production use.\n\n\
             Disable in production:\n  \
             CONFIG SET debug-command no"
        ),
        // SHUTDOWN (with or without NOSAVE)
        destructive_pattern!(
            "shutdown",
            r"(?i)\bSHUTDOWN\b",
            "SHUTDOWN stops the Redis server. SHUTDOWN NOSAVE risks data loss.",
            High,
            "SHUTDOWN stops the Redis server:\n\n\
             - SHUTDOWN SAVE: Saves RDB before exit (default)\n\
             - SHUTDOWN NOSAVE: Exits immediately, no save\n\
             - All client connections are closed\n\
             - Services depending on Redis fail\n\n\
             Check for unsaved changes:\n  \
             INFO persistence  # Look at rdb_changes_since_last_save\n\n\
             Ensure proper restart mechanism exists (systemd, Docker, etc.)."
        ),
        // CONFIG SET with dangerous options
        destructive_pattern!(
            "config-dangerous",
            r"(?i)\bCONFIG\s+SET\s+(?:dir|dbfilename|slaveof|replicaof)\b",
            "CONFIG SET for dir/dbfilename/slaveof can be used for security attacks.",
            Critical,
            "These CONFIG SET options are commonly exploited in Redis attacks:\n\n\
             - dir + dbfilename: Can write arbitrary files (RCE vector)\n\
             - slaveof/replicaof: Can exfiltrate data to attacker's server\n\n\
             Attack example:\n\
             1. CONFIG SET dir /var/spool/cron\n\
             2. CONFIG SET dbfilename root\n\
             3. SET payload '* * * * * malicious-command'\n\
             4. BGSAVE\n\n\
             Disable in production:\n  \
             rename-command CONFIG \"\"  # In redis.conf\n\n\
             Use ACLs to restrict these commands."
        ),
        // CONFIG SET maxmemory can trigger mass key eviction
        destructive_pattern!(
            "config-set-maxmemory",
            r"(?i)\bCONFIG\s+SET\s+maxmemory\b(?:\s|$)",
            "CONFIG SET maxmemory can trigger immediate mass key eviction if new limit is below current usage.",
            Critical,
            "Lowering maxmemory below current usage causes Redis to evict keys immediately\n\
             according to the active eviction policy:\n\n\
             - volatile-lru/allkeys-lru: Silently deletes keys to fit budget\n\
             - noeviction: Returns OOM errors on writes\n\n\
             Check current usage first:\n  \
             INFO memory  # Look at used_memory vs maxmemory\n\n\
             Prefer gradual reduction or off-peak changes."
        ),
        // CONFIG SET maxmemory-policy changes eviction behavior
        destructive_pattern!(
            "config-set-maxmemory-policy",
            r"(?i)\bCONFIG\s+SET\s+maxmemory-policy\b",
            "CONFIG SET maxmemory-policy changes how Redis evicts keys, risking silent data loss.",
            Critical,
            "Switching eviction policy can silently delete keys:\n\n\
             - noeviction -> allkeys-lru: Enables silent key deletion\n\
             - volatile-* -> allkeys-*: Extends eviction to non-expiring keys\n\n\
             Check current policy:\n  \
             CONFIG GET maxmemory-policy\n\n\
             Ensure application logic handles the new eviction behavior."
        ),
        // CONFIG SET save can disable RDB persistence
        destructive_pattern!(
            "config-set-save",
            r"(?i)\bCONFIG\s+SET\s+save\b",
            "CONFIG SET save can disable RDB persistence entirely, risking data loss on restart.",
            High,
            "CONFIG SET save \"\" disables all RDB snapshots:\n\n\
             - No automatic persistence to disk\n\
             - All data lost on restart unless AOF is enabled\n\
             - Existing RDB file may become stale\n\n\
             Check current persistence:\n  \
             CONFIG GET save\n  \
             CONFIG GET appendonly\n\n\
             Ensure at least one persistence mechanism remains active."
        ),
        // CONFIG SET appendonly can disable AOF persistence
        destructive_pattern!(
            "config-set-appendonly",
            r"(?i)\bCONFIG\s+SET\s+appendonly\b",
            "CONFIG SET appendonly can disable AOF persistence, risking data loss on restart.",
            High,
            "Disabling AOF without RDB means zero persistence:\n\n\
             - CONFIG SET appendonly no: Stops AOF logging\n\
             - Combined with disabled RDB: complete data loss on crash/restart\n\n\
             Check other persistence mechanisms:\n  \
             CONFIG GET save\n  \
             CONFIG GET appendonly\n\n\
             Ensure at least one persistence mechanism remains active."
        ),
        // CONFIG REWRITE persists runtime changes to disk
        destructive_pattern!(
            "config-rewrite",
            r"(?i)\bCONFIG\s+REWRITE\b",
            "CONFIG REWRITE persists all runtime CONFIG SET changes to redis.conf permanently.",
            High,
            "CONFIG REWRITE writes current runtime config back to redis.conf:\n\n\
             - Makes all CONFIG SET changes survive restarts\n\
             - Can persist dangerous temporary changes permanently\n\
             - No undo: must manually edit redis.conf to revert\n\n\
             Review current runtime changes first:\n  \
             CONFIG GET *  # Compare with original redis.conf\n\n\
             Ensure no dangerous CONFIG SET changes are pending before rewriting."
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
        assert_eq!(pack.id, "database.redis");
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn safe_get_with_no_destructive_keyword_is_allowed() {
        let pack = create_pack();
        assert!(pack.matches_safe("redis-cli GET foo"));
        assert!(pack.matches_safe("redis-cli -n 2 SCAN 0"));
        assert!(pack.matches_safe("redis-cli INFO"));
        assert!(pack.matches_safe("redis-cli KEYS '*'"));
        assert!(pack.matches_safe("redis-cli DBSIZE"));
        assert!(pack.matches_safe("redis-cli CONFIG GET maxmemory"));
    }

    #[test]
    fn compound_command_safe_word_does_not_bypass_destructive() {
        let pack = create_pack();
        let m = pack
            .check("redis-cli FLUSHALL && redis-cli GET foo")
            .expect("FLUSHALL compound with GET must still block");
        assert_eq!(m.name, Some("flushall"));

        let m = pack
            .check("redis-cli 'FLUSHDB; GET foo'")
            .expect("FLUSHDB compound with GET must still block");
        assert_eq!(m.name, Some("flushdb"));

        let m = pack
            .check("redis-cli CONFIG SET dir /tmp; redis-cli SCAN 0")
            .expect("CONFIG SET dir compound with SCAN must still block");
        assert_eq!(m.name, Some("config-dangerous"));

        let m = pack
            .check("redis-cli CONFIG RESETSTAT; redis-cli INFO")
            .expect("CONFIG RESETSTAT compound with INFO must still block");
        assert_eq!(m.name, Some("config-resetstat"));

        let m = pack
            .check("redis-cli DEBUG SEGFAULT; redis-cli INFO")
            .expect("DEBUG SEGFAULT compound with INFO must still block");
        assert_eq!(m.name, Some("debug-crash"));
    }

    #[test]
    fn key_enumeration_piped_to_delete_is_blocked() {
        let pack = create_pack();

        let m = pack
            .check("redis-cli KEYS '*' | xargs redis-cli DEL")
            .expect("KEYS piped into DEL should block");
        assert_eq!(m.name, Some("mass-delete-pipeline"));

        let m = pack
            .check("redis-cli --scan --pattern 'prefix:*' | xargs -r redis-cli UNLINK")
            .expect("--scan piped into UNLINK should block");
        assert_eq!(m.name, Some("mass-delete-pipeline"));

        let m = pack
            .check("redis-cli --scan --pattern 'session:*' | xargs -n 100 redis-cli DEL")
            .expect("xargs with an option value should still block");
        assert_eq!(m.name, Some("mass-delete-pipeline"));

        assert_no_safe_match(&pack, "redis-cli KEYS '*' | xargs redis-cli DEL");
        assert_no_safe_match(
            &pack,
            "redis-cli --scan --pattern 'prefix:*' | xargs -r redis-cli UNLINK",
        );
    }

    #[test]
    fn redis_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "redis-cli FLUSHALL", "FLUSHALL");
        assert_blocks(&pack, "redis-cli FLUSHDB", "FLUSHDB");
        assert_blocks(&pack, "redis-cli DEBUG SEGFAULT", "DEBUG");
        assert_blocks(&pack, "redis-cli DEBUG SLEEP 30", "DEBUG SLEEP");
        assert_blocks(&pack, "redis-cli SHUTDOWN", "SHUTDOWN");
        assert_blocks(&pack, "redis-cli SHUTDOWN NOSAVE", "SHUTDOWN");
        assert_blocks(&pack, "redis-cli SHUTDOWN SAVE", "SHUTDOWN");
        assert_blocks(&pack, "redis-cli CONFIG RESETSTAT", "RESETSTAT");
        assert_blocks(&pack, "redis-cli CONFIG SET dir /tmp", "CONFIG SET");
        assert_blocks(&pack, "redis-cli CONFIG SET dbfilename x", "CONFIG SET");
        assert_blocks(&pack, "redis-cli CONFIG SET slaveof x", "CONFIG SET");
        assert_blocks(&pack, "redis-cli CONFIG SET maxmemory 100mb", "maxmemory");
        assert_blocks(
            &pack,
            "redis-cli CONFIG SET maxmemory-policy allkeys-lru",
            "maxmemory-policy",
        );
        assert_blocks(&pack, "redis-cli CONFIG SET save ''", "CONFIG SET save");
        assert_blocks(
            &pack,
            "redis-cli CONFIG SET appendonly no",
            "CONFIG SET appendonly",
        );
        assert_blocks(&pack, "redis-cli CONFIG REWRITE", "CONFIG REWRITE");
    }

    #[test]
    fn redis_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "redis-cli FLUSHALL", Severity::Critical);
        assert_blocks_with_severity(&pack, "redis-cli FLUSHDB", Severity::High);
        assert_blocks_with_severity(&pack, "redis-cli DEBUG SEGFAULT", Severity::Critical);
        assert_blocks_with_severity(&pack, "redis-cli DEBUG SLEEP 10", Severity::High);
        assert_blocks_with_severity(&pack, "redis-cli SHUTDOWN", Severity::High);
        assert_blocks_with_severity(&pack, "redis-cli CONFIG RESETSTAT", Severity::Medium);
        assert_blocks_with_severity(
            &pack,
            "redis-cli --scan --pattern 'session:*' | xargs redis-cli DEL",
            Severity::High,
        );
        assert_blocks_with_severity(&pack, "redis-cli CONFIG SET dir /tmp", Severity::Critical);
        assert_blocks_with_severity(&pack, "redis-cli CONFIG REWRITE", Severity::High);
    }

    #[test]
    fn redis_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo redis");
    }
}

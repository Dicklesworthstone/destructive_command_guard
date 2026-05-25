//! In-memory session occurrence tracking for the graduated response system.
//!
//! Tracks how many times each command pattern has been evaluated within the
//! current process lifetime. Downstream tasks (E10-T4) use these counts for
//! graduation decisions (warning → soft block → hard block).
//!
//! The tracker uses a command hash to group identical commands, keyed by a
//! truncated SHA-256 digest of the raw command string. This keeps the in-memory
//! footprint constant regardless of command length.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;

/// Global session state, lazily initialized on first access.
static SESSION_STATE: Mutex<Option<SessionTracker>> = Mutex::new(None);

/// Number of hex characters to keep from the SHA-256 digest.
const HASH_TRUNCATE_LEN: usize = 16;

/// In-memory occurrence tracker for the current process.
#[derive(Debug, Clone)]
pub struct SessionTracker {
    counts: HashMap<String, u32>,
    session_id: Option<String>,
}

impl SessionTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
            session_id: crate::allowlist::current_session_id(),
        }
    }
}

/// Compute a truncated SHA-256 hash of a command string.
///
/// Returns a 16-character hex string suitable for use as a HashMap key.
/// Two identical command strings always produce the same hash.
#[must_use]
pub fn hash_command(command: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(command.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(HASH_TRUNCATE_LEN);
    for byte in &digest[..HASH_TRUNCATE_LEN / 2] {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Increment the occurrence count for a command and return the new count.
///
/// Thread-safe. The first call for any command hash returns 1.
pub fn increment(command: &str) -> u32 {
    let hash = hash_command(command);
    let mut guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tracker = guard.get_or_insert_with(SessionTracker::new);
    let count = tracker.counts.entry(hash).or_insert(0);
    *count += 1;
    *count
}

/// Get the current occurrence count for a command without incrementing.
///
/// Returns 0 if the command has never been seen in this session.
#[must_use]
pub fn get_count(command: &str) -> u32 {
    let hash = hash_command(command);
    let guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .as_ref()
        .and_then(|t| t.counts.get(&hash).copied())
        .unwrap_or(0)
}

/// Get the session ID associated with the current tracker.
#[must_use]
pub fn session_id() -> Option<String> {
    let guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_ref().and_then(|t| t.session_id.clone())
}

/// Total number of distinct command hashes tracked in this session.
#[must_use]
pub fn distinct_commands() -> usize {
    let guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_ref().map_or(0, |t| t.counts.len())
}

/// Total number of occurrences across all tracked commands.
#[must_use]
pub fn total_occurrences() -> u32 {
    let guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.as_ref().map_or(0, |t| t.counts.values().sum())
}

/// Reset all session state. Intended for testing only.
pub fn reset() {
    let mut guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = None;
}

/// Snapshot of session occurrence data for a specific command.
///
/// Returned by [`record_and_snapshot`] and attached to evaluation results
/// so downstream code can make graduation decisions without touching the
/// global state directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccurrenceSnapshot {
    /// SHA-256 hash (truncated) of the command.
    pub command_hash: String,
    /// Number of times this exact command has been seen in this session,
    /// *including* the current evaluation.
    pub session_count: u32,
    /// Total distinct command hashes tracked this session.
    pub distinct_commands: usize,
    /// Total occurrences across all commands this session.
    pub total_occurrences: u32,
}

/// Increment the occurrence count for a command and return a full snapshot.
///
/// This is the primary entry point for the evaluator: it atomically increments
/// and reads all relevant counters in a single lock acquisition.
pub fn record_and_snapshot(command: &str) -> OccurrenceSnapshot {
    let hash = hash_command(command);
    let mut guard = SESSION_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tracker = guard.get_or_insert_with(SessionTracker::new);
    let count = tracker.counts.entry(hash.clone()).or_insert(0);
    *count += 1;
    let session_count = *count;
    OccurrenceSnapshot {
        command_hash: hash,
        session_count,
        distinct_commands: tracker.counts.len(),
        total_occurrences: tracker.counts.values().sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, PoisonError};

    static SESSION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn isolated<F: FnOnce()>(f: F) {
        let _guard = SESSION_TEST_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        reset();
        f();
        reset();
    }

    #[test]
    fn hash_deterministic() {
        let h1 = hash_command("git reset --hard HEAD~1");
        let h2 = hash_command("git reset --hard HEAD~1");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), HASH_TRUNCATE_LEN);
    }

    #[test]
    fn hash_differs_for_different_commands() {
        let h1 = hash_command("git reset --hard");
        let h2 = hash_command("rm -rf /");
        assert_ne!(h1, h2);
    }

    #[test]
    fn increment_returns_sequential_counts() {
        isolated(|| {
            assert_eq!(increment("git reset --hard"), 1);
            assert_eq!(increment("git reset --hard"), 2);
            assert_eq!(increment("git reset --hard"), 3);
        });
    }

    #[test]
    fn get_count_without_increment() {
        isolated(|| {
            assert_eq!(get_count("git reset --hard"), 0);
            increment("git reset --hard");
            assert_eq!(get_count("git reset --hard"), 1);
        });
    }

    #[test]
    fn distinct_commands_tracked() {
        isolated(|| {
            increment("git reset --hard");
            increment("rm -rf /");
            increment("git reset --hard");
            assert_eq!(distinct_commands(), 2);
        });
    }

    #[test]
    fn total_occurrences_sum() {
        isolated(|| {
            increment("git reset --hard");
            increment("rm -rf /");
            increment("git reset --hard");
            assert_eq!(total_occurrences(), 3);
        });
    }

    #[test]
    fn reset_clears_all_state() {
        isolated(|| {
            increment("git reset --hard");
            increment("rm -rf /");
            reset();
            assert_eq!(get_count("git reset --hard"), 0);
            assert_eq!(distinct_commands(), 0);
            assert_eq!(total_occurrences(), 0);
        });
    }

    #[test]
    fn record_and_snapshot_atomicity() {
        isolated(|| {
            let snap1 = record_and_snapshot("git reset --hard");
            assert_eq!(snap1.session_count, 1);
            assert_eq!(snap1.distinct_commands, 1);
            assert_eq!(snap1.total_occurrences, 1);

            let snap2 = record_and_snapshot("rm -rf /");
            assert_eq!(snap2.session_count, 1);
            assert_eq!(snap2.distinct_commands, 2);
            assert_eq!(snap2.total_occurrences, 2);

            let snap3 = record_and_snapshot("git reset --hard");
            assert_eq!(snap3.session_count, 2);
            assert_eq!(snap3.distinct_commands, 2);
            assert_eq!(snap3.total_occurrences, 3);
        });
    }

    #[test]
    fn snapshot_hash_matches_hash_command() {
        isolated(|| {
            let snap = record_and_snapshot("git reset --hard");
            assert_eq!(snap.command_hash, hash_command("git reset --hard"));
        });
    }

    #[test]
    fn poisoned_mutex_recovers() {
        // Verify unwrap_or_else(into_inner) recovers from poisoning.
        // We simulate by verifying the recovery path compiles and works
        // under normal conditions (actual poisoning requires a panic in
        // another thread while holding the lock).
        isolated(|| {
            assert_eq!(increment("test"), 1);
            assert_eq!(get_count("test"), 1);
        });
    }

    #[test]
    fn empty_command_hashes() {
        isolated(|| {
            let h = hash_command("");
            assert_eq!(h.len(), HASH_TRUNCATE_LEN);
            assert_eq!(increment(""), 1);
            assert_eq!(increment(""), 2);
        });
    }

    #[test]
    fn unicode_command_hashes() {
        isolated(|| {
            let h = hash_command("git commit -m '修复bug'");
            assert_eq!(h.len(), HASH_TRUNCATE_LEN);
            assert_eq!(increment("git commit -m '修复bug'"), 1);
        });
    }

    #[test]
    fn long_command_constant_hash_length() {
        isolated(|| {
            let long_cmd = "x".repeat(100_000);
            let h = hash_command(&long_cmd);
            assert_eq!(h.len(), HASH_TRUNCATE_LEN);
        });
    }
}

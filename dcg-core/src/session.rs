//! In-memory per-agent-run session state.
//!
//! `Session` replaces the global `SESSION_STATE` `Mutex` from dcg v0.5. Each
//! agent run (or test) constructs its own `Session`. The session owns:
//!
//! - The working directory used to resolve relative paths and protected paths.
//! - An allow-once cache so that user-approved exceptions consume their code
//!   exactly once and expire after 24 hours.
//! - A per-command deny counter for graduated response (warning →
//!   soft-block → hard-block).
//!
//! # Allow-once codes
//!
//! When [`crate::Engine::evaluate`] returns
//! [`crate::Decision::Prompt`] it embeds an `allow_once_code` derived from
//! the session id and the exact command. The consumer then asks the user;
//! on approval, the consumer calls [`Session::consume_allow_once`] which
//! returns `true` exactly once for that code.
//!
//! Codes are 6 hex characters (3 bytes from a SHA-256 truncation). This is
//! the same UX as dcg v0.5 short codes — short enough for users to type from
//! a terminal, long enough to avoid collisions in practice.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use crate::decision::Decision;

/// 24-hour TTL for allow-once entries.
pub const ALLOW_ONCE_TTL: Duration = Duration::hours(24);

/// Length of the short allow-once code in hex characters.
pub const ALLOW_ONCE_CODE_LEN: usize = 6;

/// One outstanding allow-once exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowOnceEntry {
    /// The exact command (or other tool payload digest) the code was issued for.
    pub command_hash: String,
    /// When the code was issued.
    pub issued_at: DateTime<Utc>,
    /// `true` once `consume_allow_once` has been called successfully.
    pub consumed: bool,
}

impl AllowOnceEntry {
    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now - self.issued_at >= ALLOW_ONCE_TTL
    }
}

/// In-memory state for a single agent run.
#[derive(Debug, Clone)]
pub struct Session {
    /// Stable session identifier. Used for deriving allow-once codes so the
    /// same command in different sessions yields different codes.
    pub id: String,
    /// Resolved working directory; used for `protected_paths` matching.
    pub working_dir: PathBuf,
    /// Allow-once code → entry.
    allow_once_cache: HashMap<String, AllowOnceEntry>,
    /// Command hash → number of times this exact command was denied.
    deny_counter: HashMap<String, u32>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// Creates a new session with a generated random id and the current
    /// working directory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: random_session_id(),
            working_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            allow_once_cache: HashMap::new(),
            deny_counter: HashMap::new(),
        }
    }

    /// Creates a session with a specific working directory. Useful in tests
    /// and for consumers that want to scope the session to a project root.
    #[must_use]
    pub fn with_working_dir(working_dir: PathBuf) -> Self {
        Self {
            id: random_session_id(),
            working_dir,
            allow_once_cache: HashMap::new(),
            deny_counter: HashMap::new(),
        }
    }

    /// Creates a session with a fixed id. Useful for deterministic tests.
    #[must_use]
    pub fn with_id<S: Into<String>>(id: S) -> Self {
        Self {
            id: id.into(),
            working_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            allow_once_cache: HashMap::new(),
            deny_counter: HashMap::new(),
        }
    }

    /// Generates an allow-once code for `command` and registers it in the
    /// session cache. The same command in the same session yields the same
    /// code (idempotent), so a second `Prompt` for the same command does not
    /// invalidate the previously-issued code.
    pub fn generate_allow_once_code(&mut self, command: &str) -> String {
        self.generate_allow_once_code_at(command, Utc::now())
    }

    /// Like [`Self::generate_allow_once_code`] but with an explicit clock for
    /// testing.
    pub fn generate_allow_once_code_at(&mut self, command: &str, now: DateTime<Utc>) -> String {
        let cmd_hash = hash_command(command);
        let code = derive_short_code(&self.id, &cmd_hash);

        // If an entry already exists for this code and is still valid +
        // unconsumed, keep it (idempotent generation). Otherwise re-issue.
        let entry = self.allow_once_cache.get(&code);
        let needs_new = match entry {
            None => true,
            Some(e) => e.consumed || e.is_expired(now),
        };
        if needs_new {
            self.allow_once_cache.insert(
                code.clone(),
                AllowOnceEntry {
                    command_hash: cmd_hash,
                    issued_at: now,
                    consumed: false,
                },
            );
        }
        code
    }

    /// Attempts to consume an allow-once code. Returns `true` if the code
    /// was valid (issued in this session, not yet consumed, not expired);
    /// the entry is then marked consumed so subsequent calls return `false`.
    pub fn consume_allow_once(&mut self, code: &str) -> bool {
        self.consume_allow_once_at(code, Utc::now())
    }

    /// Like [`Self::consume_allow_once`] but with an explicit clock.
    pub fn consume_allow_once_at(&mut self, code: &str, now: DateTime<Utc>) -> bool {
        let Some(entry) = self.allow_once_cache.get_mut(code) else {
            return false;
        };
        if entry.consumed || entry.is_expired(now) {
            return false;
        }
        entry.consumed = true;
        true
    }

    /// Returns whether an allow-once code is currently valid (issued in this
    /// session, not consumed, not expired). Does **not** mutate the entry.
    #[must_use]
    pub fn has_unused_allow_once(&self, code: &str) -> bool {
        self.has_unused_allow_once_at(code, Utc::now())
    }

    /// Like [`Self::has_unused_allow_once`] but with an explicit clock.
    #[must_use]
    pub fn has_unused_allow_once_at(&self, code: &str, now: DateTime<Utc>) -> bool {
        self.allow_once_cache
            .get(code)
            .is_some_and(|e| !e.consumed && !e.is_expired(now))
    }

    /// Increments the deny counter for `command` and returns the new count.
    pub fn bump_deny_counter(&mut self, command: &str) -> u32 {
        let key = hash_command(command);
        let entry = self.deny_counter.entry(key).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Returns the deny counter for `command` without modifying it.
    #[must_use]
    pub fn deny_count(&self, command: &str) -> u32 {
        let key = hash_command(command);
        self.deny_counter.get(&key).copied().unwrap_or(0)
    }

    /// Removes expired allow-once entries. Returns the number of entries
    /// purged. Optional cleanup helper; call sites that don't need it can
    /// rely on `consume_allow_once` to reject expired codes lazily.
    pub fn purge_expired(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.allow_once_cache.len();
        self.allow_once_cache.retain(|_, e| !e.is_expired(now));
        before - self.allow_once_cache.len()
    }

    /// Helper: convert a [`Decision::Prompt`] into a `Decision::Allow` if the
    /// supplied user-approved code is valid. Used by consumers in their
    /// approval flow to keep the verification logic in one place.
    pub fn approve_with_code(&mut self, code: &str, decision: Decision) -> Decision {
        match decision {
            Decision::Prompt {
                ref allow_once_code,
                ..
            } if allow_once_code == code && self.consume_allow_once(code) => Decision::Allow,
            other => other,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SHA-256 the command and return a stable 16-hex-char prefix.
fn hash_command(cmd: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cmd.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Derive a short user-facing code from `(session_id, command_hash)`.
fn derive_short_code(session_id: &str, command_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(command_hash.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(ALLOW_ONCE_CODE_LEN);
    for byte in &digest[..ALLOW_ONCE_CODE_LEN / 2] {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Generate a random session id by hashing the current time + a process-local
/// counter. Avoids pulling in `rand` as a dep — the id is not security-critical
/// (it scopes allow-once codes), only needs to be unique-ish per process run.
fn random_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(now.to_le_bytes());
    hasher.update(n.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_command_is_stable_and_truncated() {
        let h1 = hash_command("git status");
        let h2 = hash_command("git status");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn allow_once_code_round_trip() {
        let mut s = Session::with_id("test-session");
        let code = s.generate_allow_once_code("git reset --hard");
        assert_eq!(code.len(), ALLOW_ONCE_CODE_LEN);
        assert!(s.has_unused_allow_once(&code));

        // First consume succeeds.
        assert!(s.consume_allow_once(&code));
        // Second consume fails (single-use).
        assert!(!s.consume_allow_once(&code));
        assert!(!s.has_unused_allow_once(&code));
    }

    #[test]
    fn allow_once_codes_are_session_scoped() {
        let mut a = Session::with_id("session-a");
        let mut b = Session::with_id("session-b");
        let cmd = "rm -rf ./target";
        let code_a = a.generate_allow_once_code(cmd);
        let code_b = b.generate_allow_once_code(cmd);
        assert_ne!(
            code_a, code_b,
            "different sessions must produce different codes"
        );
    }

    #[test]
    fn allow_once_generation_is_idempotent_within_session() {
        let mut s = Session::with_id("session-a");
        let cmd = "git push --force";
        let c1 = s.generate_allow_once_code(cmd);
        let c2 = s.generate_allow_once_code(cmd);
        assert_eq!(c1, c2, "same session+command must produce same code");
        assert!(s.has_unused_allow_once(&c1));
    }

    #[test]
    fn allow_once_expires_after_ttl() {
        let mut s = Session::with_id("session-a");
        let t0 = Utc::now();
        let code = s.generate_allow_once_code_at("rm -rf /", t0);
        let later = t0 + ALLOW_ONCE_TTL + Duration::seconds(1);
        assert!(!s.consume_allow_once_at(&code, later));
        assert!(!s.has_unused_allow_once_at(&code, later));
    }

    #[test]
    fn purge_expired_removes_old_codes() {
        let mut s = Session::with_id("session-a");
        let t0 = Utc::now();
        let _ = s.generate_allow_once_code_at("a", t0);
        let _ = s.generate_allow_once_code_at("b", t0);
        let later = t0 + ALLOW_ONCE_TTL + Duration::seconds(1);
        let purged = s.purge_expired(later);
        assert_eq!(purged, 2);
    }

    #[test]
    fn deny_counter_increments_per_command() {
        let mut s = Session::new();
        assert_eq!(s.deny_count("rm -rf /"), 0);
        assert_eq!(s.bump_deny_counter("rm -rf /"), 1);
        assert_eq!(s.bump_deny_counter("rm -rf /"), 2);
        assert_eq!(s.deny_count("rm -rf /"), 2);
        assert_eq!(s.deny_count("ls"), 0);
    }

    #[test]
    fn approve_with_code_converts_prompt_to_allow() {
        let mut s = Session::with_id("session-a");
        let cmd = "git push --force";
        let code = s.generate_allow_once_code(cmd);
        let prompt = Decision::prompt("force push warning", &code);
        let decided = s.approve_with_code(&code, prompt);
        assert!(decided.is_allow());
        // Code is consumed, second attempt does not allow.
        let prompt2 = Decision::prompt("force push warning", &code);
        let decided2 = s.approve_with_code(&code, prompt2);
        assert!(decided2.is_prompt(), "consumed code must not allow again");
    }

    #[test]
    fn approve_with_wrong_code_keeps_decision() {
        let mut s = Session::with_id("session-a");
        let prompt = Decision::prompt("danger", "abc123");
        let decided = s.approve_with_code("nope42", prompt.clone());
        assert_eq!(decided, prompt);
    }

    #[test]
    fn random_session_ids_are_distinct() {
        let a = Session::new();
        let b = Session::new();
        assert_ne!(a.id, b.id);
    }
}

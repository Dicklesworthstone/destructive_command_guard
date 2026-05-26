//! Rebase recovery mode — narrowly relax `git checkout --` / `git restore` blocks
//! when the user is actively recovering from a failed `git pull --rebase` flow.
//!
//! ## Problem
//!
//! When `git pull --rebase` fails partway (unstaged changes, stash-pop
//! conflict, interrupted rebase), the standard recovery path is often
//! `git checkout -- .` or `git restore <paths>`. Both are normally blocked
//! by dcg (rules `core.git:checkout-discard` and `core.git:restore-worktree`),
//! which leaves AI agents stuck and forced to ask the user to run the
//! command by hand. See issue #104.
//!
//! ## Solution
//!
//! Two complementary signals unlock the recovery path, both narrow and
//! bounded so the default safety guarantee is preserved outside of a
//! genuine recovery window:
//!
//! 1. **Active rebase state (automatic, zero-config).** If `.git/rebase-merge/`
//!    or `.git/rebase-apply/` exists, a rebase is in progress. In this state
//!    the discard operations are the documented recovery path, not a
//!    dangerous mistake — so dcg allows them with an informational note
//!    to stderr instead of a hard block.
//!
//! 2. **Explicit permit cookie (opt-in, short-lived).** The agent (or user)
//!    runs `dcg rebase-recover`, which writes a timestamp file into
//!    `.dcg/rebase-recovery-permit`. For the next 120 seconds (or until the
//!    next matching operation is allowed through — whichever comes first),
//!    `git checkout --` and `git restore` are allowed. This covers the
//!    common post-rebase case where the rebase itself already succeeded
//!    but a `git stash pop` left the worktree messy.
//!
//! ## Safety
//!
//! - The permit is scoped to the current repository's `.dcg/` directory.
//! - The permit is single-use (consumed on first successful allow).
//! - The permit expires after a short TTL (default 120s).
//! - Outside of both signals, the block path is unchanged. The safety
//!   guarantee for `core.git:checkout-discard` / `core.git:restore-worktree`
//!   still holds for every command that is not part of a rebase recovery.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default permit TTL in seconds.
pub const DEFAULT_PERMIT_TTL_SECS: u64 = 120;

/// Hard upper bound on permit TTL (prevents accidentally-long permits).
pub const MAX_PERMIT_TTL_SECS: u64 = 600;

/// Pattern names (within `core.git`) that participate in rebase recovery.
///
/// Any of these pattern IDs may be unblocked when a recovery signal is
/// active. Everything else stays on the normal block path.
pub const RECOVERY_PATTERNS: &[&str] = &[
    "checkout-discard",
    "checkout-ref-discard",
    "restore-worktree",
    "restore-worktree-explicit",
];

/// Reason code describing why a recovery allow was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryReason {
    /// An interactive rebase (`rebase-merge/`) or non-interactive rebase
    /// (`rebase-apply/`) was in progress at the time of the check.
    RebaseInProgress,
    /// A time-bounded permit issued by `dcg rebase-recover` was valid.
    /// The inner `u64` is the number of seconds remaining.
    ActivePermit(u64),
}

impl RecoveryReason {
    /// Short human-readable label for stderr logging.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::RebaseInProgress => "rebase in progress".to_string(),
            Self::ActivePermit(secs) => format!("active rebase-recovery permit ({secs}s left)"),
        }
    }
}

/// Check whether a recovery unblock should fire for this pack/pattern in this cwd.
///
/// Returns `Some(RecoveryReason)` if the given `pack_id`/`pattern_name` is
/// one of the recovery-eligible rules AND a recovery signal is active in
/// `cwd`. Otherwise returns `None` and the caller should keep blocking.
#[must_use]
pub fn should_allow_recovery(
    cwd: &Path,
    pack_id: Option<&str>,
    pattern_name: Option<&str>,
) -> Option<RecoveryReason> {
    // Only `core.git` patterns participate.
    if pack_id != Some("core.git") {
        return None;
    }
    let name = pattern_name?;
    if !RECOVERY_PATTERNS.contains(&name) {
        return None;
    }

    // 1. In-progress rebase — automatic unblock.
    if is_rebase_in_progress(cwd) {
        return Some(RecoveryReason::RebaseInProgress);
    }

    // 2. Explicit permit cookie — short-lived unblock.
    if let Some(remaining) = permit_seconds_remaining(cwd) {
        return Some(RecoveryReason::ActivePermit(remaining));
    }

    None
}

/// Detect whether a rebase is in progress in the given working directory.
///
/// Uses the standard git-porcelain convention: the presence of
/// `.git/rebase-merge/` (interactive/merge rebase) or `.git/rebase-apply/`
/// (non-interactive rebase) indicates an active rebase. Also handles
/// worktrees where `.git` is a file pointing to the real git dir.
#[must_use]
pub fn is_rebase_in_progress(cwd: &Path) -> bool {
    let Some(git_dir) = resolve_git_dir(cwd) else {
        return false;
    };
    git_dir.join("rebase-merge").is_dir() || git_dir.join("rebase-apply").is_dir()
}

/// Walk up from `cwd` looking for the nearest `.git`.
///
/// If `.git` is a directory, return it. If `.git` is a file (worktree /
/// submodule), parse its `gitdir:` directive. If nothing is found, return
/// `None` (we'll treat that as "not in a git repo").
fn resolve_git_dir(cwd: &Path) -> Option<PathBuf> {
    let mut current = cwd.to_path_buf();
    loop {
        let dot_git = current.join(".git");
        if dot_git.is_dir() {
            return Some(dot_git);
        }
        if dot_git.is_file() {
            if let Ok(contents) = fs::read_to_string(&dot_git) {
                for line in contents.lines() {
                    if let Some(rest) = line.strip_prefix("gitdir:") {
                        let path = PathBuf::from(rest.trim());
                        if path.is_absolute() {
                            return Some(path);
                        }
                        return Some(current.join(path));
                    }
                }
            }
            return None;
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Compute the path where the permit cookie lives for a given working
/// directory. Located inside `.dcg/` so it lives alongside other dcg state
/// and doesn't pollute the project root.
fn permit_path(cwd: &Path) -> PathBuf {
    // Anchor the permit to the repo root when possible so nested `cd`s
    // still see the same cookie during the recovery window. Fall back to
    // the raw `cwd` if we can't resolve a git dir (not in a repo).
    let anchor = resolve_git_dir(cwd)
        .and_then(|g| g.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(|| cwd.to_path_buf());
    anchor.join(".dcg").join("rebase-recovery-permit")
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a permit cookie valid for `ttl_secs` seconds.
///
/// The cookie stores the absolute expiration time (unix epoch seconds)
/// so clock skew within a single machine doesn't trip us up and we don't
/// need to parse relative times at check-time.
///
/// # Errors
///
/// Returns an IO error if the `.dcg/` directory cannot be created or the
/// permit file cannot be written.
pub fn set_permit(cwd: &Path, ttl_secs: u64) -> std::io::Result<PathBuf> {
    let ttl = ttl_secs.clamp(1, MAX_PERMIT_TTL_SECS);
    let path = permit_path(cwd);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let expires_at = now_epoch_secs().saturating_add(ttl);
    fs::write(&path, format!("{expires_at}\n"))?;
    Ok(path)
}

/// If a permit cookie exists and is still valid, return the number of
/// seconds remaining. Otherwise return `None` (no permit, expired permit,
/// malformed permit).
#[must_use]
pub fn permit_seconds_remaining(cwd: &Path) -> Option<u64> {
    let path = permit_path(cwd);
    let contents = fs::read_to_string(&path).ok()?;
    let first_line = contents.lines().next()?.trim();
    let expires_at: u64 = first_line.parse().ok()?;
    let now = now_epoch_secs();
    if expires_at > now {
        Some(expires_at - now)
    } else {
        // Expired — best-effort cleanup so the next call doesn't see it.
        let _ = fs::remove_file(&path);
        None
    }
}

/// Consume the permit (single-shot): delete the cookie file. Called after
/// a successful recovery-allow so the permit doesn't silently unblock
/// later unrelated commands within the TTL window.
pub fn consume_permit(cwd: &Path) {
    let path = permit_path(cwd);
    let _ = fs::remove_file(path);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a tempdir rooted at `target/` (which is always writable in
    /// our CI) and initialize it as a minimal fake git repo. Returns the
    /// repo root; the test is responsible for cleanup via `Drop`.
    struct FakeRepo {
        root: PathBuf,
    }

    impl FakeRepo {
        fn new(label: &str) -> Self {
            let base = std::env::temp_dir().join(format!(
                "dcg-rebase-recovery-{}-{}-{}",
                label,
                std::process::id(),
                now_epoch_secs()
            ));
            fs::create_dir_all(base.join(".git")).unwrap();
            Self { root: base }
        }

        fn start_rebase_merge(&self) {
            fs::create_dir_all(self.root.join(".git").join("rebase-merge")).unwrap();
        }

        fn start_rebase_apply(&self) {
            fs::create_dir_all(self.root.join(".git").join("rebase-apply")).unwrap();
        }
    }

    impl Drop for FakeRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn is_rebase_in_progress_false_for_clean_repo() {
        let repo = FakeRepo::new("clean");
        assert!(!is_rebase_in_progress(&repo.root));
    }

    #[test]
    fn is_rebase_in_progress_true_for_rebase_merge() {
        let repo = FakeRepo::new("merge");
        repo.start_rebase_merge();
        assert!(is_rebase_in_progress(&repo.root));
    }

    #[test]
    fn is_rebase_in_progress_true_for_rebase_apply() {
        let repo = FakeRepo::new("apply");
        repo.start_rebase_apply();
        assert!(is_rebase_in_progress(&repo.root));
    }

    #[test]
    fn is_rebase_in_progress_false_outside_repo() {
        let dir = std::env::temp_dir().join(format!(
            "dcg-no-repo-{}-{}",
            std::process::id(),
            now_epoch_secs()
        ));
        fs::create_dir_all(&dir).unwrap();
        assert!(!is_rebase_in_progress(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn should_allow_recovery_blocks_outside_rebase() {
        let repo = FakeRepo::new("block-outside");
        assert!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("checkout-discard")).is_none(),
            "recovery must NOT fire outside an active rebase or permit"
        );
        assert!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree")).is_none()
        );
    }

    #[test]
    fn should_allow_recovery_fires_during_rebase() {
        let repo = FakeRepo::new("allow-rebase");
        repo.start_rebase_merge();
        assert_eq!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("checkout-discard")),
            Some(RecoveryReason::RebaseInProgress)
        );
        assert_eq!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree")),
            Some(RecoveryReason::RebaseInProgress)
        );
    }

    #[test]
    fn should_allow_recovery_ignores_non_recovery_patterns() {
        let repo = FakeRepo::new("non-recovery");
        repo.start_rebase_merge();
        // Even during a rebase, unrelated destructive patterns must not
        // be auto-unblocked (e.g., `git reset --hard` stays blocked).
        assert!(should_allow_recovery(&repo.root, Some("core.git"), Some("reset-hard")).is_none());
        assert!(should_allow_recovery(&repo.root, Some("core.git"), Some("clean-force")).is_none());
        // Different pack — always stays blocked.
        assert!(
            should_allow_recovery(&repo.root, Some("core.filesystem"), Some("rm-rf-general"))
                .is_none()
        );
    }

    #[test]
    fn permit_valid_within_ttl() {
        let repo = FakeRepo::new("permit-valid");
        set_permit(&repo.root, 60).unwrap();
        let remaining = permit_seconds_remaining(&repo.root);
        assert!(remaining.is_some(), "permit should be active");
        let secs = remaining.unwrap();
        assert!(secs > 0 && secs <= 60, "remaining={secs}, expected <= 60");
    }

    #[test]
    fn permit_allows_recovery_when_not_in_rebase() {
        let repo = FakeRepo::new("permit-allows");
        // No rebase in progress.
        assert!(!is_rebase_in_progress(&repo.root));
        // Without a permit, blocked.
        assert!(
            should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree")).is_none()
        );
        // With a permit, allowed.
        set_permit(&repo.root, 60).unwrap();
        let reason = should_allow_recovery(&repo.root, Some("core.git"), Some("restore-worktree"));
        assert!(matches!(reason, Some(RecoveryReason::ActivePermit(_))));
    }

    #[test]
    fn permit_expires_correctly() {
        let repo = FakeRepo::new("permit-expires");
        // Manually write an already-expired cookie.
        let path = permit_path(&repo.root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let expired_at = now_epoch_secs().saturating_sub(10);
        fs::write(&path, format!("{expired_at}\n")).unwrap();
        assert!(
            permit_seconds_remaining(&repo.root).is_none(),
            "expired permit must not be honored"
        );
        // Expired permit is cleaned up on read.
        assert!(!path.exists(), "expired permit should be auto-removed");
    }

    #[test]
    fn permit_can_be_consumed() {
        let repo = FakeRepo::new("permit-consume");
        set_permit(&repo.root, 60).unwrap();
        assert!(permit_seconds_remaining(&repo.root).is_some());
        consume_permit(&repo.root);
        assert!(
            permit_seconds_remaining(&repo.root).is_none(),
            "consumed permit must not remain valid"
        );
    }

    #[test]
    fn permit_ttl_is_clamped() {
        let repo = FakeRepo::new("permit-clamp");
        // Request a huge TTL; implementation must clamp to MAX.
        set_permit(&repo.root, 60_000).unwrap();
        let remaining = permit_seconds_remaining(&repo.root).unwrap();
        assert!(
            remaining <= MAX_PERMIT_TTL_SECS,
            "remaining={remaining} > MAX={MAX_PERMIT_TTL_SECS}"
        );
    }

    #[test]
    fn malformed_permit_is_ignored() {
        let repo = FakeRepo::new("permit-malformed");
        let path = permit_path(&repo.root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "not-a-number\n").unwrap();
        assert!(permit_seconds_remaining(&repo.root).is_none());
    }

    #[test]
    fn recovery_reason_labels_are_informative() {
        assert_eq!(
            RecoveryReason::RebaseInProgress.label(),
            "rebase in progress"
        );
        let label = RecoveryReason::ActivePermit(45).label();
        assert!(label.contains("45"), "label must include seconds: {label}");
        assert!(
            label.contains("permit"),
            "label must mention permit: {label}"
        );
    }
}

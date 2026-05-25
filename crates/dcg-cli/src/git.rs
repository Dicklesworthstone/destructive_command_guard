//! Git branch detection for branch-aware strictness.
//!
//! This module provides reliable detection of the current git branch with fallback
//! mechanisms and per-directory caching for performance.
//!
//! # Design
//!
//! - **Primary method**: `git branch --show-current` (most reliable)
//! - **Fallback method**: Read `.git/HEAD` file directly (for environments without git CLI)
//! - **Detached HEAD**: Returns `None` for branch, or commit hash with special marker
//! - **Caching**: Per working directory cache to avoid repeated subprocess/file reads
//!
//! # Usage
//!
//! ```ignore
//! use dcg_cli::git::get_current_branch;
//!
//! if let Some(branch) = get_current_branch() {
//!     println!("Current branch: {}", branch);
//! } else {
//!     println!("Not on a branch (detached HEAD or not in git repo)");
//! }
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// Cache duration before refreshing branch info.
/// 30 seconds is reasonable for a CLI tool that runs briefly.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// Result of branch detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchInfo {
    /// On a named branch (e.g., "main", "feature/foo").
    Branch(String),
    /// In detached HEAD state with optional commit hash.
    DetachedHead(Option<String>),
    /// Not in a git repository.
    NotGitRepo,
}

impl BranchInfo {
    /// Returns the branch name if on a named branch, `None` otherwise.
    #[must_use]
    pub fn branch_name(&self) -> Option<&str> {
        match self {
            Self::Branch(name) => Some(name),
            Self::DetachedHead(_) | Self::NotGitRepo => None,
        }
    }

    /// Returns `true` if in a git repository (either on a branch or detached HEAD).
    #[must_use]
    pub fn is_in_git_repo(&self) -> bool {
        !matches!(self, Self::NotGitRepo)
    }

    /// Returns `true` if on a named branch.
    #[must_use]
    pub fn is_on_branch(&self) -> bool {
        matches!(self, Self::Branch(_))
    }

    /// Returns `true` if in detached HEAD state.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        matches!(self, Self::DetachedHead(_))
    }
}

/// Cached branch information for a specific working directory.
#[derive(Debug)]
struct CachedBranch {
    /// The working directory this cache entry is for.
    working_dir: PathBuf,
    /// The cached branch info.
    info: BranchInfo,
    /// When this cache entry was created.
    cached_at: Instant,
}

impl CachedBranch {
    /// Returns `true` if this cache entry is still valid.
    fn is_valid(&self, current_dir: &PathBuf) -> bool {
        self.working_dir == *current_dir && self.cached_at.elapsed() < CACHE_TTL
    }
}

thread_local! {
    /// Per-thread cache for branch information.
    /// Keyed by working directory to handle directory changes.
    static BRANCH_CACHE: RefCell<HashMap<PathBuf, CachedBranch>> = RefCell::new(HashMap::new());
}

/// Get the current git branch, using cache if available.
///
/// Returns `None` if not on a named branch (detached HEAD) or not in a git repo.
/// Use [`get_branch_info`] for more detailed information.
///
/// # Caching
///
/// Results are cached per working directory for up to 30 seconds to avoid
/// repeated subprocess calls. The cache is automatically invalidated when
/// the working directory changes.
#[must_use]
pub fn get_current_branch() -> Option<String> {
    get_branch_info().branch_name().map(String::from)
}

/// Get detailed branch information, using cache if available.
///
/// Returns a [`BranchInfo`] enum indicating:
/// - `Branch(name)`: On a named branch
/// - `DetachedHead(hash)`: In detached HEAD state (with optional commit hash)
/// - `NotGitRepo`: Not in a git repository
#[must_use]
pub fn get_branch_info() -> BranchInfo {
    let current_dir = std::env::current_dir().unwrap_or_default();
    cached_branch_info_for_dir(current_dir, fetch_branch_info)
}

fn cached_branch_info_for_dir(
    current_dir: PathBuf,
    fetch: impl FnOnce() -> BranchInfo,
) -> BranchInfo {
    let cached = BRANCH_CACHE.with(|cache| {
        let mut entries = cache.borrow_mut();
        if let Some(entry) = entries.get(&current_dir) {
            if entry.is_valid(&current_dir) {
                return Some(entry.info.clone());
            }
        }
        entries.remove(&current_dir);
        None
    });

    if let Some(info) = cached {
        return info;
    }

    // Cache miss - fetch fresh info
    let info = fetch();

    // Update cache
    BRANCH_CACHE.with(|cache| {
        let entry = CachedBranch {
            working_dir: current_dir.clone(),
            info: info.clone(),
            cached_at: Instant::now(),
        };
        cache.borrow_mut().insert(current_dir, entry);
    });

    info
}

/// Get branch information for a specific path.
///
/// This bypasses the cache since it's for a specific path that may differ
/// from the current working directory.
#[must_use]
pub fn get_branch_info_at_path(path: &std::path::Path) -> BranchInfo {
    fetch_branch_info_at_path(path)
}

/// Clear the branch cache.
///
/// Useful for testing or when you know the branch has changed.
pub fn clear_cache() {
    BRANCH_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}

/// Fetch branch info without caching.
fn fetch_branch_info() -> BranchInfo {
    // Try primary method: git command
    if let Some(info) = get_branch_from_git_command(None) {
        return info;
    }

    // Fallback: read .git/HEAD directly
    get_branch_from_head_file(None)
}

/// Fetch branch info for a specific path without caching.
fn fetch_branch_info_at_path(path: &std::path::Path) -> BranchInfo {
    // Try primary method: git command
    if let Some(info) = get_branch_from_git_command(Some(path)) {
        return info;
    }

    // Fallback: read .git/HEAD directly
    get_branch_from_head_file(Some(path))
}

/// Primary method: Use `git branch --show-current` to get the branch name.
///
/// This is the most reliable method as it handles all edge cases correctly,
/// including worktrees, submodules, and unusual repository layouts.
fn get_branch_from_git_command(working_dir: Option<&std::path::Path>) -> Option<BranchInfo> {
    let mut cmd = Command::new("git");
    cmd.args(["branch", "--show-current"]);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    // Suppress stderr to avoid noise when not in a git repo
    cmd.stderr(std::process::Stdio::null());

    let output = cmd.output().ok()?;

    if !output.status.success() {
        // Git command failed - might not be in a repo
        return None;
    }

    let branch = String::from_utf8(output.stdout).ok()?.trim().to_string();

    if branch.is_empty() {
        // Empty output means detached HEAD
        // Try to get the commit hash
        let hash = get_detached_head_hash(working_dir);
        Some(BranchInfo::DetachedHead(hash))
    } else {
        Some(BranchInfo::Branch(branch))
    }
}

/// Get the commit hash when in detached HEAD state.
fn get_detached_head_hash(working_dir: Option<&std::path::Path>) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(["rev-parse", "--short", "HEAD"]);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    cmd.stderr(std::process::Stdio::null());

    let output = cmd.output().ok()?;

    if output.status.success() {
        let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
        if !hash.is_empty() {
            return Some(hash);
        }
    }

    None
}

/// Fallback method: Read `.git/HEAD` file directly.
///
/// Format: `ref: refs/heads/<branch-name>` for branches
/// or a commit hash for detached HEAD.
fn get_branch_from_head_file(working_dir: Option<&std::path::Path>) -> BranchInfo {
    let git_dir = find_git_dir(working_dir);
    let head_path = match git_dir {
        Some(dir) => dir.join("HEAD"),
        None => return BranchInfo::NotGitRepo,
    };

    let head_content = match std::fs::read_to_string(&head_path) {
        Ok(content) => content,
        Err(_) => return BranchInfo::NotGitRepo,
    };

    parse_head_content(&head_content)
}

fn parse_head_content(head_content: &str) -> BranchInfo {
    let trimmed = head_content.trim();

    // Symbolic ref: "ref: refs/heads/<branch>" (normal) or other refs (detached-ish state)
    if let Some(ref_path) = trimmed.strip_prefix("ref: ") {
        if let Some(branch) = ref_path.strip_prefix("refs/heads/") {
            return BranchInfo::Branch(branch.to_string());
        }
        // Non-head symbolic refs (e.g., refs/remotes/origin/main) are valid git states,
        // but not local branches.
        return BranchInfo::DetachedHead(None);
    }

    // It's a commit hash (detached HEAD).
    // Accept 7..=64 hex chars: 40 for SHA-1 (default), 64 for SHA-256 repos
    // (`extensions.objectFormat = sha256`), and any abbreviated form between.
    if trimmed.len() >= 7 && trimmed.len() <= 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        // Return abbreviated hash (first 7 chars)
        let short_hash = if trimmed.len() > 7 {
            trimmed[..7].to_string()
        } else {
            trimmed.to_string()
        };
        return BranchInfo::DetachedHead(Some(short_hash));
    }

    // Couldn't parse HEAD as a symbolic ref or hex hash. We already proved
    // `.git/HEAD` exists (the caller's `read_to_string` succeeded), so this
    // IS a git repository — just one whose HEAD is in an unusual state
    // (mid-rebase rewrite, packed refs we don't recognize, CRLF noise, an
    // empty file mid-write, etc.). Returning `NotGitRepo` here would silently
    // disable downstream branch-strictness policy (a fail-open relaxation
    // of protection). `DetachedHead(None)` is the conservative classification
    // — it preserves "this is a git repo" while indicating "no current
    // branch known."
    BranchInfo::DetachedHead(None)
}

/// Find the .git directory for a repository.
///
/// Handles both regular repositories (.git as directory) and worktrees
/// (.git as file pointing to the actual git directory).
fn find_git_dir(working_dir: Option<&std::path::Path>) -> Option<PathBuf> {
    let start_dir = working_dir
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;

    let mut current = start_dir.as_path();

    loop {
        let git_path = current.join(".git");

        if git_path.is_dir() {
            // Regular git directory
            return Some(git_path);
        }

        if git_path.is_file() {
            // Worktree: .git file contains "gitdir: <path>"
            if let Ok(content) = std::fs::read_to_string(&git_path) {
                if let Some(gitdir) = parse_gitdir_from_dot_git_file(&content) {
                    let gitdir_path = PathBuf::from(gitdir);
                    // Handle relative paths
                    let resolved = if gitdir_path.is_absolute() {
                        gitdir_path
                    } else {
                        current.join(gitdir_path)
                    };
                    if resolved.is_dir() {
                        return Some(resolved);
                    }
                }
            }
        }

        // Move up to parent directory
        current = current.parent()?;
    }
}

fn parse_gitdir_from_dot_git_file(content: &str) -> Option<&str> {
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix("gitdir:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

/// Check if the current directory is in a git repository.
#[must_use]
pub fn is_in_git_repo() -> bool {
    get_branch_info().is_in_git_repo()
}

/// Check if the specified path is in a git repository.
#[must_use]
pub fn is_in_git_repo_at_path(path: &std::path::Path) -> bool {
    get_branch_info_at_path(path).is_in_git_repo()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    fn run_git(repo_path: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(repo_path)
            .args(args)
            .output()
            .expect("failed to run git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_git_repo(repo_path: &Path) {
        run_git(repo_path, &["init"]);
        run_git(
            repo_path,
            &["config", "user.email", "dcg-tests@example.com"],
        );
        run_git(repo_path, &["config", "user.name", "DCG Tests"]);
    }

    fn create_commit(repo_path: &Path, file_name: &str) {
        fs::write(repo_path.join(file_name), "test data").expect("write commit fixture file");
        run_git(repo_path, &["add", file_name]);
        run_git(repo_path, &["commit", "-m", "test commit"]);
    }

    #[test]
    fn test_branch_info_methods() {
        let branch = BranchInfo::Branch("main".to_string());
        assert_eq!(branch.branch_name(), Some("main"));
        assert!(branch.is_in_git_repo());
        assert!(branch.is_on_branch());
        assert!(!branch.is_detached());

        let detached = BranchInfo::DetachedHead(Some("abc1234".to_string()));
        assert_eq!(detached.branch_name(), None);
        assert!(detached.is_in_git_repo());
        assert!(!detached.is_on_branch());
        assert!(detached.is_detached());

        let not_repo = BranchInfo::NotGitRepo;
        assert_eq!(not_repo.branch_name(), None);
        assert!(!not_repo.is_in_git_repo());
        assert!(!not_repo.is_on_branch());
        assert!(!not_repo.is_detached());
    }

    #[test]
    fn test_cache_validity() {
        let current_dir = PathBuf::from("/test/path");
        let other_dir = PathBuf::from("/other/path");

        let cache = CachedBranch {
            working_dir: current_dir.clone(),
            info: BranchInfo::Branch("main".to_string()),
            cached_at: Instant::now(),
        };

        // Same directory, fresh cache
        assert!(cache.is_valid(&current_dir));

        // Different directory
        assert!(!cache.is_valid(&other_dir));
    }

    #[test]
    fn test_branch_cache_keeps_entries_per_directory() {
        clear_cache();

        let fetch_count = Cell::new(0);
        let dir_a = PathBuf::from("/test/repo-a");
        let dir_b = PathBuf::from("/test/repo-b");

        let first = cached_branch_info_for_dir(dir_a.clone(), || {
            fetch_count.set(fetch_count.get() + 1);
            BranchInfo::Branch("main".to_string())
        });
        let second = cached_branch_info_for_dir(dir_b, || {
            fetch_count.set(fetch_count.get() + 1);
            BranchInfo::Branch("feature/cache".to_string())
        });
        let third = cached_branch_info_for_dir(dir_a, || {
            panic!("expected repo-a branch info to come from cache")
        });

        assert_eq!(first, BranchInfo::Branch("main".to_string()));
        assert_eq!(second, BranchInfo::Branch("feature/cache".to_string()));
        assert_eq!(third, BranchInfo::Branch("main".to_string()));
        assert_eq!(fetch_count.get(), 2);

        clear_cache();
    }

    #[test]
    fn test_branch_cache_refreshes_expired_entries() {
        clear_cache();

        let dir = PathBuf::from("/test/expired-repo");
        let expired_at = Instant::now()
            .checked_sub(CACHE_TTL + Duration::from_secs(1))
            .expect("system uptime should exceed cache TTL");

        BRANCH_CACHE.with(|cache| {
            cache.borrow_mut().insert(
                dir.clone(),
                CachedBranch {
                    working_dir: dir.clone(),
                    info: BranchInfo::Branch("stale".to_string()),
                    cached_at: expired_at,
                },
            );
        });

        let fetch_count = Cell::new(0);
        let refreshed = cached_branch_info_for_dir(dir.clone(), || {
            fetch_count.set(fetch_count.get() + 1);
            BranchInfo::Branch("fresh".to_string())
        });
        let cached_again = cached_branch_info_for_dir(dir, || {
            panic!("expected refreshed branch info to come from cache")
        });

        assert_eq!(refreshed, BranchInfo::Branch("fresh".to_string()));
        assert_eq!(cached_again, BranchInfo::Branch("fresh".to_string()));
        assert_eq!(fetch_count.get(), 1);

        clear_cache();
    }

    #[test]
    fn test_head_file_parsing_branch() {
        let info = parse_head_content("ref: refs/heads/feature/my-branch");
        assert_eq!(info, BranchInfo::Branch("feature/my-branch".to_string()));
    }

    #[test]
    fn test_head_file_parsing_non_head_ref_is_detached() {
        let info = parse_head_content("ref: refs/remotes/origin/main");
        assert_eq!(info, BranchInfo::DetachedHead(None));
    }

    #[test]
    fn test_head_file_parsing_detached() {
        // Test commit hash detection
        let hash = "abc1234def5678";
        assert!(hash.len() >= 7 && hash.len() <= 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        let info = parse_head_content(hash);
        assert_eq!(info, BranchInfo::DetachedHead(Some("abc1234".to_string())));
    }

    #[test]
    fn test_head_file_parsing_sha256_hash_is_detached_not_not_git_repo() {
        // Repos using `extensions.objectFormat = sha256` store 64-hex-char
        // commit hashes in HEAD. Before the fix the parser rejected
        // anything > 40 chars and returned `NotGitRepo`, which silently
        // disabled branch-strictness policy across every dcg invocation
        // in such a repo (a fail-open relaxation of protection).
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(hash.len(), 64);
        let info = parse_head_content(hash);
        assert!(
            matches!(info, BranchInfo::DetachedHead(Some(_))),
            "SHA-256 HEAD should classify as DetachedHead, got {info:?}"
        );
        assert!(
            info.is_in_git_repo(),
            "SHA-256 HEAD must report is_in_git_repo() = true"
        );
    }

    #[test]
    fn test_head_file_parsing_unrecognized_content_falls_back_to_detached_not_not_git_repo() {
        // The caller already proved `.git/HEAD` exists by reading it. If
        // the content is not a symbolic ref and not hex (corrupted file,
        // mid-write empty content, packed-refs symbolic line we don't yet
        // support, CRLF noise...), fall back to `DetachedHead(None)` so
        // downstream branch-strictness remains active. Returning
        // `NotGitRepo` would silently disable protection on a real repo.
        for unusual in [
            "",                                  // empty file (mid-write race)
            "not-a-hash-or-ref",                 // garbage
            "ref: refs/something-weird/foo\r\n", // non-head ref with CRLF
            "0123456789abcdefghij",              // looks hash-like but has non-hex char
        ] {
            let info = parse_head_content(unusual);
            assert!(
                info.is_in_git_repo(),
                "unrecognized HEAD content must NOT be classified as NotGitRepo: input={unusual:?}, got {info:?}"
            );
        }
    }

    #[test]
    fn test_parse_gitdir_from_dot_git_file_multiline() {
        let content = "gitdir: ../.git/worktrees/demo\nworktree: /tmp/demo\n";
        assert_eq!(
            parse_gitdir_from_dot_git_file(content),
            Some("../.git/worktrees/demo")
        );
    }

    #[test]
    fn test_find_git_dir_resolves_worktree_pointer_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        let worktree = repo_root.join("nested").join("worktree");
        let git_dir = repo_root.join(".real-git-dir");

        fs::create_dir_all(&worktree).expect("create worktree");
        fs::create_dir_all(&git_dir).expect("create git dir");

        let dot_git = repo_root.join(".git");
        fs::write(
            &dot_git,
            "gitdir: .real-git-dir\nworktree: nested/worktree\n",
        )
        .expect("write .git file");

        let resolved = find_git_dir(Some(&worktree)).expect("resolve git dir");
        assert_eq!(resolved, git_dir);
    }

    #[test]
    fn test_clear_cache() {
        // Just verify clear_cache doesn't panic
        clear_cache();

        // And that we can still get branch info after clearing
        let _ = get_branch_info();
    }

    #[test]
    fn test_get_current_branch_returns_some_in_git_repo() {
        // This test runs in the dcg repo, so should return a branch
        // unless we're in a weird CI state
        let result = get_current_branch();
        // We don't assert the specific value since it could be any branch
        // Just verify the function doesn't panic
        drop(result);
    }

    #[test]
    fn test_is_in_git_repo() {
        // This test runs in the dcg repo
        let result = is_in_git_repo();
        // Should be true since we're in a git repo
        assert!(result, "Expected to be in a git repo");
    }

    #[test]
    fn test_branch_info_at_temp_path() {
        // Test with a path that's definitely not a git repo
        let temp_dir = std::env::temp_dir();
        let result = get_branch_info_at_path(&temp_dir);
        // Temp dir might or might not be in a git repo depending on system
        // Just verify it doesn't panic
        drop(result);
    }

    #[test]
    fn test_get_branch_info_at_path_detects_named_branch() {
        let temp = tempfile::tempdir().expect("tempdir");
        init_git_repo(temp.path());
        run_git(temp.path(), &["checkout", "-b", "feature/test"]);

        let info = get_branch_info_at_path(temp.path());
        assert_eq!(info, BranchInfo::Branch("feature/test".to_string()));
    }

    #[test]
    fn test_get_branch_info_at_path_detects_detached_head() {
        let temp = tempfile::tempdir().expect("tempdir");
        init_git_repo(temp.path());
        create_commit(temp.path(), "detached.txt");
        run_git(temp.path(), &["checkout", "--detach"]);

        let info = get_branch_info_at_path(temp.path());
        assert!(
            matches!(info, BranchInfo::DetachedHead(_)),
            "Expected detached HEAD, got {info:?}"
        );
    }

    #[test]
    fn test_get_branch_info_at_path_returns_not_git_repo_for_plain_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let info = get_branch_info_at_path(temp.path());
        assert_eq!(info, BranchInfo::NotGitRepo);
    }
}

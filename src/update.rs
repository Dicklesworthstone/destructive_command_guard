//! Self-update version check functionality.
//!
//! This module provides functionality to check for newer versions of dcg
//! by querying the GitHub Releases API. Results are cached to avoid API spam.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Cache duration for version checks (24 hours).
pub const CACHE_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// GitHub repository owner.
const REPO_OWNER: &str = "Dicklesworthstone";

/// GitHub repository name.
const REPO_NAME: &str = "destructive_command_guard";

/// Result of a version check operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionCheckResult {
    /// Current installed version.
    pub current_version: String,
    /// Latest available version from GitHub.
    pub latest_version: String,
    /// Whether an update is available.
    pub update_available: bool,
    /// URL to the latest release.
    pub release_url: String,
    /// Release notes/body (first 500 chars).
    pub release_notes: Option<String>,
    /// When this check was performed.
    pub checked_at: String,
}

/// Cached version check data.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedCheck {
    /// The check result.
    result: VersionCheckResult,
    /// Unix timestamp when cached.
    cached_at_secs: u64,
}

/// Errors that can occur during version check or update.
#[derive(Debug)]
pub enum VersionCheckError {
    /// Network request failed.
    NetworkError(String),
    /// Failed to parse API response.
    ParseError(String),
    /// Failed to read/write cache.
    CacheError(String),
    /// Current version could not be determined.
    CurrentVersionError(String),
    /// Update operation failed.
    UpdateError(String),
    /// Backup operation failed.
    BackupError(String),
    /// No update available.
    NoUpdateAvailable,
}

impl std::fmt::Display for VersionCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "Network error: {msg}"),
            Self::ParseError(msg) => write!(f, "Parse error: {msg}"),
            Self::CacheError(msg) => write!(f, "Cache error: {msg}"),
            Self::CurrentVersionError(msg) => write!(f, "Version error: {msg}"),
            Self::UpdateError(msg) => write!(f, "Update error: {msg}"),
            Self::BackupError(msg) => write!(f, "Backup error: {msg}"),
            Self::NoUpdateAvailable => write!(f, "No update available"),
        }
    }
}

impl std::error::Error for VersionCheckError {}

/// Get the path to the version check cache file.
fn cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("dcg").join("version_check.json"))
}

/// Read cached version check if it exists and is still valid.
fn read_cache() -> Option<VersionCheckResult> {
    let path = cache_path()?;
    let content = fs::read_to_string(&path).ok()?;
    let cached: CachedCheck = serde_json::from_str(&content).ok()?;

    // Check if cache is still valid
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    if now.saturating_sub(cached.cached_at_secs) < CACHE_DURATION.as_secs() {
        Some(cached.result)
    } else {
        None
    }
}

/// Write version check result to cache.
fn write_cache(result: &VersionCheckResult) -> Result<(), VersionCheckError> {
    let path = cache_path().ok_or_else(|| {
        VersionCheckError::CacheError("Could not determine cache directory".to_string())
    })?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            VersionCheckError::CacheError(format!("Failed to create cache directory: {e}"))
        })?;
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| VersionCheckError::CacheError(format!("Failed to get current time: {e}")))?
        .as_secs();

    let cached = CachedCheck {
        result: result.clone(),
        cached_at_secs: now,
    };

    let content = serde_json::to_string_pretty(&cached)
        .map_err(|e| VersionCheckError::CacheError(format!("Failed to serialize cache: {e}")))?;

    fs::write(&path, content)
        .map_err(|e| VersionCheckError::CacheError(format!("Failed to write cache: {e}")))?;

    Ok(())
}

/// Get the current version of dcg from Cargo.toml.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Check for updates, using cache if available.
///
/// Returns the version check result, either from cache or from a fresh API call.
///
/// # Errors
///
/// Returns `VersionCheckError` if the network request fails, the API response
/// cannot be parsed, or the current version cannot be determined.
pub fn check_for_update(force_refresh: bool) -> Result<VersionCheckResult, VersionCheckError> {
    // Try cache first (unless force refresh)
    if !force_refresh {
        if let Some(cached) = read_cache() {
            return Ok(cached);
        }
    }

    // Fetch fresh data from GitHub
    let result = fetch_latest_version()?;

    // Cache the result
    if let Err(e) = write_cache(&result) {
        // Log cache error but don't fail the check
        eprintln!("Warning: Failed to cache version check: {e}");
    }

    Ok(result)
}

/// Fetch the latest version from GitHub Releases API.
fn fetch_latest_version() -> Result<VersionCheckResult, VersionCheckError> {
    let current = current_version();

    // Use self_update crate to fetch release info
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()
        .map_err(|e| VersionCheckError::NetworkError(format!("Failed to configure release list: {e}")))?
        .fetch()
        .map_err(|e| VersionCheckError::NetworkError(format!("Failed to fetch releases: {e}")))?;

    let latest = releases
        .first()
        .ok_or_else(|| VersionCheckError::ParseError("No releases found".to_string()))?;

    // Strip 'v' prefix if present
    let latest_version = latest.version.trim_start_matches('v').to_string();
    let current_clean = current.trim_start_matches('v');

    // Compare versions using semver
    let update_available = match (
        semver::Version::parse(current_clean),
        semver::Version::parse(&latest_version),
    ) {
        (Ok(curr), Ok(lat)) => lat > curr,
        _ => {
            // Fallback to string comparison if semver fails
            latest_version != current_clean
        }
    };

    let checked_at = chrono::Utc::now().to_rfc3339();

    // Truncate release notes if too long
    let release_notes = latest.body.as_ref().map(|body| {
        if body.len() > 500 {
            format!("{}...", &body[..497])
        } else {
            body.clone()
        }
    });

    let result = VersionCheckResult {
        current_version: current.to_string(),
        latest_version,
        update_available,
        release_url: format!("https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest"),
        release_notes,
        checked_at,
    };

    Ok(result)
}

/// Clear the version check cache.
///
/// # Errors
///
/// Returns `VersionCheckError::CacheError` if the cache file exists but cannot be removed.
pub fn clear_cache() -> Result<(), VersionCheckError> {
    if let Some(path) = cache_path() {
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                VersionCheckError::CacheError(format!("Failed to remove cache: {e}"))
            })?;
        }
    }
    Ok(())
}

/// Format the version check result for display.
#[must_use]
pub fn format_check_result(result: &VersionCheckResult, use_color: bool) -> String {
    use std::fmt::Write;
    let mut output = String::new();

    if use_color {
        writeln!(output, "\x1b[1mCurrent version:\x1b[0m {}", result.current_version).ok();
        writeln!(output, "\x1b[1mLatest version:\x1b[0m  {}", result.latest_version).ok();
        writeln!(output).ok();

        if result.update_available {
            writeln!(
                output,
                "\x1b[33m✨ Update available!\x1b[0m Run '\x1b[1mdcg update\x1b[0m' to upgrade"
            )
            .ok();
        } else {
            writeln!(output, "\x1b[32m✓ You're up to date!\x1b[0m").ok();
        }
    } else {
        writeln!(output, "Current version: {}", result.current_version).ok();
        writeln!(output, "Latest version:  {}", result.latest_version).ok();
        writeln!(output).ok();

        if result.update_available {
            writeln!(output, "Update available! Run 'dcg update' to upgrade").ok();
        } else {
            writeln!(output, "You're up to date!").ok();
        }
    }

    output
}

/// Format version check result as JSON.
///
/// # Errors
///
/// Returns `VersionCheckError::ParseError` if JSON serialization fails.
pub fn format_check_result_json(result: &VersionCheckResult) -> Result<String, VersionCheckError> {
    serde_json::to_string_pretty(result)
        .map_err(|e| VersionCheckError::ParseError(format!("Failed to serialize result: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version() {
        let version = current_version();
        assert!(!version.is_empty());
        // Should be valid semver
        assert!(semver::Version::parse(version).is_ok());
    }

    #[test]
    fn test_version_check_result_serialization() {
        let result = VersionCheckResult {
            current_version: "0.2.12".to_string(),
            latest_version: "0.3.0".to_string(),
            update_available: true,
            release_url: "https://github.com/test/repo/releases/latest".to_string(),
            release_notes: Some("Bug fixes".to_string()),
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: VersionCheckResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.current_version, result.current_version);
        assert_eq!(parsed.latest_version, result.latest_version);
        assert_eq!(parsed.update_available, result.update_available);
    }

    #[test]
    fn test_format_check_result_up_to_date() {
        let result = VersionCheckResult {
            current_version: "1.0.0".to_string(),
            latest_version: "1.0.0".to_string(),
            update_available: false,
            release_url: "https://example.com".to_string(),
            release_notes: None,
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        let output = format_check_result(&result, false);
        assert!(output.contains("You're up to date"));
        assert!(output.contains("1.0.0"));
    }

    #[test]
    fn test_format_check_result_update_available() {
        let result = VersionCheckResult {
            current_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            update_available: true,
            release_url: "https://example.com".to_string(),
            release_notes: None,
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        let output = format_check_result(&result, false);
        assert!(output.contains("Update available"));
        assert!(output.contains("dcg update"));
    }
}

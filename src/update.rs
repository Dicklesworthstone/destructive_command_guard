//! Self-update version check functionality.
//!
//! This module provides functionality to check for newer versions of dcg
//! by querying the GitHub Releases API. Results are cached to avoid API spam.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime};

use self_update::update::Release;
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
    /// URL to the release corresponding to `latest_version`.
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

// =============================================================================
// Backup Manager for Version Rollback
// =============================================================================

/// Maximum number of backup versions to keep.
const MAX_BACKUPS: usize = 3;

/// Backup entry metadata stored alongside the backup binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Version of the backed-up binary.
    pub version: String,
    /// Unix timestamp when the backup was created.
    pub created_at: u64,
    /// Actual backup artifact basename (without `.json`) if non-legacy naming was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_name: Option<String>,
    /// Original path where dcg was installed.
    pub original_path: PathBuf,
}

/// Get the path to the backup directory.
#[must_use]
pub fn backup_dir() -> Option<PathBuf> {
    crate::config::user_data_dir().map(|d| d.join("dcg").join("backups"))
}

fn is_valid_backup_artifact_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(':')
}

fn backup_artifact_name(entry: &BackupEntry) -> String {
    entry
        .artifact_name
        .as_deref()
        .filter(|name| is_valid_backup_artifact_name(name))
        .map(str::to_string)
        .unwrap_or_else(|| format!("dcg-{}-{}", entry.version, entry.created_at))
}

fn generate_unique_backup_name(dir: &Path, version: &str, timestamp: u64) -> String {
    let base = format!("dcg-{version}-{timestamp}");
    let base_path = dir.join(&base);
    let base_metadata_path = dir.join(format!("{base}.json"));

    if !base_path.exists() && !base_metadata_path.exists() {
        return base;
    }

    let nanos_suffix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.subsec_nanos());
    let fallback = format!("{base}-{nanos_suffix:09}");
    let fallback_path = dir.join(&fallback);
    let fallback_metadata_path = dir.join(format!("{fallback}.json"));
    if !fallback_path.exists() && !fallback_metadata_path.exists() {
        return fallback;
    }

    for counter in 1..=u32::MAX {
        let candidate = format!("{base}-{nanos_suffix:09}-{counter}");
        let candidate_path = dir.join(&candidate);
        let candidate_metadata_path = dir.join(format!("{candidate}.json"));
        if !candidate_path.exists() && !candidate_metadata_path.exists() {
            return candidate;
        }
    }

    // Practically unreachable, but keep behavior deterministic.
    format!("{base}-{nanos_suffix:09}-overflow")
}

/// List this installation's backup versions, newest first.
///
/// # Errors
///
/// Returns `VersionCheckError::BackupError` if the backup directory cannot be read.
pub fn list_backups() -> Result<Vec<BackupEntry>, VersionCheckError> {
    let current_exe = std::env::current_exe().map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to get current executable path: {e}"))
    })?;
    Ok(list_all_backups()?
        .into_iter()
        .filter(|entry| backup_belongs_to_installation(entry, &current_exe))
        .collect())
}

fn backup_belongs_to_installation(entry: &BackupEntry, installation: &Path) -> bool {
    entry.original_path == installation
        || fs::canonicalize(&entry.original_path)
            .ok()
            .zip(fs::canonicalize(installation).ok())
            .is_some_and(|(original, current)| original == current)
}

fn list_all_backups() -> Result<Vec<BackupEntry>, VersionCheckError> {
    let dir = backup_dir().ok_or_else(|| {
        VersionCheckError::BackupError("Could not determine backup directory".to_string())
    })?;

    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for entry in fs::read_dir(&dir).map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to read backup directory: {e}"))
    })? {
        let entry = entry.map_err(|e| {
            VersionCheckError::BackupError(format!("Failed to read directory entry: {e}"))
        })?;

        let path = entry.path();

        // Look for .json metadata files
        if path.extension().is_some_and(|ext| ext == "json") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(backup) = serde_json::from_str::<BackupEntry>(&content) {
                    entries.push(backup);
                }
            }
        }
    }

    // Sort by creation time, newest first
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));

    Ok(entries)
}

/// Create a backup of the current dcg binary before updating.
///
/// # Errors
///
/// Returns `VersionCheckError::BackupError` if the backup cannot be created.
pub fn create_backup() -> Result<PathBuf, VersionCheckError> {
    let current_exe = std::env::current_exe().map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to get current executable path: {e}"))
    })?;
    create_backup_for(&current_exe, current_version())
}

/// Snapshot the binary that the installer will actually replace. The caller
/// supplies that binary's version, which may differ from the running program
/// when an explicit installation destination was requested.
///
/// Creating a recovery point never prunes older backups: only a successful
/// replacement may commit retention changes.
pub(crate) fn create_backup_for(
    binary: &Path,
    version: &str,
) -> Result<PathBuf, VersionCheckError> {
    let dir = backup_dir().ok_or_else(|| {
        VersionCheckError::BackupError("Could not determine backup directory".to_string())
    })?;
    create_backup_in(&dir, binary, version)
}

/// Probe a local executable without enabling hook repair, update checks, or
/// ambient output modes. A reported version is usable only after native exit 0.
pub(crate) fn reported_binary_version(binary: &Path) -> Result<String, VersionCheckError> {
    let output = std::process::Command::new(binary)
        .arg("--version")
        .env("DCG_SELF_HEAL_HOOK", "0")
        .env("DCG_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1")
        .env("DCG_NO_COLOR", "1")
        .env_remove("DCG_ROBOT")
        .env_remove("DCG_QUIET")
        .env_remove("DCG_FORMAT")
        .output()
        .map_err(|error| {
            VersionCheckError::BackupError(format!(
                "Could not identify existing {}: {error}",
                binary.display()
            ))
        })?;
    if !output.status.success() {
        return Err(VersionCheckError::BackupError(format!(
            "Refusing to replace {} without an identifiable recovery version (status {})",
            binary.display(),
            output.status
        )));
    }
    parse_binary_version(&output.stdout, &output.stderr).ok_or_else(|| {
        VersionCheckError::BackupError(format!(
            "Could not identify recovery version for {}: expected an unambiguous SemVer",
            binary.display()
        ))
    })
}

pub(crate) fn parse_binary_version(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let stdout = std::str::from_utf8(stdout).ok()?;
    let stderr = std::str::from_utf8(stderr).ok()?;
    let mut found = None;
    for line in stdout.lines().chain(stderr.lines()) {
        let candidate = line.trim();
        let candidate = candidate
            .strip_prefix("dcg")
            .filter(|suffix| suffix.starts_with(char::is_whitespace))
            .map_or(candidate, str::trim_start);
        let candidate = candidate.strip_prefix('v').unwrap_or(candidate);
        if let Ok(version) = semver::Version::parse(candidate) {
            let version = version.to_string();
            if found.as_ref().is_some_and(|previous| previous != &version) {
                return None;
            }
            found = Some(version);
        }
    }
    found
}

fn copy_to_new_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let mut input = fs::File::open(source)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "backup source is not a regular file",
        ));
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    let result = (|| {
        std::io::copy(&mut input, &mut output)?;
        output.set_permissions(metadata.permissions())?;
        output.sync_all()
    })();
    drop(output);
    if result.is_err() {
        // Only this call's exclusively created, incomplete file is removed.
        let _ = fs::remove_file(destination);
    }
    result
}

fn create_backup_in(
    dir: &Path,
    binary: &Path,
    version: &str,
) -> Result<PathBuf, VersionCheckError> {
    let version = semver::Version::parse(version)
        .map_err(|e| VersionCheckError::BackupError(format!("Invalid backup version: {e}")))?;
    let version = version.to_string();
    fs::create_dir_all(dir).map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to create backup directory: {e}"))
    })?;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| VersionCheckError::BackupError(format!("Failed to get timestamp: {e}")))?
        .as_secs();

    let backup_name = generate_unique_backup_name(dir, &version, timestamp);
    let backup_path = dir.join(&backup_name);
    let metadata_path = dir.join(format!("{backup_name}.json"));

    copy_to_new_file(binary, &backup_path).map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to copy binary to backup: {e}"))
    })?;

    // Write metadata
    let entry = BackupEntry {
        version,
        created_at: timestamp,
        artifact_name: Some(backup_name.clone()),
        original_path: binary.to_path_buf(),
    };

    let metadata_content = serde_json::to_string_pretty(&entry).map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to serialize backup metadata: {e}"))
    })?;

    let mut metadata = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&metadata_path)
        .map_err(|e| {
            VersionCheckError::BackupError(format!("Failed to create backup metadata: {e}"))
        })?;
    metadata
        .write_all(metadata_content.as_bytes())
        .map_err(|e| {
            VersionCheckError::BackupError(format!("Failed to write backup metadata: {e}"))
        })?;
    metadata.sync_all().map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to flush backup metadata: {e}"))
    })?;

    Ok(backup_path)
}

fn backup_names_to_prune(backups: &[BackupEntry], preserve_artifact_names: &[&str]) -> Vec<String> {
    let mut sorted = backups.to_vec();
    sorted.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));

    // Reserve the recovery points first, including snapshots created in the
    // same timestamp second and an explicitly selected older rollback target.
    let mut retained_total = sorted
        .iter()
        .filter(|entry| preserve_artifact_names.contains(&backup_artifact_name(entry).as_str()))
        .count();
    let mut prune_names = Vec::new();

    for backup in sorted {
        let backup_name = backup_artifact_name(&backup);

        if preserve_artifact_names.contains(&backup_name.as_str()) {
            continue;
        }

        if retained_total < MAX_BACKUPS {
            retained_total += 1;
            continue;
        }

        prune_names.push(backup_name);
    }

    prune_names
}

/// Compute a retention plan before handing off an authenticated installer.
/// Deferred workers receive these exact paths and remove them only on success.
pub(crate) fn backup_files_to_prune(
    installation: &Path,
    preserve_paths: &[&Path],
) -> Result<Vec<PathBuf>, VersionCheckError> {
    // The data directory can be shared by multiple installations. Updating one
    // must neither choose nor prune another installation's recovery points.
    let backups: Vec<_> = list_all_backups()?
        .into_iter()
        .filter(|entry| backup_belongs_to_installation(entry, installation))
        .collect();
    let dir = backup_dir().ok_or_else(|| {
        VersionCheckError::BackupError("Could not determine backup directory".to_string())
    })?;
    let preserve_names: Vec<_> = preserve_paths
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect();
    let prune_names = backup_names_to_prune(&backups, &preserve_names);
    let mut paths = Vec::with_capacity(prune_names.len() * 2);
    for backup_name in prune_names {
        if !is_valid_backup_artifact_name(&backup_name) {
            return Err(VersionCheckError::BackupError(
                "Invalid backup artifact name in retention metadata".to_string(),
            ));
        }
        paths.push(dir.join(&backup_name));
        paths.push(dir.join(format!("{backup_name}.json")));
    }
    Ok(paths)
}

pub(crate) fn prune_backup_files(paths: &[PathBuf]) -> Result<(), VersionCheckError> {
    for path in paths {
        if let Err(error) = fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(VersionCheckError::BackupError(format!(
                    "Failed to prune {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

/// Rollback to a previous version.
///
/// If `target_version` is None, rolls back to the most recent backup.
/// If `target_version` is Some, rolls back to that specific version.
///
/// # Errors
///
/// Returns `VersionCheckError::BackupError` if no matching backup is found
/// or if the rollback operation fails.
pub fn rollback(target_version: Option<&str>) -> Result<String, VersionCheckError> {
    let backups = list_backups()?;

    if backups.is_empty() {
        return Err(VersionCheckError::BackupError(
            "No backup versions available".to_string(),
        ));
    }

    // Find the backup to restore
    let backup = if let Some(version) = target_version {
        let version_clean = version.trim_start_matches('v');
        backups
            .iter()
            .find(|b| b.version == version_clean || b.version == version)
            .ok_or_else(|| {
                VersionCheckError::BackupError(format!(
                    "No backup found for version {version}. Available versions: {}",
                    backups
                        .iter()
                        .map(|b| b.version.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?
    } else {
        // Use most recent backup
        backups.first().ok_or_else(|| {
            VersionCheckError::BackupError("No backup versions available".to_string())
        })?
    };

    let dir = backup_dir().ok_or_else(|| {
        VersionCheckError::BackupError("Could not determine backup directory".to_string())
    })?;

    let backup_name = backup_artifact_name(backup);
    if !is_valid_backup_artifact_name(&backup_name) {
        return Err(VersionCheckError::BackupError(
            "Invalid backup artifact name".to_string(),
        ));
    }
    let backup_path = dir.join(&backup_name);

    if !backup_path.exists() {
        return Err(VersionCheckError::BackupError(format!(
            "Backup file not found: {}",
            backup_path.display()
        )));
    }

    // Get current executable path for restoration
    let current_exe = std::env::current_exe().map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to get current executable path: {e}"))
    })?;

    let recovery_backup = create_backup()?;
    let prune_paths = backup_files_to_prune(&current_exe, &[&backup_path, &recovery_backup])?;
    swap_running_executable(&current_exe, &backup_path, &backup.version)?;
    if let Err(error) = prune_backup_files(&prune_paths) {
        eprintln!("Rollback succeeded, but older backups were retained: {error}");
    }

    Ok(format!(
        "Successfully rolled back to version {} (was at {})",
        backup.version,
        current_version()
    ))
}

/// Copy and qualify a backup beside the current executable before replacing it.
///
/// Unix rename replaces the directory entry atomically without trying to
/// truncate the running inode (which Linux rejects with ETXTBSY). Windows must
/// first move its locked executable aside, then publish the completed staged
/// file, restoring the incumbent if publication fails. The source backup is
/// never consumed.
fn swap_running_executable(
    current_exe: &Path,
    backup_path: &Path,
    expected_version: &str,
) -> Result<(), VersionCheckError> {
    if !current_exe.is_file() {
        return Err(VersionCheckError::BackupError(
            "Current executable is not a regular file".to_string(),
        ));
    }
    let parent = current_exe.parent().ok_or_else(|| {
        VersionCheckError::BackupError("Executable has no parent directory".to_string())
    })?;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| VersionCheckError::BackupError(format!("Failed to get timestamp: {e}")))?
        .as_nanos();
    let expected_version = semver::Version::parse(
        expected_version
            .strip_prefix('v')
            .unwrap_or(expected_version),
    )
    .map_err(|error| {
        VersionCheckError::BackupError(format!("Invalid rollback version in metadata: {error}"))
    })?
    .to_string();
    // The explicit executable suffix also permits a native Windows version
    // probe. The stage remains beside the destination for the final rename.
    let staged = parent.join(format!(".dcg-rollback-{}-{nanos}.exe", std::process::id()));
    copy_to_new_file(backup_path, &staged).map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to stage rollback backup: {e}"))
    })?;

    let result = (|| {
        let reported_version = reported_binary_version(&staged)?;
        if reported_version != expected_version {
            return Err(VersionCheckError::BackupError(format!(
                "Rollback backup version mismatch: expected {expected_version}, got {reported_version}"
            )));
        }
        publish_staged_executable(current_exe, &staged)
    })();
    // A successfully published file has already moved out of this path.
    let _ = fs::remove_file(&staged);
    result
}

fn publish_staged_executable(current_exe: &Path, staged: &Path) -> Result<(), VersionCheckError> {
    #[cfg(not(windows))]
    let result = fs::rename(staged, current_exe).map_err(|e| {
        VersionCheckError::BackupError(format!("Failed to publish rollback backup: {e}"))
    });

    #[cfg(windows)]
    let result = (|| {
        let backup_old = staged.with_extension("old");
        fs::rename(current_exe, &backup_old).map_err(|e| {
            VersionCheckError::BackupError(format!("Failed to move current executable: {e}"))
        })?;
        if let Err(error) = fs::rename(staged, current_exe) {
            if let Err(restore_error) = fs::rename(&backup_old, current_exe) {
                return Err(VersionCheckError::BackupError(format!(
                    "Failed to publish rollback backup ({error}) and restore the incumbent \
                     ({restore_error}); original executable remains at {}",
                    backup_old.display()
                )));
            }
            return Err(VersionCheckError::BackupError(format!(
                "Failed to publish rollback backup: {error}"
            )));
        }
        // Windows may retain the mapped incumbent until this process exits.
        let _ = fs::remove_file(&backup_old);
        Ok(())
    })();

    result
}

/// Format backup list for display.
#[must_use]
pub fn format_backup_list(backups: &[BackupEntry], use_color: bool) -> String {
    use std::fmt::Write;

    if backups.is_empty() {
        return if use_color {
            "\x1b[33mNo backup versions available.\x1b[0m\n\
             Run 'dcg update' to create a backup of the current version."
                .to_string()
        } else {
            "No backup versions available.\n\
             Run 'dcg update' to create a backup of the current version."
                .to_string()
        };
    }

    let mut output = String::new();

    if use_color {
        writeln!(output, "\x1b[1mAvailable backup versions:\x1b[0m").ok();
    } else {
        writeln!(output, "Available backup versions:").ok();
    }
    writeln!(output).ok();

    for (i, backup) in backups.iter().enumerate() {
        // Format timestamp as human-readable date
        let datetime = i64::try_from(backup.created_at)
            .ok()
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
            .map_or_else(
                || backup.created_at.to_string(),
                |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            );

        let marker = if i == 0 { " (most recent)" } else { "" };

        if use_color {
            writeln!(
                output,
                "  \x1b[1mv{}\x1b[0m{} - backed up {}",
                backup.version, marker, datetime
            )
            .ok();
        } else {
            writeln!(
                output,
                "  v{}{} - backed up {}",
                backup.version, marker, datetime
            )
            .ok();
        }
    }

    writeln!(output).ok();
    if use_color {
        writeln!(
            output,
            "Use '\x1b[1mdcg update --rollback\x1b[0m' to restore the most recent backup"
        )
        .ok();
        writeln!(
            output,
            "Use '\x1b[1mdcg update --rollback <version>\x1b[0m' to restore a specific version"
        )
        .ok();
    } else {
        writeln!(
            output,
            "Use 'dcg update --rollback' to restore the most recent backup"
        )
        .ok();
        writeln!(
            output,
            "Use 'dcg update --rollback <version>' to restore a specific version"
        )
        .ok();
    }

    output
}

/// Get the path to the version check cache file.
fn cache_path() -> Option<PathBuf> {
    crate::config::user_cache_dir().map(|d| d.join("dcg").join("version_check.json"))
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

/// Read a cached version check result if it is still fresh.
#[must_use]
pub fn read_cached_check() -> Option<VersionCheckResult> {
    read_cache()
}

/// Spawn a background update check to refresh the cache if needed.
///
/// This is best-effort and ignores failures. If a fresh cache already exists,
/// no thread is spawned.
pub fn spawn_update_check_if_needed() {
    if read_cache().is_some() {
        return;
    }

    let _ = thread::Builder::new()
        .name("dcg-update-check".to_string())
        .spawn(|| {
            let _ = check_for_update(false);
        });
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
#[must_use]
pub const fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

const fn prefer_dsr_metadata<'a>(dsr: Option<&'a str>, vergen: Option<&'a str>) -> Option<&'a str> {
    match dsr {
        Some(value) => Some(value),
        None => vergen,
    }
}

/// `git describe --tags --dirty` captured at compile time by `build.rs`
/// (#320).
///
/// Strict DSR snapshots use their prevalidated release tag because the
/// tracked-byte build root intentionally has no `.git` directory.
pub const GIT_DESCRIBE: Option<&str> = prefer_dsr_metadata(
    option_env!("DCG_DSR_GIT_DESCRIBE"),
    option_env!("VERGEN_GIT_DESCRIBE"),
);

/// Full commit SHA captured at compile time by `build.rs`.
pub const GIT_SHA: Option<&str> = prefer_dsr_metadata(
    option_env!("DCG_DSR_GIT_SHA"),
    option_env!("VERGEN_GIT_SHA"),
);

/// Explicit release-pipeline fallback marker (#320). Strict DSR builds emit
/// their marker only after the supplied SHA and tag have passed build-script
/// validation; legacy release builders may still export `DCG_RELEASE_BUILD=1`.
/// Usable git metadata remains authoritative, so neither marker can bless a
/// dirty or ahead-of-tag build.
const RELEASE_BUILD_MARKER: Option<&str> = prefer_dsr_metadata(
    option_env!("DCG_DSR_RELEASE_BUILD"),
    option_env!("DCG_RELEASE_BUILD"),
);

/// Where this binary came from, as far as compile-time metadata can prove
/// (#320).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildProvenance {
    /// Built from a clean checkout exactly at this version's release tag, or
    /// built by a release pipeline when git metadata was unavailable.
    /// Replacing it with the published release of the same or newer version
    /// loses nothing.
    Release,
    /// Built from a git checkout that is ahead of (or dirty relative to) the
    /// release tag for this version. Replacing it with the published release
    /// silently discards the local delta — for a guard, that can mean
    /// downgrading coverage the operator depends on.
    LocalAheadOfRelease {
        /// The compile-time `git describe --tags --dirty` output.
        describe: String,
    },
    /// No usable provenance: no git metadata was available at build time
    /// (e.g. `cargo install` from a registry tarball).
    Unknown,
}

/// Classify this binary's build provenance (#320).
#[must_use]
pub fn build_provenance() -> BuildProvenance {
    classify_provenance(GIT_DESCRIBE, RELEASE_BUILD_MARKER, current_version())
}

/// Pure classification seam for [`build_provenance`], unit-testable without
/// rebuilding under different environments.
fn classify_provenance(
    describe: Option<&str>,
    release_marker: Option<&str>,
    version: &str,
) -> BuildProvenance {
    let release_marker_enabled = release_marker.is_some_and(crate::output::env_flag_value_enabled);
    let Some(describe) = describe else {
        return if release_marker_enabled {
            BuildProvenance::Release
        } else {
            BuildProvenance::Unknown
        };
    };
    // vergen substitutes a fixed placeholder when git metadata could not be
    // gathered; treat it (and empty output) as absent metadata, where the
    // explicit release-pipeline marker may supply the missing provenance.
    if describe.is_empty() || describe == "VERGEN_IDEMPOTENT_OUTPUT" {
        return if release_marker_enabled {
            BuildProvenance::Release
        } else {
            BuildProvenance::Unknown
        };
    }
    if describe == format!("v{version}") {
        return BuildProvenance::Release;
    }
    // Anything else — `v0.11.0-7-gabc1234`, a `-dirty` suffix, or a describe
    // rooted at an older tag — is a local build whose bytes are not those of
    // this version's release tag.
    BuildProvenance::LocalAheadOfRelease {
        describe: describe.to_string(),
    }
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
        .map_err(|e| {
            VersionCheckError::NetworkError(format!("Failed to configure release list: {e}"))
        })?
        .fetch()
        .map_err(|e| VersionCheckError::NetworkError(format!("Failed to fetch releases: {e}")))?;

    let latest = select_latest_release(releases.all())
        .ok_or_else(|| VersionCheckError::ParseError("No releases found".to_string()))?;

    let latest_version = latest.version().trim_start_matches('v').to_string();
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
    let release_notes = latest.body().map(|body| truncate_release_notes(body, 500));

    let result = VersionCheckResult {
        current_version: current.to_string(),
        latest_version,
        update_available,
        release_url: release_url_for_version(latest.version()),
        release_notes,
        checked_at,
    };

    Ok(result)
}

fn select_latest_release(releases: &[Release]) -> Option<&Release> {
    let mut best_stable: Option<(&Release, semver::Version)> = None;
    let mut best_any: Option<(&Release, semver::Version)> = None;

    for release in releases {
        let version_str = release.version().trim_start_matches('v');
        let Ok(version) = semver::Version::parse(version_str) else {
            continue;
        };

        if best_any
            .as_ref()
            .is_none_or(|(_, current)| version > *current)
        {
            best_any = Some((release, version.clone()));
        }

        if version.pre.is_empty()
            && best_stable
                .as_ref()
                .is_none_or(|(_, current)| version > *current)
        {
            best_stable = Some((release, version));
        }
    }

    best_stable
        .map(|(release, _)| release)
        .or_else(|| best_any.map(|(release, _)| release))
        .or_else(|| releases.first())
}

fn truncate_release_notes(body: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if max_chars <= 3 {
        if body.chars().count() <= max_chars {
            return body.to_string();
        }
        return ".".repeat(max_chars);
    }

    let mut chars = body.chars();
    for _ in 0..max_chars {
        if chars.next().is_none() {
            return body.to_string();
        }
    }

    if chars.next().is_none() {
        return body.to_string();
    }

    let visible_limit = max_chars.saturating_sub(3);
    let truncated: String = body.chars().take(visible_limit).collect();
    format!("{truncated}...")
}

fn release_url_for_version(version: &str) -> String {
    let bare_version = version.trim().trim_start_matches('v');
    if bare_version.is_empty() {
        format!("https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest")
    } else {
        format!("https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/tag/v{bare_version}")
    }
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
        writeln!(
            output,
            "\x1b[1mCurrent version:\x1b[0m {}",
            result.current_version
        )
        .ok();
        writeln!(
            output,
            "\x1b[1mLatest version:\x1b[0m  {}",
            result.latest_version
        )
        .ok();
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

/// Spawn a background thread to check for updates.
///
/// This function returns immediately. The check runs in the background and
/// caches the result for future calls to [`get_update_notice`].
///
/// This is fire-and-forget: errors are silently ignored since this is
/// a non-critical enhancement.
pub fn spawn_background_check() {
    std::thread::spawn(|| {
        // Silent check - ignore all errors
        let _ = check_for_update(false);
    });
}

/// Get an update notice from the cache without blocking.
///
/// Returns `Some(notice_string)` if an update is available and cached,
/// `None` if no update is available, the cache is expired, or any error occurs.
///
/// This function never blocks on network I/O - it only reads from the cache.
#[must_use]
pub fn get_update_notice(use_color: bool) -> Option<String> {
    // Only read from cache - never fetch
    let cached = read_cache()?;

    if !cached.update_available {
        return None;
    }

    // Format a subtle notice
    let notice = if use_color {
        format!(
            "\x1b[33m!\x1b[0m A new version of dcg is available: {} -> {}\n  Run '\x1b[1mdcg update\x1b[0m' to upgrade",
            cached.current_version, cached.latest_version
        )
    } else {
        format!(
            "! A new version of dcg is available: {} -> {}\n  Run 'dcg update' to upgrade",
            cached.current_version, cached.latest_version
        )
    };

    Some(notice)
}

/// Check if update checking is enabled via environment variable.
///
/// Returns `false` if `DCG_NO_UPDATE_CHECK` is enabled. Documented falsey
/// values such as `0`, `false`, `no`, and `off` do not disable update checks.
#[must_use]
pub fn is_update_check_enabled() -> bool {
    is_update_check_enabled_with(|key| std::env::var(key).ok())
}

fn is_update_check_enabled_with<F>(mut get_env: F) -> bool
where
    F: FnMut(&str) -> Option<String>,
{
    get_env("DCG_NO_UPDATE_CHECK").is_none_or(|value| !disable_env_flag_enabled(&value))
}

fn disable_env_flag_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "n" | "off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsr_release_identity_precedes_git_discovery_fallbacks() {
        assert_eq!(
            prefer_dsr_metadata(Some("certified"), Some("discovered")),
            Some("certified")
        );
        assert_eq!(
            prefer_dsr_metadata(None, Some("discovered")),
            Some("discovered")
        );
        assert_eq!(prefer_dsr_metadata(None, None), None);
    }

    /// #320/#344: a release marker is fallback evidence for builds where git
    /// metadata is unavailable, not permission to contradict explicit git
    /// state.
    #[test]
    fn release_marker_only_fills_unusable_git_metadata() {
        for release_marker in ["1", "true", "YES", "on", " enabled "] {
            for describe in [None, Some(""), Some("VERGEN_IDEMPOTENT_OUTPUT")] {
                assert_eq!(
                    classify_provenance(describe, Some(release_marker), "0.11.0"),
                    BuildProvenance::Release,
                    "{release_marker:?}, {describe:?}"
                );
            }
        }

        for describe in ["v0.11.0-7-gabc1234", "v0.11.0-dirty", "v0.10.0"] {
            assert_eq!(
                classify_provenance(Some(describe), Some("1"), "0.11.0"),
                BuildProvenance::LocalAheadOfRelease {
                    describe: describe.to_string()
                },
                "release marker must not bless explicit git state: {describe}"
            );
        }
    }

    /// #320/#344: exact matching tag metadata is independently sufficient,
    /// while documented falsey marker values cannot manufacture provenance.
    #[test]
    fn classify_provenance_covers_release_local_and_unknown() {
        for release_marker in [None, Some("1"), Some("true"), Some("yes"), Some("on")] {
            assert_eq!(
                classify_provenance(Some("v0.11.0"), release_marker, "0.11.0"),
                BuildProvenance::Release,
                "{release_marker:?}"
            );
        }

        for release_marker in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("NO"),
            Some("n"),
            Some("Off"),
        ] {
            assert_eq!(
                classify_provenance(None, release_marker, "0.11.0"),
                BuildProvenance::Unknown,
                "{release_marker:?}"
            );
        }

        for describe in ["v0.11.0-7-gabc1234", "v0.11.0-dirty", "v0.10.0-40-gdeadbee"] {
            assert_eq!(
                classify_provenance(Some(describe), None, "0.11.0"),
                BuildProvenance::LocalAheadOfRelease {
                    describe: describe.to_string()
                },
                "{describe}"
            );
        }

        for describe in [None, Some("VERGEN_IDEMPOTENT_OUTPUT"), Some("")] {
            assert_eq!(
                classify_provenance(describe, None, "0.11.0"),
                BuildProvenance::Unknown,
                "{describe:?}"
            );
        }
    }

    /// Exercise publication and restore-on-failure on both platforms. The CLI
    /// integration tests also qualify and replace a mapped, running executable.
    #[test]
    fn publish_staged_executable_replaces_and_restores() {
        let dir = tempfile::tempdir().expect("tempdir");
        let current = dir.path().join("dcg.exe");
        let backup = dir.path().join("backup.exe");
        let staged = dir.path().join("stage.exe");
        std::fs::write(&current, b"OLD").unwrap();
        std::fs::write(&backup, b"NEW").unwrap();

        copy_to_new_file(&backup, &staged).unwrap();
        publish_staged_executable(&current, &staged).expect("swap should succeed");
        assert_eq!(std::fs::read(&current).unwrap(), b"NEW");
        assert_eq!(std::fs::read(&backup).unwrap(), b"NEW");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);

        // Failure (missing backup source): current must be restored, not lost.
        std::fs::write(&current, b"OLD2").unwrap();
        let missing = dir.path().join("does-not-exist.exe");
        let err = publish_staged_executable(&current, &missing);
        assert!(err.is_err(), "missing backup source must error");
        assert_eq!(
            std::fs::read(&current).unwrap(),
            b"OLD2",
            "current executable must be restored on publication failure"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn swap_running_executable_publication_failure_preserves_source_and_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("occupied");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("incumbent"), b"OLD").unwrap();
        let backup = dir.path().join("backup");
        std::fs::write(&backup, b"NEW").unwrap();

        assert!(swap_running_executable(&target, &backup, "0.15.0").is_err());
        assert_eq!(std::fs::read(target.join("incumbent")).unwrap(), b"OLD");
        assert_eq!(std::fs::read(&backup).unwrap(), b"NEW");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_qualifies_the_completed_stage_before_publishing() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("dcg");
        let backup = dir.path().join("backup");
        let payload = b"#!/bin/sh\ncase \"$0\" in */.dcg-rollback-*.exe) ;; *) exit 77;; esac\nprintf 'dcg v0.15.0\\n' >&2\n";
        std::fs::write(&current, b"incumbent").unwrap();
        std::fs::write(&backup, payload).unwrap();
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o751)).unwrap();

        swap_running_executable(&current, &backup, "0.15.0").unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), payload);
        assert_eq!(std::fs::read(&backup).unwrap(), payload);
        assert_eq!(
            std::fs::metadata(&current).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_rejects_unqualified_stages_without_touching_incumbent_or_source() {
        use std::os::unix::fs::PermissionsExt;

        for payload in [
            "",
            "not an executable",
            "#!/bin/sh\nprintf '0.14.0\\n'\n",
            "#!/bin/sh\nprintf '0.15.0\\n'\nexit 23\n",
            "#!/bin/sh\nprintf '0.15.0\\n'\nprintf '0.14.0\\n' >&2\n",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let current = dir.path().join("dcg");
            let backup = dir.path().join("backup");
            std::fs::write(&current, b"incumbent").unwrap();
            std::fs::write(&backup, payload).unwrap();
            std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o751)).unwrap();

            assert!(swap_running_executable(&current, &backup, "0.15.0").is_err());
            assert_eq!(std::fs::read(&current).unwrap(), b"incumbent");
            assert_eq!(std::fs::read(&backup).unwrap(), payload.as_bytes());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        }
    }

    #[test]
    fn exclusive_backup_copy_never_truncates_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        std::fs::write(&source, b"NEW").unwrap();
        std::fs::write(&target, b"RECOVERY").unwrap();
        let error = copy_to_new_file(&source, &target).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"RECOVERY");
    }

    #[test]
    fn creating_a_backup_preserves_bytes_metadata_and_prior_recovery_points() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("dcg");
        std::fs::write(&source, b"installed binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o751)).unwrap();
        }
        let backups = dir.path().join("backups");
        let mut snapshots = Vec::new();
        for _ in 0..MAX_BACKUPS + 2 {
            snapshots.push(create_backup_in(&backups, &source, "0.15.0").unwrap());
        }
        assert_eq!(
            std::fs::read_dir(&backups).unwrap().count(),
            snapshots.len() * 2
        );
        for snapshot in snapshots {
            assert_eq!(std::fs::read(&snapshot).unwrap(), b"installed binary");
            let metadata_path = snapshot.with_file_name(format!(
                "{}.json",
                snapshot.file_name().unwrap().to_str().unwrap()
            ));
            let metadata: BackupEntry =
                serde_json::from_slice(&std::fs::read(metadata_path).unwrap()).unwrap();
            assert_eq!(metadata.version, "0.15.0");
            assert_eq!(metadata.original_path, source);
            assert_eq!(
                backup_artifact_name(&metadata),
                snapshot.file_name().unwrap().to_str().unwrap()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(snapshot).unwrap().permissions().mode() & 0o777,
                    0o751
                );
            }
        }
    }

    #[test]
    fn failed_backup_creation_leaves_the_installation_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("dcg");
        let blocked = dir.path().join("not-a-directory");
        std::fs::write(&source, b"installed binary").unwrap();
        std::fs::write(&blocked, b"existing data").unwrap();
        assert!(create_backup_in(&blocked, &source, "0.15.0").is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"installed binary");
        assert_eq!(std::fs::read(&blocked).unwrap(), b"existing data");
        assert!(create_backup_in(&dir.path().join("unused"), &source, "../bad").is_err());
        assert!(!dir.path().join("unused").exists());
    }

    #[test]
    fn test_current_version() {
        let version = current_version();
        assert!(!version.is_empty());
        // Should be valid semver
        assert!(semver::Version::parse(version).is_ok());
    }

    #[test]
    fn test_truncate_release_notes_utf8_safe() {
        let body = "Release ✅ notes with emoji 🚀 and accents café";
        let truncated = truncate_release_notes(body, 10);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.chars().count(), 10);

        let untrimmed = truncate_release_notes(body, 200);
        assert_eq!(untrimmed, body);

        let tiny = truncate_release_notes(body, 2);
        assert_eq!(tiny, "..");
    }

    fn make_release(version: &str) -> Release {
        let mut builder = Release::builder();
        builder
            .name(version)
            // self_update 1.0 validates custom Release values as bare SemVer;
            // forge adapters preserve the raw tag only in the display name.
            .version(version.trim_start_matches('v'))
            .date("2026-01-01T00:00:00Z");
        builder.build().expect("valid test release")
    }

    #[test]
    fn test_select_latest_release_prefers_stable() {
        let releases = vec![
            make_release("2.0.0-beta.1"),
            make_release("1.9.0"),
            make_release("2.0.0-rc.1"),
        ];

        let selected = select_latest_release(&releases).expect("select");
        assert_eq!(selected.version(), "1.9.0");
    }

    #[test]
    fn test_select_latest_release_highest_semver() {
        let releases = vec![
            make_release("1.0.0"),
            make_release("2.0.0"),
            make_release("1.5.0"),
        ];

        let selected = select_latest_release(&releases).expect("select");
        assert_eq!(selected.version(), "2.0.0");
    }

    #[test]
    fn test_select_latest_release_with_backend_normalized_v_tags() {
        let releases = vec![
            make_release("v1.0.0"),
            make_release("v2.1.0"),
            make_release("v2.0.5"),
        ];

        let selected = select_latest_release(&releases).expect("select");
        assert_eq!(selected.version(), "2.1.0");
        assert_eq!(selected.name(), "v2.1.0");
    }

    #[test]
    fn test_release_url_for_version_uses_canonical_v_tag() {
        assert_eq!(
            release_url_for_version("v2.1.0"),
            "https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v2.1.0"
        );
        assert_eq!(
            release_url_for_version("2.1.0"),
            "https://github.com/Dicklesworthstone/destructive_command_guard/releases/tag/v2.1.0"
        );
    }

    #[test]
    fn test_release_url_for_version_empty_uses_latest() {
        assert_eq!(
            release_url_for_version(""),
            "https://github.com/Dicklesworthstone/destructive_command_guard/releases/latest"
        );
    }

    #[test]
    fn test_generate_unique_backup_name_avoids_collision() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path();
        let timestamp = 1_737_200_000_u64;
        let base = "dcg-0.2.12-1737200000";

        std::fs::write(dir.join(base), b"binary").expect("seed backup artifact");
        std::fs::write(dir.join(format!("{base}.json")), b"{}").expect("seed backup metadata");

        let generated = generate_unique_backup_name(dir, "0.2.12", timestamp);
        assert_ne!(generated, base);
        assert!(generated.starts_with(&format!("{base}-")));
    }

    #[test]
    fn test_backup_artifact_name_prefers_metadata() {
        let with_name = BackupEntry {
            version: "0.2.12".to_string(),
            created_at: 1_737_200_000,
            artifact_name: Some("dcg-0.2.12-1737200000-123456789".to_string()),
            original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
        };
        assert_eq!(
            backup_artifact_name(&with_name),
            "dcg-0.2.12-1737200000-123456789"
        );

        let legacy = BackupEntry {
            version: "0.2.11".to_string(),
            created_at: 1_737_100_000,
            artifact_name: None,
            original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
        };
        assert_eq!(backup_artifact_name(&legacy), "dcg-0.2.11-1737100000");
    }

    #[test]
    fn test_backup_artifact_name_rejects_path_like_metadata() {
        let fallback = "dcg-0.2.12-1737200000";
        for artifact_name in [
            "",
            ".",
            "..",
            "../outside",
            "/tmp/dcg-backup",
            "nested/dcg-backup",
            r"nested\dcg-backup",
            "C:dcg-backup",
        ] {
            let entry = BackupEntry {
                version: "0.2.12".to_string(),
                created_at: 1_737_200_000,
                artifact_name: Some(artifact_name.to_string()),
                original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
            };
            assert_eq!(backup_artifact_name(&entry), fallback);
        }
    }

    fn backup_entry(version: &str, created_at: u64) -> BackupEntry {
        BackupEntry {
            version: version.to_string(),
            created_at,
            artifact_name: None,
            original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
        }
    }

    #[test]
    fn test_backup_names_to_prune_preserves_selected_rollback_target() {
        let backups = vec![
            backup_entry("0.2.13", 500),
            backup_entry("0.2.12", 400),
            backup_entry("0.2.11", 300),
            backup_entry("0.2.10", 200),
        ];
        let rollback_target = backup_artifact_name(&backups[3]);

        let normal_prune = backup_names_to_prune(&backups, &[]);
        assert_eq!(normal_prune, vec![rollback_target.clone()]);

        let rollback_prune = backup_names_to_prune(&backups, &[&rollback_target]);
        assert_eq!(rollback_prune, vec!["dcg-0.2.11-300"]);
        assert!(!rollback_prune.contains(&rollback_target));
    }

    #[test]
    fn test_backup_names_to_prune_still_removes_non_preserved_overflow() {
        let backups = vec![
            backup_entry("0.2.14", 600),
            backup_entry("0.2.13", 500),
            backup_entry("0.2.12", 400),
            backup_entry("0.2.11", 300),
            backup_entry("0.2.10", 200),
        ];
        let rollback_target = backup_artifact_name(&backups[4]);

        let rollback_prune = backup_names_to_prune(&backups, &[&rollback_target]);
        assert_eq!(rollback_prune, vec!["dcg-0.2.12-400", "dcg-0.2.11-300"]);
        assert!(!rollback_prune.contains(&rollback_target));
    }

    #[test]
    fn test_backup_names_to_prune_keeps_cap_when_preserved_target_is_recent() {
        let backups = vec![
            backup_entry("0.2.13", 500),
            backup_entry("0.2.12", 400),
            backup_entry("0.2.11", 300),
            backup_entry("0.2.10", 200),
        ];
        let rollback_target = backup_artifact_name(&backups[1]);

        let rollback_prune = backup_names_to_prune(&backups, &[&rollback_target]);
        assert_eq!(rollback_prune, vec!["dcg-0.2.10-200".to_string()]);
        assert!(!rollback_prune.contains(&rollback_target));
    }

    #[test]
    fn backup_retention_protects_new_recovery_point_when_timestamps_tie() {
        let backups = vec![
            backup_entry("0.2.13", 500),
            backup_entry("0.2.12", 500),
            backup_entry("0.2.11", 500),
            backup_entry("0.2.10", 500),
        ];
        let recovery = backup_artifact_name(&backups[3]);
        let restored = backup_artifact_name(&backups[2]);
        assert_eq!(
            backup_names_to_prune(&backups, &[&recovery, &restored]),
            vec!["dcg-0.2.12-500"]
        );
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

    #[test]
    fn test_is_update_check_enabled_default() {
        let env_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        assert!(is_update_check_enabled_with(|key| {
            env_map.get(key).map(|v| (*v).to_string())
        }));
    }

    #[test]
    fn test_is_update_check_disabled_by_env() {
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", "1")]);
        assert!(!is_update_check_enabled_with(|key| {
            env_map.get(key).map(|v| (*v).to_string())
        }));
    }

    #[test]
    fn test_get_update_notice_no_cache() {
        // With no cache file, should return None
        // This is safe because get_update_notice only reads cache
        // and doesn't create it
        let notice = get_update_notice(false);
        // May or may not be Some depending on actual cache state
        // but should not panic
        let _ = notice;
    }

    #[test]
    fn test_backup_entry_serialization() {
        let entry = BackupEntry {
            version: "0.2.12".to_string(),
            created_at: 1_737_200_000,
            artifact_name: Some("dcg-0.2.12-1737200000".to_string()),
            original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: BackupEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, entry.version);
        assert_eq!(parsed.created_at, entry.created_at);
        assert_eq!(parsed.artifact_name, entry.artifact_name);
        assert_eq!(parsed.original_path, entry.original_path);
    }

    #[test]
    fn test_format_backup_list_empty() {
        let output = format_backup_list(&[], false);
        assert!(output.contains("No backup versions available"));
    }

    #[test]
    fn test_format_backup_list_with_entries() {
        let entries = vec![
            BackupEntry {
                version: "0.2.12".to_string(),
                created_at: 1_737_200_000,
                artifact_name: None,
                original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
            },
            BackupEntry {
                version: "0.2.11".to_string(),
                created_at: 1_737_100_000,
                artifact_name: None,
                original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
            },
        ];

        let output = format_backup_list(&entries, false);
        assert!(output.contains("v0.2.12"));
        assert!(output.contains("v0.2.11"));
        assert!(output.contains("most recent"));
    }

    #[test]
    fn test_backup_dir_exists() {
        // backup_dir should return Some path
        let dir = backup_dir();
        assert!(dir.is_some());
        // The path should contain "dcg" and "backups"
        let path = dir.unwrap();
        assert!(path.to_string_lossy().contains("dcg"));
        assert!(path.to_string_lossy().contains("backups"));
    }

    #[test]
    fn test_list_backups_no_dir() {
        // list_backups should return empty vec if dir doesn't exist
        // (it will exist for most systems, but the function handles non-existence gracefully)
        let result = list_backups();
        // Should not error, just return empty or existing backups
        assert!(result.is_ok());
    }

    // =========================================================================
    // Version Comparison Tests
    // =========================================================================

    #[test]
    fn test_version_comparison_newer_available() {
        // Test semver comparison: 2.0.0 > 1.9.0
        let current = semver::Version::parse("1.9.0").unwrap();
        let latest = semver::Version::parse("2.0.0").unwrap();

        assert!(latest > current, "2.0.0 should be newer than 1.9.0");
    }

    #[test]
    fn test_version_comparison_already_current() {
        // Test semver comparison when versions are equal
        let current = semver::Version::parse("2.0.0").unwrap();
        let latest = semver::Version::parse("2.0.0").unwrap();

        assert!(latest <= current, "Same version should not need update");
    }

    #[test]
    fn test_version_comparison_patch_update() {
        // Test patch version increment (1.9.0 -> 1.9.1)
        let current = semver::Version::parse("1.9.0").unwrap();
        let latest = semver::Version::parse("1.9.1").unwrap();

        assert!(latest > current, "1.9.1 should be newer than 1.9.0");
    }

    #[test]
    fn test_version_comparison_minor_update() {
        // Test minor version increment (1.9.0 -> 1.10.0)
        let current = semver::Version::parse("1.9.0").unwrap();
        let latest = semver::Version::parse("1.10.0").unwrap();

        assert!(latest > current, "1.10.0 should be newer than 1.9.0");
    }

    #[test]
    fn test_version_comparison_major_update() {
        // Test major version increment (1.9.0 -> 2.0.0)
        let current = semver::Version::parse("1.9.0").unwrap();
        let latest = semver::Version::parse("2.0.0").unwrap();

        assert!(latest > current, "2.0.0 should be newer than 1.9.0");
    }

    #[test]
    fn test_version_comparison_prerelease_vs_stable() {
        // Prereleases are less than their release (2.0.0-beta.1 < 2.0.0)
        let prerelease = semver::Version::parse("2.0.0-beta.1").unwrap();
        let stable = semver::Version::parse("2.0.0").unwrap();

        assert!(
            stable > prerelease,
            "Stable 2.0.0 should be greater than 2.0.0-beta.1"
        );
    }

    #[test]
    fn test_version_comparison_prerelease_ordering() {
        // Test prerelease ordering: alpha < beta < rc
        let alpha = semver::Version::parse("2.0.0-alpha.1").unwrap();
        let beta = semver::Version::parse("2.0.0-beta.1").unwrap();
        let rc = semver::Version::parse("2.0.0-rc.1").unwrap();

        assert!(beta > alpha, "beta should be greater than alpha");
        assert!(rc > beta, "rc should be greater than beta");
    }

    #[test]
    fn test_version_comparison_with_v_prefix() {
        // Test that 'v' prefix is properly stripped
        let version_str = "v1.2.3";
        let clean = version_str.trim_start_matches('v');
        let parsed = semver::Version::parse(clean).unwrap();

        assert_eq!(parsed.major, 1);
        assert_eq!(parsed.minor, 2);
        assert_eq!(parsed.patch, 3);
    }

    #[test]
    fn test_version_comparison_downgrade_detection() {
        // Test that downgrade is detected (latest < current)
        let current = semver::Version::parse("2.0.0").unwrap();
        let latest = semver::Version::parse("1.9.0").unwrap();

        assert!(
            latest <= current,
            "1.9.0 should not trigger update when current is 2.0.0"
        );
    }

    // =========================================================================
    // Error Handling Tests
    // =========================================================================

    #[test]
    fn test_version_check_error_display_network() {
        let err = VersionCheckError::NetworkError("Connection refused".to_string());
        let display = format!("{err}");
        assert!(display.contains("Network error"));
        assert!(display.contains("Connection refused"));
    }

    #[test]
    fn test_version_check_error_display_parse() {
        let err = VersionCheckError::ParseError("Invalid JSON".to_string());
        let display = format!("{err}");
        assert!(display.contains("Parse error"));
        assert!(display.contains("Invalid JSON"));
    }

    #[test]
    fn test_version_check_error_display_cache() {
        let err = VersionCheckError::CacheError("Permission denied".to_string());
        let display = format!("{err}");
        assert!(display.contains("Cache error"));
        assert!(display.contains("Permission denied"));
    }

    #[test]
    fn test_version_check_error_display_update() {
        let err = VersionCheckError::UpdateError("Download failed".to_string());
        let display = format!("{err}");
        assert!(display.contains("Update error"));
        assert!(display.contains("Download failed"));
    }

    #[test]
    fn test_version_check_error_display_backup() {
        let err = VersionCheckError::BackupError("Disk full".to_string());
        let display = format!("{err}");
        assert!(display.contains("Backup error"));
        assert!(display.contains("Disk full"));
    }

    #[test]
    fn test_version_check_error_display_no_update() {
        let err = VersionCheckError::NoUpdateAvailable;
        let display = format!("{err}");
        assert!(display.contains("No update available"));
    }

    // =========================================================================
    // Update Notice Tests
    // =========================================================================

    #[test]
    fn test_format_check_result_with_release_notes() {
        let result = VersionCheckResult {
            current_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            update_available: true,
            release_url: "https://example.com".to_string(),
            release_notes: Some("Bug fixes and improvements".to_string()),
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        // The format function should not crash with release notes
        let output = format_check_result(&result, false);
        assert!(output.contains("2.0.0"));
    }

    #[test]
    fn test_format_check_result_json_output() {
        let result = VersionCheckResult {
            current_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            update_available: true,
            release_url: "https://example.com".to_string(),
            release_notes: None,
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        let json = format_check_result_json(&result).unwrap();
        assert!(json.contains("\"current_version\""));
        assert!(json.contains("\"latest_version\""));
        assert!(json.contains("\"update_available\""));
    }

    #[test]
    fn test_format_check_result_with_color() {
        let result = VersionCheckResult {
            current_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            update_available: true,
            release_url: "https://example.com".to_string(),
            release_notes: None,
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        let output = format_check_result(&result, true);
        // Should contain ANSI escape codes for color
        assert!(output.contains("\x1b["));
    }

    #[test]
    fn test_format_check_result_no_color() {
        let result = VersionCheckResult {
            current_version: "1.0.0".to_string(),
            latest_version: "2.0.0".to_string(),
            update_available: true,
            release_url: "https://example.com".to_string(),
            release_notes: None,
            checked_at: "2026-01-17T00:00:00Z".to_string(),
        };

        let output = format_check_result(&result, false);
        // Should NOT contain ANSI escape codes
        assert!(!output.contains("\x1b["));
    }

    // =========================================================================
    // Backup List Tests
    // =========================================================================

    #[test]
    fn test_backup_list_sorting_by_date() {
        // Test that backups are sorted newest first
        let mut entries = [
            BackupEntry {
                version: "0.2.10".to_string(),
                created_at: 1_737_000_000, // oldest
                artifact_name: None,
                original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
            },
            BackupEntry {
                version: "0.2.12".to_string(),
                created_at: 1_737_200_000, // newest
                artifact_name: None,
                original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
            },
            BackupEntry {
                version: "0.2.11".to_string(),
                created_at: 1_737_100_000, // middle
                artifact_name: None,
                original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
            },
        ];

        // Sort as list_backups does
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));

        assert_eq!(entries[0].version, "0.2.12");
        assert_eq!(entries[1].version, "0.2.11");
        assert_eq!(entries[2].version, "0.2.10");
    }

    #[test]
    fn test_format_backup_list_with_color() {
        let entries = vec![BackupEntry {
            version: "0.2.12".to_string(),
            created_at: 1_737_200_000,
            artifact_name: None,
            original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
        }];

        let output = format_backup_list(&entries, true);
        // Should contain ANSI escape codes
        assert!(output.contains("\x1b["));
        assert!(output.contains("v0.2.12"));
    }

    #[test]
    fn test_format_backup_list_empty_with_color() {
        let output = format_backup_list(&[], true);
        // Should contain ANSI escape codes for colored message
        assert!(output.contains("\x1b["));
        assert!(output.contains("No backup versions available"));
    }

    #[test]
    fn backup_list_and_update_notice_emit_no_escapes_when_color_disabled() {
        // win-vt-ansi-enable (.1.6): with color disabled (NO_COLOR / non-TTY ->
        // use_color=false), the hand-rolled ANSI emitters must produce ZERO
        // escape sequences on every platform.
        let entries = vec![BackupEntry {
            version: "0.2.12".to_string(),
            created_at: 1_737_200_000,
            artifact_name: None,
            original_path: std::path::PathBuf::from("/usr/local/bin/dcg"),
        }];
        let populated = format_backup_list(&entries, false);
        assert!(
            !populated.contains('\u{1b}'),
            "backup list leaked an escape: {populated:?}"
        );
        assert!(populated.contains("v0.2.12"));

        let empty = format_backup_list(&[], false);
        assert!(
            !empty.contains('\u{1b}'),
            "empty backup list leaked an escape"
        );

        let notice = get_update_notice(false);
        if let Some(notice) = notice {
            assert!(
                !notice.contains('\u{1b}'),
                "update notice leaked an escape: {notice:?}"
            );
        }
    }

    // =========================================================================
    // Cache Duration Tests
    // =========================================================================

    #[test]
    fn test_cache_duration_is_24_hours() {
        assert_eq!(CACHE_DURATION.as_secs(), 24 * 60 * 60);
    }

    #[test]
    fn test_max_backups_limit() {
        assert_eq!(MAX_BACKUPS, 3);
    }

    // =========================================================================
    // Environment Variable Tests
    // =========================================================================

    #[test]
    fn test_is_update_check_enabled_empty_value() {
        // Empty string should NOT disable update check
        let env_map: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", "")]);
        assert!(is_update_check_enabled_with(|key| {
            env_map.get(key).map(|v| (*v).to_string())
        }));
    }

    #[test]
    fn test_is_update_check_disabled_various_values() {
        for val in &["1", "true", "yes", "anything"] {
            let env_map: std::collections::HashMap<&str, &str> =
                std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", *val)]);
            assert!(
                !is_update_check_enabled_with(|key| { env_map.get(key).map(|v| (*v).to_string()) }),
                "DCG_NO_UPDATE_CHECK={val} should disable update check"
            );
        }
    }

    #[test]
    fn test_is_update_check_falsey_values_do_not_disable() {
        for val in &["0", "false", "no", "n", "off", " FALSE "] {
            let env_map: std::collections::HashMap<&str, &str> =
                std::collections::HashMap::from([("DCG_NO_UPDATE_CHECK", *val)]);
            assert!(
                is_update_check_enabled_with(|key| { env_map.get(key).map(|v| (*v).to_string()) }),
                "DCG_NO_UPDATE_CHECK={val} should not disable update check"
            );
        }
    }
}

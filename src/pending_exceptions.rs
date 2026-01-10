//! Pending exception store for allow-once short-code flow.
//!
//! This module provides a small JSONL-backed record store that is:
//! - Append-friendly for concurrent hooks
//! - Deterministic in serialization
//! - Fail-open on parse errors (corrupt lines are skipped)

use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::config::resolve_config_path_value;
use crate::logging::{RedactionConfig, redact_command};

/// Environment override for pending exceptions file path.
pub const ENV_PENDING_EXCEPTIONS_PATH: &str = "DCG_PENDING_EXCEPTIONS_PATH";

const PENDING_EXCEPTIONS_FILE: &str = "pending_exceptions.jsonl";
const SCHEMA_VERSION: u32 = 1;
const EXPIRY_HOURS: i64 = 24;

/// A stored pending exception record (JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingExceptionRecord {
    pub schema_version: u32,
    pub short_code: String,
    pub full_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub cwd: String,
    pub command_raw: String,
    pub command_redacted: String,
    pub reason: String,
    pub single_use: bool,
    pub consumed_at: Option<String>,
}

impl PendingExceptionRecord {
    #[must_use]
    pub fn new(
        timestamp: DateTime<Utc>,
        cwd: &str,
        command_raw: &str,
        reason: &str,
        redaction: &RedactionConfig,
        single_use: bool,
    ) -> Self {
        let created_at = format_timestamp(timestamp);
        let expires_at = format_timestamp(timestamp + Duration::hours(EXPIRY_HOURS));
        let full_hash = compute_full_hash(&created_at, cwd, command_raw);
        let short_code = short_code_from_hash(&full_hash);
        let command_redacted = redact_for_pending(command_raw, redaction);

        Self {
            schema_version: SCHEMA_VERSION,
            short_code,
            full_hash,
            created_at,
            expires_at,
            cwd: cwd.to_string(),
            command_raw: command_raw.to_string(),
            command_redacted,
            reason: reason.to_string(),
            single_use,
            consumed_at: None,
        }
    }

    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }
}

/// Maintenance stats produced while loading/pruning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PendingMaintenance {
    pub pruned_expired: usize,
    pub pruned_consumed: usize,
    pub parse_errors: usize,
}

impl PendingMaintenance {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pruned_expired == 0 && self.pruned_consumed == 0 && self.parse_errors == 0
    }
}

/// Pending exception store wrapper.
#[derive(Debug, Clone)]
pub struct PendingExceptionStore {
    path: PathBuf,
}

impl PendingExceptionStore {
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resolve the default path (env override or ~/.config/dcg/..).
    #[must_use]
    pub fn default_path(cwd: Option<&Path>) -> PathBuf {
        if let Ok(value) = env::var(ENV_PENDING_EXCEPTIONS_PATH) {
            if let Some(path) = resolve_config_path_value(&value, cwd) {
                return path;
            }
        }

        let base = dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"));
        base.join("dcg").join(PENDING_EXCEPTIONS_FILE)
    }

    /// Record a blocked command in the pending exceptions store.
    ///
    /// Returns the created record plus maintenance stats (expired/consumed prunes).
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn record_block(
        &self,
        command: &str,
        cwd: &str,
        reason: &str,
        redaction: &RedactionConfig,
        single_use: bool,
    ) -> io::Result<(PendingExceptionRecord, PendingMaintenance)> {
        let now = Utc::now();
        let record = PendingExceptionRecord::new(now, cwd, command, reason, redaction, single_use);

        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_active_from_file(&mut file, now);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_records(&mut file, &active)?;
        }

        append_record(&mut file, &record)?;

        Ok((record, maintenance))
    }

    /// Load active records and prune expired/consumed entries from disk.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn load_active(
        &self,
        now: DateTime<Utc>,
    ) -> io::Result<(Vec<PendingExceptionRecord>, PendingMaintenance)> {
        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_active_from_file(&mut file, now);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_records(&mut file, &active)?;
        }

        Ok((active, maintenance))
    }

    /// Load active records matching a short code.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn lookup_by_code(
        &self,
        code: &str,
        now: DateTime<Utc>,
    ) -> io::Result<(Vec<PendingExceptionRecord>, PendingMaintenance)> {
        let (active, maintenance) = self.load_active(now)?;
        let matches = active
            .into_iter()
            .filter(|record| record.short_code == code)
            .collect();
        Ok((matches, maintenance))
    }
}

/// Write a maintenance log entry (optional).
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_maintenance(
    log_file: &str,
    maintenance: PendingMaintenance,
    context: &str,
) -> io::Result<()> {
    if maintenance.is_empty() {
        return Ok(());
    }

    let path = if log_file.starts_with("~/") {
        std::env::var_os("HOME").map_or_else(
            || PathBuf::from(log_file),
            |home| PathBuf::from(format!("{}{}", home.to_string_lossy(), &log_file[1..])),
        )
    } else {
        PathBuf::from(log_file)
    };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let timestamp = format_timestamp(Utc::now());
    writeln!(
        file,
        "[{timestamp}] [pending-exceptions] {context}: pruned_expired={}, pruned_consumed={}, parse_errors={}",
        maintenance.pruned_expired, maintenance.pruned_consumed, maintenance.parse_errors
    )?;
    Ok(())
}

fn open_locked(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    file.lock_exclusive()?;
    Ok(file)
}

fn load_active_from_file(
    file: &mut File,
    now: DateTime<Utc>,
) -> (Vec<PendingExceptionRecord>, PendingMaintenance) {
    let mut maintenance = PendingMaintenance::default();
    let mut active: Vec<PendingExceptionRecord> = Vec::new();

    if file.seek(SeekFrom::Start(0)).is_err() {
        maintenance.parse_errors += 1;
        return (active, maintenance);
    }
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let Ok(line) = line else {
            maintenance.parse_errors += 1;
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let Ok(record) = serde_json::from_str::<PendingExceptionRecord>(trimmed) else {
            maintenance.parse_errors += 1;
            continue;
        };

        if record.is_consumed() {
            maintenance.pruned_consumed += 1;
            continue;
        }

        if is_expired(&record.expires_at, now) {
            maintenance.pruned_expired += 1;
            continue;
        }

        active.push(record);
    }

    (active, maintenance)
}

fn rewrite_records(file: &mut File, records: &[PendingExceptionRecord]) -> io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    for record in records {
        let line = serde_json::to_string(record).map_err(io::Error::other)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
    }
    file.sync_data()?;
    Ok(())
}

fn append_record(file: &mut File, record: &PendingExceptionRecord) -> io::Result<()> {
    file.seek(SeekFrom::End(0))?;
    let line = serde_json::to_string(record).map_err(io::Error::other)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}

fn is_expired(expires_at: &str, now: DateTime<Utc>) -> bool {
    if let Ok(dt) = DateTime::parse_from_rfc3339(expires_at) {
        return dt.with_timezone(&Utc) < now;
    }
    false
}

fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn compute_full_hash(timestamp: &str, cwd: &str, command_raw: &str) -> String {
    let input = format!("{timestamp} | {cwd} | {command_raw}");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn short_code_from_hash(full_hash: &str) -> String {
    if full_hash.len() <= 4 {
        return full_hash.to_string();
    }
    full_hash[full_hash.len() - 4..].to_string()
}

fn redact_for_pending(command: &str, redaction: &RedactionConfig) -> String {
    let mut effective = redaction.clone();
    if !effective.enabled {
        effective.enabled = true;
    }
    redact_command(command, &effective)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_store() -> (PendingExceptionStore, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("pending.jsonl");
        (PendingExceptionStore::new(path), dir)
    }

    fn redaction_config() -> RedactionConfig {
        RedactionConfig {
            enabled: true,
            mode: crate::logging::RedactionMode::Arguments,
            max_argument_len: 8,
        }
    }

    #[test]
    fn test_short_code_deterministic() {
        let timestamp = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let record = PendingExceptionRecord::new(
            timestamp,
            "/repo",
            "git reset --hard HEAD",
            "blocked",
            &redaction_config(),
            false,
        );
        assert_eq!(record.short_code.len(), 4);
        assert_eq!(record.full_hash.len(), 64);
    }

    #[test]
    fn test_prunes_expired_and_consumed() {
        let (store, _dir) = make_store();
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let mut active =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false);
        active.expires_at = format_timestamp(now + Duration::hours(1));

        let mut expired = PendingExceptionRecord::new(
            now - Duration::hours(30),
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
        );
        expired.expires_at = format_timestamp(now - Duration::hours(1));

        let mut consumed = PendingExceptionRecord::new(
            now,
            "/repo",
            "rm -rf /tmp/foo",
            "blocked",
            &redaction,
            true,
        );
        consumed.consumed_at = Some(format_timestamp(now));

        let contents = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&active).unwrap(),
            serde_json::to_string(&expired).unwrap(),
            serde_json::to_string(&consumed).unwrap()
        );
        std::fs::write(store.path(), contents).unwrap();

        let (records, maintenance) = store.load_active(now).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(maintenance.pruned_expired, 1);
        assert_eq!(maintenance.pruned_consumed, 1);

        let rewritten = std::fs::read_to_string(store.path()).unwrap();
        assert_eq!(rewritten.lines().count(), 1);
    }

    #[test]
    fn test_skips_corrupt_lines() {
        let (store, _dir) = make_store();
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git status",
            "ok",
            &redaction_config(),
            false,
        );

        let contents = format!("not-json\n{}\n", serde_json::to_string(&record).unwrap());
        std::fs::write(store.path(), contents).unwrap();

        let (records, maintenance) = store.load_active(now).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(maintenance.parse_errors, 1);
    }

    #[test]
    fn test_lookup_by_code_filters() {
        let (store, _dir) = make_store();
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let record_a =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false);
        let record_b = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
        );

        let contents = format!(
            "{}\n{}\n",
            serde_json::to_string(&record_a).unwrap(),
            serde_json::to_string(&record_b).unwrap()
        );
        std::fs::write(store.path(), contents).unwrap();

        let (matches, _maintenance) = store.lookup_by_code(&record_a.short_code, now).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].command_raw, "git status");
    }
}

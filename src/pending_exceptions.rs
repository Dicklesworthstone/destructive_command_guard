//! Pending exception store for allow-once short-code flow.
//!
//! This module provides a small JSONL-backed record store that is:
//! - Append-friendly for concurrent hooks
//! - Deterministic in serialization
//! - Fail-open on parse errors (corrupt lines are skipped)

use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;
use hmac::{Hmac, Mac};
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
/// Environment override for allow-once entries file path.
pub const ENV_ALLOW_ONCE_PATH: &str = "DCG_ALLOW_ONCE_PATH";
/// Optional HMAC secret for short-code hardening.
/// When set, codes cannot be forged without knowing the secret.
pub const ENV_ALLOW_ONCE_SECRET: &str = "DCG_ALLOW_ONCE_SECRET";

const PENDING_EXCEPTIONS_FILE: &str = "pending_exceptions.jsonl";
const ALLOW_ONCE_FILE: &str = "allow_once.jsonl";
const SCHEMA_VERSION: u32 = 1;
const EXPIRY_HOURS: i64 = 24;

/// Scope kind for allow-once entries.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AllowOnceScopeKind {
    Cwd,
    Project,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// A stored allow-once entry (JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowOnceEntry {
    pub schema_version: u32,
    pub source_short_code: String,
    pub source_full_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub scope_kind: AllowOnceScopeKind,
    pub scope_path: String,
    pub command_raw: String,
    pub command_redacted: String,
    pub reason: String,
    #[serde(default)]
    pub single_use: bool,
    pub consumed_at: Option<String>,
    #[serde(default)]
    pub force_allow_config: bool,
}

impl AllowOnceEntry {
    #[must_use]
    pub fn from_pending(
        pending: &PendingExceptionRecord,
        now: DateTime<Utc>,
        scope_kind: AllowOnceScopeKind,
        scope_path: &str,
        single_use: bool,
        force_allow_config: bool,
        redaction: &RedactionConfig,
    ) -> Self {
        let created_at = format_timestamp(now);
        let expires_at = format_timestamp(now + Duration::hours(EXPIRY_HOURS));

        Self {
            schema_version: SCHEMA_VERSION,
            source_short_code: pending.short_code.clone(),
            source_full_hash: pending.full_hash.clone(),
            created_at,
            expires_at,
            scope_kind,
            scope_path: scope_path.to_string(),
            command_raw: pending.command_raw.clone(),
            command_redacted: redact_for_pending(&pending.command_raw, redaction),
            reason: pending.reason.clone(),
            single_use,
            consumed_at: None,
            force_allow_config,
        }
    }

    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    #[must_use]
    pub fn matches_scope(&self, cwd: &Path) -> bool {
        let scope_path = Path::new(&self.scope_path);
        match self.scope_kind {
            AllowOnceScopeKind::Cwd => cwd == scope_path,
            AllowOnceScopeKind::Project => cwd.starts_with(scope_path),
        }
    }
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
        source: Option<String>,
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
            source,
        }
    }

    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }
}

/// Maintenance stats produced while loading/pruning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
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
    #[allow(clippy::too_many_arguments)]
    pub fn record_block(
        &self,
        command: &str,
        cwd: &str,
        reason: &str,
        redaction: &RedactionConfig,
        single_use: bool,
        source: Option<String>,
        allow_once_audit: Option<&AllowOnceAuditConfig<'_>>,
    ) -> io::Result<(PendingExceptionRecord, PendingMaintenance)> {
        let now = Utc::now();
        let record =
            PendingExceptionRecord::new(now, cwd, command, reason, redaction, single_use, source);

        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_active_from_file(&mut file, now, allow_once_audit);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_records(&mut file, &active)?;
        }

        append_record(&mut file, &record)?;

        if let Some(audit) = allow_once_audit {
            let _ = log_code_issued(audit.log_file, &record, audit.redaction, audit.format);
        }

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
        let (active, maintenance) = load_active_from_file(&mut file, now, None);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_records(&mut file, &active)?;
        }

        Ok((active, maintenance))
    }

    /// Load active records without rewriting the store file.
    ///
    /// This is useful for "preview" operations that want to display what would
    /// change before mutating on disk.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening or locking the store file.
    pub fn preview_active(
        &self,
        now: DateTime<Utc>,
    ) -> io::Result<(Vec<PendingExceptionRecord>, PendingMaintenance)> {
        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_active_from_file(&mut file, now, None);
        Ok((active, maintenance))
    }

    /// Remove all active records (expired/consumed are also pruned).
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn clear_all(&self, now: DateTime<Utc>) -> io::Result<(usize, PendingMaintenance)> {
        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_active_from_file(&mut file, now, None);
        let removed = active.len();
        rewrite_records(&mut file, &[])?;
        Ok((removed, maintenance))
    }

    /// Remove active records matching a full hash (expired/consumed are also pruned).
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn remove_by_full_hash(
        &self,
        full_hash: &str,
        now: DateTime<Utc>,
    ) -> io::Result<(usize, PendingMaintenance)> {
        let mut file = open_locked(&self.path)?;
        let (mut active, maintenance) = load_active_from_file(&mut file, now, None);
        let before = active.len();
        active.retain(|record| record.full_hash != full_hash);
        let removed = before - active.len();

        if removed > 0 || maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_records(&mut file, &active)?;
        }

        Ok((removed, maintenance))
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

/// Allow-once entry store wrapper.
#[derive(Debug, Clone)]
pub struct AllowOnceStore {
    path: PathBuf,
}

impl AllowOnceStore {
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
        if let Ok(value) = env::var(ENV_ALLOW_ONCE_PATH) {
            if let Some(path) = resolve_config_path_value(&value, cwd) {
                return path;
            }
        }

        let base = dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"));
        base.join("dcg").join(ALLOW_ONCE_FILE)
    }

    /// Append a new allow-once entry and prune expired/consumed entries.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn add_entry(
        &self,
        entry: &AllowOnceEntry,
        now: DateTime<Utc>,
    ) -> io::Result<PendingMaintenance> {
        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_allow_once_from_file(&mut file, now, None);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_allow_once_records(&mut file, &active)?;
        }

        append_allow_once_record(&mut file, entry)?;
        Ok(maintenance)
    }

    /// Load active allow-once entries and prune expired/consumed entries from disk.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn load_active(
        &self,
        now: DateTime<Utc>,
    ) -> io::Result<(Vec<AllowOnceEntry>, PendingMaintenance)> {
        if !self.path.exists() {
            return Ok((Vec::new(), PendingMaintenance::default()));
        }

        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_allow_once_from_file(&mut file, now, None);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_allow_once_records(&mut file, &active)?;
        }

        Ok((active, maintenance))
    }

    /// Load active allow-once entries without rewriting the store file.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening or locking the store file.
    pub fn preview_active(
        &self,
        now: DateTime<Utc>,
    ) -> io::Result<(Vec<AllowOnceEntry>, PendingMaintenance)> {
        if !self.path.exists() {
            return Ok((Vec::new(), PendingMaintenance::default()));
        }

        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_allow_once_from_file(&mut file, now, None);
        Ok((active, maintenance))
    }

    /// Remove all active allow-once entries (expired/consumed are also pruned).
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn clear_all(&self, now: DateTime<Utc>) -> io::Result<(usize, PendingMaintenance)> {
        if !self.path.exists() {
            return Ok((0, PendingMaintenance::default()));
        }

        let mut file = open_locked(&self.path)?;
        let (active, maintenance) = load_allow_once_from_file(&mut file, now, None);
        let removed = active.len();
        rewrite_allow_once_records(&mut file, &[])?;
        Ok((removed, maintenance))
    }

    /// Remove active allow-once entries matching a source full hash (expired/consumed are also pruned).
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn remove_by_source_full_hash(
        &self,
        full_hash: &str,
        now: DateTime<Utc>,
    ) -> io::Result<(usize, PendingMaintenance)> {
        if !self.path.exists() {
            return Ok((0, PendingMaintenance::default()));
        }

        let mut file = open_locked(&self.path)?;
        let (mut active, maintenance) = load_allow_once_from_file(&mut file, now, None);
        let before = active.len();
        active.retain(|entry| entry.source_full_hash != full_hash);
        let removed = before - active.len();

        if removed > 0 || maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_allow_once_records(&mut file, &active)?;
        }

        Ok((removed, maintenance))
    }

    /// Match a command against active allow-once entries.
    ///
    /// If a single-use entry matches, it is consumed immediately.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn match_command(
        &self,
        command: &str,
        cwd: &Path,
        now: DateTime<Utc>,
        allow_once_audit: Option<&AllowOnceAuditConfig<'_>>,
    ) -> io::Result<Option<AllowOnceEntry>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = open_locked(&self.path)?;
        let (mut active, maintenance) = load_allow_once_from_file(&mut file, now, allow_once_audit);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_allow_once_records(&mut file, &active)?;
        }

        let idx = active
            .iter()
            .position(|entry| entry.command_raw == command && entry.matches_scope(cwd));

        let Some(idx) = idx else {
            return Ok(None);
        };

        let mut selected = active[idx].clone();
        if active[idx].single_use {
            selected.consumed_at = Some(format_timestamp(now));
            active.remove(idx);
            rewrite_allow_once_records(&mut file, &active)?;
        }

        if let Some(audit) = allow_once_audit {
            let cwd_str = cwd.to_string_lossy();
            let _ = log_allow_granted(
                audit.log_file,
                &selected,
                audit.redaction,
                "allow_once",
                audit.format,
                cwd_str.as_ref(),
            );
            if selected.consumed_at.is_some() {
                let _ = log_entry_consumed(
                    audit.log_file,
                    &selected,
                    audit.redaction,
                    audit.format,
                    cwd_str.as_ref(),
                );
            }
        }

        Ok(Some(selected))
    }

    /// Match a command against allow-once entries, but only grant if `force_allow_config` is set.
    ///
    /// This prevents single-use entries from being consumed when a config blocklist would still
    /// deny the command (unless explicitly forced).
    ///
    /// If a single-use entry matches and is granted, it is consumed immediately.
    ///
    /// # Errors
    ///
    /// Returns any I/O errors encountered while opening, locking, or writing the store file.
    pub fn match_command_force_config(
        &self,
        command: &str,
        cwd: &Path,
        now: DateTime<Utc>,
        allow_once_audit: Option<&AllowOnceAuditConfig<'_>>,
    ) -> io::Result<Option<AllowOnceEntry>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let mut file = open_locked(&self.path)?;
        let (mut active, maintenance) = load_allow_once_from_file(&mut file, now, allow_once_audit);

        if maintenance.pruned_expired > 0 || maintenance.pruned_consumed > 0 {
            rewrite_allow_once_records(&mut file, &active)?;
        }

        let idx = active
            .iter()
            .position(|entry| entry.command_raw == command && entry.matches_scope(cwd));

        let Some(idx) = idx else {
            return Ok(None);
        };

        if !active[idx].force_allow_config {
            return Ok(None);
        }

        let mut selected = active[idx].clone();
        if active[idx].single_use {
            selected.consumed_at = Some(format_timestamp(now));
            active.remove(idx);
            rewrite_allow_once_records(&mut file, &active)?;
        }

        if let Some(audit) = allow_once_audit {
            let cwd_str = cwd.to_string_lossy();
            let _ = log_allow_granted(
                audit.log_file,
                &selected,
                audit.redaction,
                "allow_once",
                audit.format,
                cwd_str.as_ref(),
            );
            if selected.consumed_at.is_some() {
                let _ = log_entry_consumed(
                    audit.log_file,
                    &selected,
                    audit.redaction,
                    audit.format,
                    cwd_str.as_ref(),
                );
            }
        }

        Ok(Some(selected))
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

/// Log an allow-once management action (best-effort).
///
/// This uses the same log file path expansion rules as [`log_maintenance`].
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_allow_once_action(log_file: &str, action: &str, details: &str) -> io::Result<()> {
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
    writeln!(file, "[{timestamp}] [allow-once] {action}: {details}")?;
    Ok(())
}

// ============================================================================
// Structured Allow-Once Logging
// ============================================================================

/// Runtime configuration for allow-once audit logging.
///
/// This is passed down from hook/CLI code so pending/allow-once store maintenance can emit
/// structured log events without re-parsing config.
#[derive(Debug, Clone, Copy)]
pub struct AllowOnceAuditConfig<'a> {
    pub log_file: &'a str,
    pub format: AllowOnceLogFormat,
    pub redaction: &'a RedactionConfig,
}

/// Event kind for structured allow-once logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowOnceEventKind {
    /// A short code was issued when a command was blocked.
    CodeIssued,
    /// A short code was resolved and an allow-once entry was created.
    CodeResolved,
    /// An allow-once entry granted permission to a command.
    AllowGranted,
    /// A single-use allow-once entry was consumed.
    EntryConsumed,
    /// An allow-once entry expired and was pruned.
    EntryExpired,
}

impl AllowOnceEventKind {
    /// Get a human-readable label for this event kind.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CodeIssued => "code_issued",
            Self::CodeResolved => "code_resolved",
            Self::AllowGranted => "allow_granted",
            Self::EntryConsumed => "entry_consumed",
            Self::EntryExpired => "entry_expired",
        }
    }
}

/// A structured log entry for allow-once events.
///
/// This provides machine-readable, stable log entries for audit trails.
/// All command data respects the redaction configuration.
#[derive(Debug, Clone, Serialize)]
pub struct AllowOnceLogEntry {
    /// ISO 8601 timestamp of the event.
    pub timestamp: String,
    /// Event kind (`code_issued`, `code_resolved`, `allow_granted`, etc.).
    pub event: String,
    /// Short code (4 hex chars) for user interaction.
    pub short_code: String,
    /// Full SHA256 hash for unique identification.
    pub full_hash: String,
    /// Working directory where the command was executed.
    pub cwd: String,
    /// Command text (redacted according to configuration).
    pub command: String,
    /// Expiry timestamp for the exception.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Reason the command was blocked (for `code_issued` events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Allowlist layer used (for `allow_granted` events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist_layer: Option<String>,
    /// Scope kind (cwd or project).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_kind: Option<String>,
    /// Whether this was a single-use exception.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_use: Option<bool>,
    /// Whether this overrode a config blocklist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_allow_config: Option<bool>,
    /// Match source (pack, `config_override`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl AllowOnceLogEntry {
    /// Create a log entry for a code issuance event (when a command is blocked).
    #[must_use]
    pub fn code_issued(record: &PendingExceptionRecord, redaction: &RedactionConfig) -> Self {
        Self {
            timestamp: format_timestamp(Utc::now()),
            event: AllowOnceEventKind::CodeIssued.label().to_string(),
            short_code: record.short_code.clone(),
            full_hash: record.full_hash.clone(),
            cwd: record.cwd.clone(),
            command: redact_for_log(&record.command_raw, redaction),
            expires_at: Some(record.expires_at.clone()),
            reason: Some(record.reason.clone()),
            allowlist_layer: None,
            scope_kind: None,
            single_use: Some(record.single_use),
            force_allow_config: None,
            source: record.source.clone(),
        }
    }

    /// Create a log entry for a code resolution event (when allow-once is granted).
    #[must_use]
    pub fn code_resolved(entry: &AllowOnceEntry, redaction: &RedactionConfig) -> Self {
        Self {
            timestamp: format_timestamp(Utc::now()),
            event: AllowOnceEventKind::CodeResolved.label().to_string(),
            short_code: entry.source_short_code.clone(),
            full_hash: entry.source_full_hash.clone(),
            cwd: entry.scope_path.clone(),
            command: redact_for_log(&entry.command_raw, redaction),
            expires_at: Some(entry.expires_at.clone()),
            reason: Some(entry.reason.clone()),
            allowlist_layer: None,
            scope_kind: Some(format!("{:?}", entry.scope_kind).to_lowercase()),
            single_use: Some(entry.single_use),
            force_allow_config: Some(entry.force_allow_config),
            source: None,
        }
    }

    /// Create a log entry for an allow grant event (when a command is allowed by allow-once).
    #[must_use]
    pub fn allow_granted(
        entry: &AllowOnceEntry,
        redaction: &RedactionConfig,
        layer: &str,
        cwd: &str,
    ) -> Self {
        Self {
            timestamp: format_timestamp(Utc::now()),
            event: AllowOnceEventKind::AllowGranted.label().to_string(),
            short_code: entry.source_short_code.clone(),
            full_hash: entry.source_full_hash.clone(),
            cwd: cwd.to_string(),
            command: redact_for_log(&entry.command_raw, redaction),
            expires_at: Some(entry.expires_at.clone()),
            reason: None,
            allowlist_layer: Some(layer.to_string()),
            scope_kind: Some(format!("{:?}", entry.scope_kind).to_lowercase()),
            single_use: Some(entry.single_use),
            force_allow_config: Some(entry.force_allow_config),
            source: None,
        }
    }

    /// Create a log entry for an entry consumption event (single-use consumed).
    #[must_use]
    pub fn entry_consumed(entry: &AllowOnceEntry, redaction: &RedactionConfig, cwd: &str) -> Self {
        Self {
            timestamp: format_timestamp(Utc::now()),
            event: AllowOnceEventKind::EntryConsumed.label().to_string(),
            short_code: entry.source_short_code.clone(),
            full_hash: entry.source_full_hash.clone(),
            cwd: cwd.to_string(),
            command: redact_for_log(&entry.command_raw, redaction),
            expires_at: Some(entry.expires_at.clone()),
            reason: None,
            allowlist_layer: None,
            scope_kind: Some(format!("{:?}", entry.scope_kind).to_lowercase()),
            single_use: Some(true),
            force_allow_config: None,
            source: None,
        }
    }

    /// Create a log entry for an entry expiry event.
    #[must_use]
    pub fn entry_expired(
        short_code: &str,
        full_hash: &str,
        cwd: &str,
        command: &str,
        expires_at: &str,
        redaction: &RedactionConfig,
    ) -> Self {
        Self {
            timestamp: format_timestamp(Utc::now()),
            event: AllowOnceEventKind::EntryExpired.label().to_string(),
            short_code: short_code.to_string(),
            full_hash: full_hash.to_string(),
            cwd: cwd.to_string(),
            command: redact_for_log(command, redaction),
            expires_at: Some(expires_at.to_string()),
            reason: None,
            allowlist_layer: None,
            scope_kind: None,
            single_use: None,
            force_allow_config: None,
            source: None,
        }
    }

    /// Format as a text log line.
    #[must_use]
    pub fn format_text(&self) -> String {
        let mut parts = Vec::with_capacity(8);
        parts.push(format!("[{}]", self.timestamp));
        parts.push(format!("[allow-once:{}]", self.event));
        parts.push(format!("code={}", self.short_code));
        parts.push(format!("cwd=\"{}\"", self.cwd));
        parts.push(format!("cmd=\"{}\"", self.command));

        if let Some(ref expires) = self.expires_at {
            parts.push(format!("expires={expires}"));
        }
        if let Some(ref reason) = self.reason {
            parts.push(format!("reason=\"{reason}\""));
        }
        if let Some(ref layer) = self.allowlist_layer {
            parts.push(format!("layer={layer}"));
        }
        if let Some(single) = self.single_use {
            if single {
                parts.push("single_use=true".to_string());
            }
        }
        if let Some(force) = self.force_allow_config {
            if force {
                parts.push("force_allow=true".to_string());
            }
        }

        parts.join(" ")
    }

    /// Format as a JSON line.
    #[must_use]
    pub fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Log format for allow-once structured logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllowOnceLogFormat {
    /// Human-readable text format.
    #[default]
    Text,
    /// Machine-readable JSON format.
    Json,
}

/// Log a structured allow-once event.
///
/// This is the primary function for logging allow-once events with full
/// structured data and redaction support.
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_allow_once_event(
    log_file: &str,
    entry: &AllowOnceLogEntry,
    format: AllowOnceLogFormat,
) -> io::Result<()> {
    let path = expand_log_path(log_file);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    let line = match format {
        AllowOnceLogFormat::Text => entry.format_text(),
        AllowOnceLogFormat::Json => entry.format_json(),
    };

    writeln!(file, "{line}")?;
    Ok(())
}

/// Log a code issuance event (when a command is blocked and a short code is generated).
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_code_issued(
    log_file: &str,
    record: &PendingExceptionRecord,
    redaction: &RedactionConfig,
    format: AllowOnceLogFormat,
) -> io::Result<()> {
    let entry = AllowOnceLogEntry::code_issued(record, redaction);
    log_allow_once_event(log_file, &entry, format)
}

/// Log a code resolution event (when an allow-once entry is created from a pending code).
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_code_resolved(
    log_file: &str,
    allow_entry: &AllowOnceEntry,
    redaction: &RedactionConfig,
    format: AllowOnceLogFormat,
) -> io::Result<()> {
    let entry = AllowOnceLogEntry::code_resolved(allow_entry, redaction);
    log_allow_once_event(log_file, &entry, format)
}

/// Log an allow grant event (when a command is allowed by an allow-once entry).
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_allow_granted(
    log_file: &str,
    allow_entry: &AllowOnceEntry,
    redaction: &RedactionConfig,
    layer: &str,
    format: AllowOnceLogFormat,
    cwd: &str,
) -> io::Result<()> {
    let entry = AllowOnceLogEntry::allow_granted(allow_entry, redaction, layer, cwd);
    log_allow_once_event(log_file, &entry, format)
}

/// Log an entry consumption event (when a single-use allow-once entry is consumed).
///
/// # Errors
///
/// Returns any I/O errors encountered while opening or appending to the log file.
pub fn log_entry_consumed(
    log_file: &str,
    allow_entry: &AllowOnceEntry,
    redaction: &RedactionConfig,
    format: AllowOnceLogFormat,
    cwd: &str,
) -> io::Result<()> {
    let entry = AllowOnceLogEntry::entry_consumed(allow_entry, redaction, cwd);
    log_allow_once_event(log_file, &entry, format)
}

fn expand_log_path(log_file: &str) -> PathBuf {
    if log_file.starts_with("~/") {
        std::env::var_os("HOME").map_or_else(
            || PathBuf::from(log_file),
            |home| PathBuf::from(format!("{}{}", home.to_string_lossy(), &log_file[1..])),
        )
    } else {
        PathBuf::from(log_file)
    }
}

fn redact_for_log(command: &str, redaction: &RedactionConfig) -> String {
    if !redaction.enabled {
        return command.to_string();
    }
    redact_command(command, redaction)
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
    allow_once_audit: Option<&AllowOnceAuditConfig<'_>>,
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
            if let Some(audit) = allow_once_audit {
                let expired = AllowOnceLogEntry::entry_expired(
                    &record.short_code,
                    &record.full_hash,
                    &record.cwd,
                    &record.command_raw,
                    &record.expires_at,
                    audit.redaction,
                );
                let _ = log_allow_once_event(audit.log_file, &expired, audit.format);
            }
            continue;
        }

        active.push(record);
    }

    (active, maintenance)
}

fn load_allow_once_from_file(
    file: &mut File,
    now: DateTime<Utc>,
    allow_once_audit: Option<&AllowOnceAuditConfig<'_>>,
) -> (Vec<AllowOnceEntry>, PendingMaintenance) {
    let mut maintenance = PendingMaintenance::default();
    let mut active: Vec<AllowOnceEntry> = Vec::new();

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

        let Ok(record) = serde_json::from_str::<AllowOnceEntry>(trimmed) else {
            maintenance.parse_errors += 1;
            continue;
        };

        if record.is_consumed() {
            maintenance.pruned_consumed += 1;
            continue;
        }

        if is_expired(&record.expires_at, now) {
            maintenance.pruned_expired += 1;
            if let Some(audit) = allow_once_audit {
                let expired = AllowOnceLogEntry::entry_expired(
                    &record.source_short_code,
                    &record.source_full_hash,
                    &record.scope_path,
                    &record.command_raw,
                    &record.expires_at,
                    audit.redaction,
                );
                let _ = log_allow_once_event(audit.log_file, &expired, audit.format);
            }
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

fn rewrite_allow_once_records(file: &mut File, records: &[AllowOnceEntry]) -> io::Result<()> {
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

fn append_allow_once_record(file: &mut File, record: &AllowOnceEntry) -> io::Result<()> {
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

/// Type alias for HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

fn sha256_digest(input: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

/// Compute full hash for a pending exception.
///
/// If `DCG_ALLOW_ONCE_SECRET` is set, uses HMAC-SHA256 for tamper resistance.
/// Otherwise, uses plain SHA256 (backwards compatible).
fn compute_full_hash(timestamp: &str, cwd: &str, command_raw: &str) -> String {
    let secret = env::var(ENV_ALLOW_ONCE_SECRET).ok();
    compute_full_hash_with_secret(timestamp, cwd, command_raw, secret.as_deref())
}

/// Compute full hash with an explicit secret parameter.
///
/// - If `secret` is `Some(...)`, uses HMAC-SHA256 for tamper resistance.
/// - If `secret` is `None`, uses plain SHA256 (backwards compatible).
fn compute_full_hash_with_secret(
    timestamp: &str,
    cwd: &str,
    command_raw: &str,
    secret: Option<&str>,
) -> String {
    let input = format!("{timestamp} | {cwd} | {command_raw}");

    let digest: Vec<u8> = secret.map_or_else(
        || sha256_digest(&input),
        |secret| {
            // HMAC-SHA256 with secret for tamper resistance
            HmacSha256::new_from_slice(secret.as_bytes()).map_or_else(
                |_| sha256_digest(&input),
                |mut mac| {
                    mac.update(input.as_bytes());
                    mac.finalize().into_bytes().to_vec()
                },
            )
        },
    );

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
            None,
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
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);
        active.expires_at = format_timestamp(now + Duration::hours(1));

        let mut expired = PendingExceptionRecord::new(
            now - Duration::hours(30),
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );
        expired.expires_at = format_timestamp(now - Duration::hours(1));

        let mut consumed = PendingExceptionRecord::new(
            now,
            "/repo",
            "rm -rf /tmp/foo",
            "blocked",
            &redaction,
            true,
            None,
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
            None,
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
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);
        let record_b = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
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

    #[test]
    fn test_allow_once_consumes_single_use() {
        let dir = TempDir::new().expect("tempdir");
        let allow_path = dir.path().join("allow_once.jsonl");
        let store = AllowOnceStore::new(allow_path);
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let pending =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);

        let entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            true,
            false,
            &redaction,
        );

        store.add_entry(&entry, now).unwrap();

        let cwd = Path::new("/repo");
        let first = store.match_command("git status", cwd, now, None).unwrap();
        assert!(first.is_some());

        let second = store.match_command("git status", cwd, now, None).unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn test_allow_once_project_scope_matches_subdir() {
        let dir = TempDir::new().expect("tempdir");
        let allow_path = dir.path().join("allow_once.jsonl");
        let store = AllowOnceStore::new(allow_path);
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let pending =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);

        let entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Project,
            "/repo",
            false,
            false,
            &redaction,
        );

        store.add_entry(&entry, now).unwrap();

        let cwd = Path::new("/repo/subdir");
        let matched = store.match_command("git status", cwd, now, None).unwrap();
        assert!(matched.is_some());
    }

    #[test]
    fn test_full_hash_derivation_is_stable_and_lowercase() {
        let hash = compute_full_hash("2099-01-01T00:00:00Z", "/repo", "git status");
        assert_eq!(
            hash,
            "17a268f67ce0aab3bc5015427e3ba8fd1d643d25f9f13dca1332c13818a5ac63"
        );
        assert_eq!(hash, hash.to_lowercase());
        assert_eq!(short_code_from_hash(&hash), "ac63");
    }

    #[test]
    fn test_allow_once_reusable_until_expiry() {
        let dir = TempDir::new().expect("tempdir");
        let allow_path = dir.path().join("allow_once.jsonl");
        let store = AllowOnceStore::new(allow_path.clone());
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let pending =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);
        let entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            false,
            false,
            &redaction,
        );
        store.add_entry(&entry, now).unwrap();

        let cwd = Path::new("/repo");
        assert!(
            store
                .match_command("git status", cwd, now, None)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .match_command("git status", cwd, now, None)
                .unwrap()
                .is_some()
        );

        let contents = std::fs::read_to_string(&allow_path).unwrap();
        assert_eq!(contents.lines().count(), 1);
    }

    #[test]
    fn test_allow_once_scope_mismatch_does_not_allow() {
        let dir = TempDir::new().expect("tempdir");
        let allow_path = dir.path().join("allow_once.jsonl");
        let store = AllowOnceStore::new(allow_path);
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let pending =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);
        let entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            false,
            false,
            &redaction,
        );
        store.add_entry(&entry, now).unwrap();

        let cwd = Path::new("/different");
        assert!(
            store
                .match_command("git status", cwd, now, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_allow_once_load_active_prunes_expired_and_consumed() {
        let dir = TempDir::new().expect("tempdir");
        let allow_path = dir.path().join("allow_once.jsonl");
        let store = AllowOnceStore::new(allow_path.clone());
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let pending =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);

        let active = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            false,
            false,
            &redaction,
        );

        let mut expired = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            false,
            false,
            &redaction,
        );
        expired.expires_at = format_timestamp(now - Duration::hours(1));

        let mut consumed = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            true,
            false,
            &redaction,
        );
        consumed.consumed_at = Some(format_timestamp(now));

        let contents = format!(
            "{}\n{}\n{}\n",
            serde_json::to_string(&active).unwrap(),
            serde_json::to_string(&expired).unwrap(),
            serde_json::to_string(&consumed).unwrap()
        );
        std::fs::write(&allow_path, contents).unwrap();

        let (entries, maintenance) = store.load_active(now).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(maintenance.pruned_expired, 1);
        assert_eq!(maintenance.pruned_consumed, 1);

        let rewritten = std::fs::read_to_string(&allow_path).unwrap();
        assert_eq!(rewritten.lines().count(), 1);
    }

    #[test]
    fn test_pending_lookup_by_code_returns_multiple_on_collision() {
        let (store, _dir) = make_store();
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();

        let record_a =
            PendingExceptionRecord::new(now, "/repo", "git status", "ok", &redaction, false, None);
        let mut record_b = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );

        // Force a short-code collision (real collisions are unlikely; we want deterministic coverage).
        record_b.short_code = record_a.short_code.clone();

        let contents = format!(
            "{}\n{}\n",
            serde_json::to_string(&record_a).unwrap(),
            serde_json::to_string(&record_b).unwrap()
        );
        std::fs::write(store.path(), contents).unwrap();

        let (matches, _maintenance) = store.lookup_by_code(&record_a.short_code, now).unwrap();
        assert_eq!(matches.len(), 2);
    }

    // =========================================================================
    // Structured Logging Tests
    // =========================================================================

    #[test]
    fn test_allow_once_log_entry_code_issued() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard HEAD",
            "destructive command blocked",
            &redaction,
            false,
            Some("core.git".to_string()),
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        assert_eq!(entry.event, "code_issued");
        assert_eq!(entry.short_code, record.short_code);
        assert_eq!(entry.full_hash, record.full_hash);
        assert_eq!(entry.cwd, "/repo");
        assert!(entry.reason.is_some());
        assert_eq!(entry.source, Some("core.git".to_string()));
    }

    #[test]
    fn test_allow_once_log_entry_code_resolved() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let pending = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );
        let allow_entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            true,
            false,
            &redaction,
        );

        let entry = AllowOnceLogEntry::code_resolved(&allow_entry, &redaction);
        assert_eq!(entry.event, "code_resolved");
        assert_eq!(entry.scope_kind, Some("cwd".to_string()));
        assert_eq!(entry.single_use, Some(true));
        assert_eq!(entry.force_allow_config, Some(false));
    }

    #[test]
    fn test_allow_once_log_entry_allow_granted() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let pending = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );
        let allow_entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Project,
            "/repo",
            false,
            false,
            &redaction,
        );

        let entry =
            AllowOnceLogEntry::allow_granted(&allow_entry, &redaction, "allow_once", "/repo");
        assert_eq!(entry.event, "allow_granted");
        assert_eq!(entry.allowlist_layer, Some("allow_once".to_string()));
        assert_eq!(entry.scope_kind, Some("project".to_string()));
    }

    #[test]
    fn test_allow_once_log_entry_entry_consumed() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let pending = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            true,
            None,
        );
        let allow_entry = AllowOnceEntry::from_pending(
            &pending,
            now,
            AllowOnceScopeKind::Cwd,
            "/repo",
            true,
            false,
            &redaction,
        );

        let entry = AllowOnceLogEntry::entry_consumed(&allow_entry, &redaction, "/repo");
        assert_eq!(entry.event, "entry_consumed");
        assert_eq!(entry.single_use, Some(true));
    }

    #[test]
    fn test_allow_once_log_entry_entry_expired() {
        let redaction = redaction_config();
        let entry = AllowOnceLogEntry::entry_expired(
            "ab12",
            "abc123def456",
            "/repo",
            "git reset --hard",
            "2026-01-11T06:30:00Z",
            &redaction,
        );
        assert_eq!(entry.event, "entry_expired");
        assert_eq!(entry.short_code, "ab12");
        assert_eq!(entry.expires_at, Some("2026-01-11T06:30:00Z".to_string()));
    }

    #[test]
    fn test_allow_once_log_entry_format_text() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            true,
            None,
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        let text = entry.format_text();

        assert!(text.contains("[allow-once:code_issued]"));
        assert!(text.contains("code="));
        assert!(text.contains("cwd=\"/repo\""));
        assert!(text.contains("single_use=true"));
    }

    #[test]
    fn test_allow_once_log_entry_format_json() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        let json = entry.format_json();

        // Verify it's valid JSON and contains expected fields
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["event"], "code_issued");
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["short_code"].is_string());
        assert!(parsed["full_hash"].is_string());
    }

    #[test]
    fn test_allow_once_log_entry_redaction_enabled() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = RedactionConfig {
            enabled: true,
            mode: crate::logging::RedactionMode::Full,
            max_argument_len: 8,
        };
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard HEAD",
            "blocked",
            &redaction,
            false,
            None,
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        assert_eq!(entry.command, "[REDACTED]");
    }

    #[test]
    fn test_allow_once_log_entry_redaction_disabled() {
        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = RedactionConfig {
            enabled: false,
            mode: crate::logging::RedactionMode::Full,
            max_argument_len: 8,
        };
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard HEAD",
            "blocked",
            &redaction,
            false,
            None,
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        assert_eq!(entry.command, "git reset --hard HEAD");
    }

    #[test]
    fn test_log_allow_once_event_writes_to_file() {
        let dir = TempDir::new().expect("tempdir");
        let log_path = dir.path().join("allow_once.log");
        let log_file = log_path.to_string_lossy().to_string();

        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        log_allow_once_event(&log_file, &entry, AllowOnceLogFormat::Text).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("[allow-once:code_issued]"));
        assert!(contents.contains("code="));
    }

    #[test]
    fn test_log_allow_once_event_json_format() {
        let dir = TempDir::new().expect("tempdir");
        let log_path = dir.path().join("allow_once.log");
        let log_file = log_path.to_string_lossy().to_string();

        let now = DateTime::parse_from_rfc3339("2026-01-10T06:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let redaction = redaction_config();
        let record = PendingExceptionRecord::new(
            now,
            "/repo",
            "git reset --hard",
            "blocked",
            &redaction,
            false,
            None,
        );

        let entry = AllowOnceLogEntry::code_issued(&record, &redaction);
        log_allow_once_event(&log_file, &entry, AllowOnceLogFormat::Json).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["event"], "code_issued");
    }

    #[test]
    fn test_allow_once_event_kind_labels() {
        assert_eq!(AllowOnceEventKind::CodeIssued.label(), "code_issued");
        assert_eq!(AllowOnceEventKind::CodeResolved.label(), "code_resolved");
        assert_eq!(AllowOnceEventKind::AllowGranted.label(), "allow_granted");
        assert_eq!(AllowOnceEventKind::EntryConsumed.label(), "entry_consumed");
        assert_eq!(AllowOnceEventKind::EntryExpired.label(), "entry_expired");
    }

    // =========================================================================
    // HMAC Hardening Tests (oien.1.10)
    // =========================================================================
    //
    // Tests use compute_full_hash_with_secret directly to avoid env var manipulation.

    #[test]
    fn test_hmac_hash_differs_from_plain_hash() {
        // Without secret: should produce plain SHA256
        let plain_hash =
            compute_full_hash_with_secret("2099-01-01T00:00:00Z", "/repo", "git status", None);

        // With secret: should produce HMAC-SHA256 (different hash)
        let hmac_hash = compute_full_hash_with_secret(
            "2099-01-01T00:00:00Z",
            "/repo",
            "git status",
            Some("test-secret-key"),
        );

        // Hashes should be different
        assert_ne!(
            plain_hash, hmac_hash,
            "HMAC hash should differ from plain SHA256 hash"
        );

        // Both should be valid hex strings of 64 chars (256 bits)
        assert_eq!(plain_hash.len(), 64);
        assert_eq!(hmac_hash.len(), 64);
    }

    #[test]
    fn test_hmac_hash_is_deterministic() {
        let hash1 = compute_full_hash_with_secret(
            "2099-01-01T00:00:00Z",
            "/repo",
            "git status",
            Some("deterministic-secret"),
        );
        let hash2 = compute_full_hash_with_secret(
            "2099-01-01T00:00:00Z",
            "/repo",
            "git status",
            Some("deterministic-secret"),
        );

        assert_eq!(
            hash1, hash2,
            "Same inputs with same secret should produce same HMAC"
        );
    }

    #[test]
    fn test_different_secrets_produce_different_hashes() {
        let hash1 = compute_full_hash_with_secret(
            "2099-01-01T00:00:00Z",
            "/repo",
            "git status",
            Some("secret-one"),
        );
        let hash2 = compute_full_hash_with_secret(
            "2099-01-01T00:00:00Z",
            "/repo",
            "git status",
            Some("secret-two"),
        );

        assert_ne!(
            hash1, hash2,
            "Different secrets should produce different HMAC hashes"
        );
    }

    #[test]
    fn test_backwards_compatible_hash_without_secret() {
        // Ensure the expected hash from test_full_hash_derivation_is_stable_and_lowercase
        // is preserved when no secret is set (backwards compatibility)
        let hash =
            compute_full_hash_with_secret("2099-01-01T00:00:00Z", "/repo", "git status", None);

        assert_eq!(
            hash, "17a268f67ce0aab3bc5015427e3ba8fd1d643d25f9f13dca1332c13818a5ac63",
            "Hash without secret should match original implementation"
        );
    }
}

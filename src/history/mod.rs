//! Command history database for DCG.
//!
//! This module provides SQLite-based history collection and querying for
//! tracking all commands evaluated by DCG across agent sessions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      HistoryDb                                   │
//! │  (SQLite database for command history and analytics)            │
//! └─────────────────────────────────────────────────────────────────┘
//!                                  │
//!           ┌──────────────────────┼──────────────────────┐
//!           ▼                      ▼                      ▼
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │  commands table │    │  commands_fts   │    │ schema_version  │
//! │  (main storage) │    │  (full-text)    │    │  (migrations)   │
//! └─────────────────┘    └─────────────────┘    └─────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use destructive_command_guard::history::{HistoryDb, CommandEntry, Outcome};
//!
//! let db = HistoryDb::open(None)?; // Uses default path
//! db.log_command(&CommandEntry {
//!     timestamp: chrono::Utc::now(),
//!     agent_type: "claude_code".into(),
//!     working_dir: "/path/to/project".into(),
//!     command: "git status".into(),
//!     outcome: Outcome::Allow,
//!     ..Default::default()
//! })?;
//! ```

mod schema;

use crate::config::{HistoryConfig, HistoryRedactionMode};
use crate::logging::{RedactionConfig, RedactionMode};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, error, trace, warn};

pub use schema::{
    AgentStat, BackupResult, CURRENT_SCHEMA_VERSION, CheckResult, CommandEntry,
    DEFAULT_DB_FILENAME, ExportFilters, ExportOptions, ExportedData, FrequentBlock,
    HistoryAnalyzer, HistoryDb, HistoryError, HistoryStats, Outcome, OutcomeStats,
    PackEffectivenessAnalysis, PackRecommendation, PathCluster, PatternEffectiveness, PatternStat,
    PerformanceStats, PotentialGap, ProjectStat, RecommendationType, RuleMetrics, RuleTrend,
    StatsTrends, SuggestionAction, SuggestionAuditEntry, SuggestionCandidate,
};

/// Environment variable to override the history database path.
pub const ENV_HISTORY_DB_PATH: &str = "DCG_HISTORY_DB";

/// Environment variable to disable history collection entirely.
pub const ENV_HISTORY_DISABLED: &str = "DCG_HISTORY_DISABLED";

enum HistoryMessage {
    Entry(Box<CommandEntry>),
    Flush(mpsc::Sender<()>),
    Shutdown,
}

/// Configuration for the history worker thread.
#[derive(Clone)]
struct WorkerConfig {
    batch_size: usize,
    flush_interval: Duration,
    auto_prune: bool,
    retention_days: u32,
    prune_check_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            batch_size: 50,
            flush_interval: Duration::from_millis(100),
            auto_prune: false,
            retention_days: 90,
            prune_check_interval: Duration::from_secs(24 * 3600),
        }
    }
}

impl From<&HistoryConfig> for WorkerConfig {
    fn from(config: &HistoryConfig) -> Self {
        Self {
            batch_size: config.batch_size as usize,
            flush_interval: Duration::from_millis(u64::from(config.batch_flush_interval_ms)),
            auto_prune: config.auto_prune,
            retention_days: config.retention_days,
            prune_check_interval: Duration::from_secs(
                u64::from(config.prune_check_interval_hours) * 3600,
            ),
        }
    }
}

#[derive(Clone)]
pub struct HistoryFlushHandle {
    sender: mpsc::Sender<HistoryMessage>,
}

impl HistoryFlushHandle {
    /// Flush and wait for pending writes to complete.
    pub fn flush_sync(&self) {
        const FLUSH_TIMEOUT: Duration = Duration::from_secs(10);
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.sender.send(HistoryMessage::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(FLUSH_TIMEOUT);
        }
    }
}

/// Asynchronous history writer with write batching support.
pub struct HistoryWriter {
    sender: Option<mpsc::Sender<HistoryMessage>>,
    handle: Option<thread::JoinHandle<()>>,
    redaction_mode: HistoryRedactionMode,
    session_id: String,
}

impl HistoryWriter {
    /// Create a new history writer.
    ///
    /// The database path is passed to the worker thread, which opens the
    /// connection itself. This avoids needing `Send` on `HistoryDb` (which
    /// uses `Rc`-based `fsqlite::Connection` internally).
    ///
    /// The writer is disabled when `config.enabled` is false.
    #[must_use]
    pub fn new(db_path: Option<std::path::PathBuf>, config: &HistoryConfig) -> Self {
        if !config.enabled {
            return Self::disabled();
        }

        // Generate a unique session ID for this writer instance
        let session_id = generate_session_id();

        let (sender, receiver) = mpsc::channel::<HistoryMessage>();
        let worker_config = WorkerConfig::from(config);

        let handle = match thread::Builder::new()
            .name("dcg-history-writer".to_string())
            .spawn(move || {
                match HistoryDb::open(db_path) {
                    Ok(db) => history_worker(db, receiver, worker_config),
                    Err(e) => {
                        error!(error = %e, "Failed to open history DB in worker thread");
                        // Drain the receiver so senders don't block
                        drop(receiver);
                    }
                }
            }) {
            Ok(h) => h,
            Err(e) => {
                // Thread spawn failed - return disabled writer to avoid leaking
                // messages into a channel with no receiver.
                error!(
                    error = %e,
                    "Failed to spawn history writer thread - history collection disabled"
                );
                return Self::disabled();
            }
        };

        Self {
            sender: Some(sender),
            handle: Some(handle),
            redaction_mode: config.redaction_mode,
            session_id,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            sender: None,
            handle: None,
            redaction_mode: HistoryRedactionMode::Pattern,
            session_id: String::new(),
        }
    }

    /// Get the session ID for this writer instance.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn flush_handle(&self) -> Option<HistoryFlushHandle> {
        self.sender.as_ref().map(|sender| HistoryFlushHandle {
            sender: sender.clone(),
        })
    }

    /// Log a command entry asynchronously.
    pub fn log(&self, mut entry: CommandEntry) {
        entry.command = redact_for_history(&entry.command, self.redaction_mode);
        // Set session ID if not already set
        if entry.session_id.is_none() && !self.session_id.is_empty() {
            entry.session_id = Some(self.session_id.clone());
        }
        if let Some(sender) = &self.sender {
            if let Err(e) = sender.send(HistoryMessage::Entry(Box::new(entry))) {
                // Channel disconnected - worker thread likely crashed or shutdown
                warn!(
                    error = %e,
                    "Failed to send history entry - worker thread unavailable"
                );
            }
        }
    }

    /// Request a flush without waiting for completion.
    pub fn flush(&self) {
        if let Some(sender) = &self.sender {
            let (ack_tx, _ack_rx) = mpsc::channel();
            let _ = sender.send(HistoryMessage::Flush(ack_tx));
        }
    }

    /// Flush and wait for pending writes to complete.
    pub fn flush_sync(&self) {
        if let Some(handle) = self.flush_handle() {
            handle.flush_sync();
        }
    }
}

impl Drop for HistoryWriter {
    fn drop(&mut self) {
        self.flush_sync();

        if let Some(sender) = self.sender.take() {
            let _ = sender.send(HistoryMessage::Shutdown);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Generate a unique session ID for a writer instance.
fn generate_session_id() -> String {
    use sha2::{Digest, Sha256};
    use std::process;

    let now = chrono::Utc::now();
    let pid = process::id();
    let thread_id = format!("{:?}", thread::current().id());

    let mut hasher = Sha256::new();
    hasher.update(now.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(thread_id.as_bytes());

    let digest = hasher.finalize();
    // Use first 8 bytes for a shorter, more readable ID
    format!(
        "ses-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    )
}

#[allow(clippy::needless_pass_by_value)]
fn history_worker(db: HistoryDb, receiver: mpsc::Receiver<HistoryMessage>, config: WorkerConfig) {
    let mut batch: Vec<CommandEntry> = Vec::with_capacity(config.batch_size);
    let mut last_flush = Instant::now();
    let mut last_prune_check = Instant::now();

    // Check if we need auto-prune on startup
    if config.auto_prune {
        check_and_prune(&db, config.retention_days);
    }

    loop {
        // Use recv_timeout to enable periodic flushing
        let timeout = config.flush_interval.saturating_sub(last_flush.elapsed());
        match receiver.recv_timeout(timeout) {
            Ok(HistoryMessage::Entry(entry)) => {
                batch.push(*entry);

                // Flush if batch is full
                if batch.len() >= config.batch_size {
                    flush_batch(&db, &mut batch);
                    last_flush = Instant::now();
                }
            }
            Ok(HistoryMessage::Flush(ack)) => {
                // Drain and flush ALL pending entries before acknowledging.
                // drain_entries_into_batch caps at batch_size*2, so we loop
                // to ensure the entire channel is emptied before sending the ack.
                let mut pending_acks = vec![ack];
                let mut should_shutdown = false;
                loop {
                    while let Some(msg) =
                        drain_entries_into_batch(&receiver, &mut batch, config.batch_size)
                    {
                        match msg {
                            HistoryMessage::Flush(pending_ack) => pending_acks.push(pending_ack),
                            HistoryMessage::Shutdown => {
                                should_shutdown = true;
                                break;
                            }
                            HistoryMessage::Entry(_) => unreachable!(),
                        }
                    }
                    if batch.is_empty() || should_shutdown {
                        break;
                    }
                    flush_batch(&db, &mut batch);
                }
                // Final flush for any remaining entries
                flush_batch(&db, &mut batch);
                last_flush = Instant::now();
                // Send all pending acks
                for pending_ack in pending_acks {
                    let _ = pending_ack.send(());
                }
                if should_shutdown {
                    if let Err(e) = db.checkpoint() {
                        warn!(error = %e, "WAL checkpoint failed on shutdown");
                    }
                    break;
                }
            }
            Ok(HistoryMessage::Shutdown) => {
                // Final flush before shutdown
                let mut pending_acks = Vec::new();
                while let Some(msg) =
                    drain_entries_into_batch(&receiver, &mut batch, config.batch_size)
                {
                    match msg {
                        HistoryMessage::Flush(pending_ack) => pending_acks.push(pending_ack),
                        HistoryMessage::Shutdown => {} // Already shutting down
                        HistoryMessage::Entry(_) => unreachable!(),
                    }
                }
                flush_batch(&db, &mut batch);
                // Send all pending acks before shutdown
                for pending_ack in pending_acks {
                    let _ = pending_ack.send(());
                }
                // Checkpoint WAL before closing
                if let Err(e) = db.checkpoint() {
                    warn!(error = %e, "WAL checkpoint failed during shutdown");
                } else {
                    debug!("WAL checkpoint completed successfully");
                }
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Periodic flush on timeout
                if !batch.is_empty() {
                    flush_batch(&db, &mut batch);
                    last_flush = Instant::now();
                }

                // Check for auto-prune periodically
                if config.auto_prune && last_prune_check.elapsed() >= config.prune_check_interval {
                    check_and_prune(&db, config.retention_days);
                    last_prune_check = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Channel closed, flush and exit
                debug!("History channel disconnected, performing final flush");
                flush_batch(&db, &mut batch);
                if let Err(e) = db.checkpoint() {
                    warn!(error = %e, "WAL checkpoint failed on channel disconnect");
                }
                break;
            }
        }
    }
}

/// Drain pending entry messages into the batch.
///
/// Returns any control message (Flush/Shutdown) encountered during drain
/// so the caller can handle it properly instead of losing it.
fn drain_entries_into_batch(
    receiver: &mpsc::Receiver<HistoryMessage>,
    batch: &mut Vec<CommandEntry>,
    batch_size: usize,
) -> Option<HistoryMessage> {
    loop {
        match receiver.try_recv() {
            Ok(HistoryMessage::Entry(entry)) => {
                batch.push(*entry);
                // If batch exceeds limit, return to allow flush
                if batch.len() >= batch_size * 2 {
                    return None;
                }
            }
            Ok(msg @ (HistoryMessage::Flush(_) | HistoryMessage::Shutdown)) => {
                // Return control message so caller can handle it
                return Some(msg);
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {
                return None;
            }
        }
    }
}

/// Flush the batch to the database.
fn flush_batch(db: &HistoryDb, batch: &mut Vec<CommandEntry>) {
    if batch.is_empty() {
        return;
    }

    let batch_len = batch.len();
    trace!(batch_size = batch_len, "Flushing history batch");

    // Try batch insert first (more efficient)
    if batch_len >= 2 {
        match db.log_commands_batch(batch) {
            Ok(()) => {
                trace!(count = batch_len, "Batch insert succeeded");
            }
            Err(e) => {
                warn!(
                    error = %e,
                    batch_size = batch_len,
                    "Batch insert failed, falling back to individual inserts"
                );
                // Fallback to individual inserts on error
                let mut success_count = 0;
                let mut error_count = 0;
                for entry in batch.iter() {
                    match db.log_command(entry) {
                        Ok(_id) => success_count += 1,
                        Err(insert_err) => {
                            error_count += 1;
                            // Log first few errors, then summarize
                            if error_count <= 3 {
                                error!(
                                    error = %insert_err,
                                    command = %entry.command,
                                    "Failed to insert history entry"
                                );
                            }
                        }
                    }
                }
                if error_count > 3 {
                    error!(
                        total_errors = error_count,
                        "Additional history insert errors suppressed"
                    );
                }
                if error_count > 0 {
                    warn!(
                        success = success_count,
                        failed = error_count,
                        "History batch recovery completed with errors"
                    );
                }
            }
        }
    } else {
        // Single entry, use regular insert
        for entry in batch.iter() {
            match db.log_command(entry) {
                Ok(_id) => trace!(command = %entry.command, "Inserted history entry"),
                Err(e) => error!(
                    error = %e,
                    command = %entry.command,
                    "Failed to insert history entry"
                ),
            }
        }
    }

    batch.clear();
}

/// Check if pruning is needed and perform it.
fn check_and_prune(db: &HistoryDb, retention_days: u32) {
    // Check if enough time has passed since last prune
    match db.should_auto_prune() {
        Ok(true) => {
            debug!(retention_days = retention_days, "Starting auto-prune");
            match db.prune_older_than_days(u64::from(retention_days), false) {
                Ok(pruned_count) => {
                    debug!(pruned = pruned_count, "Auto-prune completed");
                    if let Err(e) = db.record_prune_timestamp() {
                        warn!(error = %e, "Failed to record prune timestamp");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Auto-prune failed");
                }
            }
        }
        Ok(false) => {
            trace!("Auto-prune not needed yet");
        }
        Err(e) => {
            warn!(error = %e, "Failed to check if auto-prune is needed");
        }
    }
}

fn redact_for_history(command: &str, mode: HistoryRedactionMode) -> String {
    match mode {
        HistoryRedactionMode::None => command.to_string(),
        HistoryRedactionMode::Full => "[REDACTED]".to_string(),
        HistoryRedactionMode::Pattern => {
            let config = RedactionConfig {
                enabled: true,
                mode: RedactionMode::Arguments,
                ..Default::default()
            };
            crate::logging::redact_command(command, &config)
        }
    }
}

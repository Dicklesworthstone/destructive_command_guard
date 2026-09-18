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
mod sqlite;

use crate::config::{HistoryConfig, HistoryRedactionMode, resolve_config_path_value};
use crate::logging::{RedactionConfig, RedactionMode};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, error, trace, warn};

pub use schema::{
    AgentStat, BackupResult, CURRENT_SCHEMA_VERSION, CheckResult, CommandEntry,
    DEFAULT_DB_FILENAME, ExportFilters, ExportOptions, ExportedData, FrequentBlock,
    HistoryAnalyzer, HistoryDb, HistoryError, HistoryStats, InteractiveAllowlistAuditEntry,
    InteractiveAllowlistOptionType, Outcome, OutcomeStats, PackEffectivenessAnalysis,
    PackRecommendation, PathCluster, PatternEffectiveness, PatternStat, PerformanceStats,
    PotentialGap, ProjectStat, RecommendationType, RuleMetrics, RuleTrend, StatsTrends,
    SuggestionAction, SuggestionAuditEntry, SuggestionCandidate,
};
pub use sqlite::{Connection as HistoryConnection, Row as HistoryRow, SqliteValue};

/// Environment variable to override the history database path.
pub const ENV_HISTORY_DB_PATH: &str = "DCG_HISTORY_DB";

/// Environment variable to disable history collection entirely.
pub const ENV_HISTORY_DISABLED: &str = "DCG_HISTORY_DISABLED";

/// Opt in to terse history lifecycle diagnostics on stderr (`1` or `true`).
///
/// These report acknowledgement deadlines and intentional busy drops without
/// recording commands or changing the hook's timeout, retry, or drop policy.
/// They also let subprocess persistence tests distinguish a known best-effort
/// omission from unexplained data loss. Normal robot/hook output stays silent.
pub const ENV_HISTORY_DIAGNOSTICS: &str = "DCG_HISTORY_DIAGNOSTICS";

fn history_diagnostic(status: &str, detail: std::fmt::Arguments<'_>) {
    if env::var(ENV_HISTORY_DIAGNOSTICS)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
    {
        use std::io::Write as _;
        // Diagnostics must never turn a closed stderr pipe into a hook panic.
        let _ = writeln!(std::io::stderr(), "[dcg-history] status={status} {detail}");
    }
}

/// Whether [`ENV_HISTORY_DISABLED`] is set to `1` or `true` (case-insensitive).
#[must_use]
pub fn history_disabled_by_env() -> bool {
    env::var(ENV_HISTORY_DISABLED)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Which rule selected the history database path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryPathSource {
    /// The `DCG_HISTORY_DB` environment variable.
    Environment,
    /// `[history] database_path` from the loaded configuration.
    Config,
    /// An existing database at the pre-0.15 location beside `config.toml`.
    LegacyConfigDir,
    /// The platform state directory: `$XDG_STATE_HOME/dcg` or
    /// `~/.local/state/dcg` on Unix, `%LOCALAPPDATA%\dcg` on Windows.
    Default,
}

impl HistoryPathSource {
    /// Short human-readable label for diagnostics.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Environment => "DCG_HISTORY_DB",
            Self::Config => "[history] database_path",
            Self::LegacyConfigDir => "legacy config-directory location",
            Self::Default => "default state directory",
        }
    }
}

/// A history database path together with the rule that selected it.
///
/// Every reader and writer of the history database must go through
/// [`ResolvedHistoryPath::resolve`] so the hook, `dcg history`, `dcg stats`,
/// and `dcg doctor` all agree on one file. Precedence, highest first:
///
/// 1. `DCG_HISTORY_DB` (non-empty; `~` expanded, relative paths resolved
///    against the current directory).
/// 2. `[history] database_path` in the effective configuration.
/// 3. An existing `history.db` beside `config.toml` (the location every
///    release before 0.15 wrote to). It is honored, never moved, so an
///    upgrade keeps its data.
/// 4. The platform state directory. History is state, not configuration, so
///    it no longer defaults into `~/.config/dcg`; sandboxes that mount the
///    config directory read-only keep working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHistoryPath {
    /// The database file path.
    pub path: PathBuf,
    /// Which rule selected `path`.
    pub source: HistoryPathSource,
}

impl ResolvedHistoryPath {
    /// Resolve the history database path for `config`.
    #[must_use]
    pub fn resolve(config: &HistoryConfig) -> Self {
        Self::from_parts(
            env::var(ENV_HISTORY_DB_PATH).ok().as_deref(),
            config.expanded_database_path(),
            existing_legacy_db_path(),
            default_state_db_path(),
        )
    }

    /// Resolve without a loaded configuration (env, legacy, then default).
    #[must_use]
    pub fn resolve_without_config() -> Self {
        Self::from_parts(
            env::var(ENV_HISTORY_DB_PATH).ok().as_deref(),
            None,
            existing_legacy_db_path(),
            default_state_db_path(),
        )
    }

    fn from_parts(
        env_override: Option<&str>,
        config_path: Option<PathBuf>,
        existing_legacy: Option<PathBuf>,
        default_path: PathBuf,
    ) -> Self {
        let cwd = env::current_dir().ok();
        if let Some(path) =
            env_override.and_then(|raw| resolve_config_path_value(raw, cwd.as_deref()))
        {
            return Self {
                path,
                source: HistoryPathSource::Environment,
            };
        }
        if let Some(path) = config_path {
            return Self {
                path,
                source: HistoryPathSource::Config,
            };
        }
        if let Some(path) = existing_legacy {
            return Self {
                path,
                source: HistoryPathSource::LegacyConfigDir,
            };
        }
        Self {
            path: default_path,
            source: HistoryPathSource::Default,
        }
    }
}

/// The pre-0.15 database location, if a database already exists there.
///
/// Mirrors the config-directory search in `Config::user_config_path`:
/// `$XDG_CONFIG_HOME`, then `~/.config`, then the platform-native config
/// directory. Only an existing *file* counts; an empty directory does not pin
/// new installs to the old location.
fn existing_legacy_db_path() -> Option<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::with_capacity(3);
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        let xdg = PathBuf::from(xdg);
        if xdg.is_absolute() {
            bases.push(xdg);
        }
    }
    if let Some(home) = dirs::home_dir() {
        bases.push(home.join(".config"));
    }
    if let Some(native) = dirs::config_dir() {
        bases.push(native);
    }
    bases
        .into_iter()
        .map(|base| base.join("dcg").join(DEFAULT_DB_FILENAME))
        .find(|candidate| candidate.is_file())
}

/// The default database location for new installs.
fn default_state_db_path() -> PathBuf {
    state_db_path_from(
        env::var_os("XDG_STATE_HOME").as_deref(),
        dirs::home_dir().as_deref(),
        dirs::data_local_dir().as_deref(),
    )
}

/// Pure form of [`default_state_db_path`] for tests.
///
/// Unix: `$XDG_STATE_HOME/dcg/history.db` when set to an absolute path, else
/// `~/.local/state/dcg/history.db` (the XDG Base Directory default for state
/// such as logs and history). Windows: `%LOCALAPPDATA%\dcg\history.db`.
fn state_db_path_from(
    xdg_state_home: Option<&std::ffi::OsStr>,
    home: Option<&Path>,
    windows_local_data: Option<&Path>,
) -> PathBuf {
    let home_state = || home.map(|h| h.join(".local").join("state"));
    let base = if cfg!(windows) {
        windows_local_data
            .map(Path::to_path_buf)
            .or_else(home_state)
    } else {
        xdg_state_home
            .map(Path::new)
            .filter(|p| p.is_absolute())
            .map(Path::to_path_buf)
            .or_else(home_state)
    };
    base.unwrap_or_else(|| PathBuf::from(".local").join("state"))
        .join("dcg")
        .join(DEFAULT_DB_FILENAME)
}

enum HistoryMessage {
    Entry(Box<CommandEntry>),
    Flush(mpsc::Sender<()>),
    Shutdown(mpsc::Sender<()>),
}

/// Configuration for the history worker thread.
#[derive(Clone)]
struct WorkerConfig {
    batch_size: usize,
    flush_interval: Duration,
    auto_prune: bool,
    retention_days: u32,
    prune_check_interval: Duration,
    max_size_bytes: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            batch_size: 50,
            flush_interval: Duration::from_millis(100),
            auto_prune: false,
            retention_days: 90,
            prune_check_interval: Duration::from_secs(24 * 3600),
            max_size_bytes: 500 * 1024 * 1024,
        }
    }
}

impl From<&HistoryConfig> for WorkerConfig {
    fn from(config: &HistoryConfig) -> Self {
        Self {
            batch_size: config.batch_size.max(1) as usize,
            flush_interval: Duration::from_millis(u64::from(config.batch_flush_interval_ms.max(1))),
            auto_prune: config.auto_prune,
            retention_days: config
                .retention_days
                .clamp(1, HistoryConfig::MAX_RETENTION_DAYS),
            prune_check_interval: Duration::from_secs(
                u64::from(config.prune_check_interval_hours.max(1)) * 3600,
            ),
            max_size_bytes: u64::from(config.max_size_mb.max(1)).saturating_mul(1024 * 1024),
        }
    }
}

#[derive(Clone)]
pub struct HistoryFlushHandle {
    sender: mpsc::Sender<HistoryMessage>,
}

impl HistoryFlushHandle {
    /// Request a flush and wait up to the hook-safe bounded timeout.
    ///
    /// History is best-effort telemetry, so lock contention or a stalled
    /// storage worker may cause this to return before the write lands.
    pub fn flush_sync(&self) {
        let _ = self.flush_sync_with_timeout(Duration::from_millis(40));
    }

    /// Request a flush and wait for at most `timeout`.
    ///
    /// Returns `true` only when the worker acknowledged that every entry
    /// queued before this request was processed. Processing can intentionally
    /// drop best-effort telemetry; this is not a durability acknowledgement.
    #[must_use]
    pub fn flush_sync_with_timeout(&self, timeout: Duration) -> bool {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.sender.send(HistoryMessage::Flush(ack_tx)).is_ok()
            && ack_rx.recv_timeout(timeout).is_ok()
    }
}

/// Asynchronous history writer with write batching support.
pub struct HistoryWriter {
    sender: Option<mpsc::Sender<HistoryMessage>>,
    handle: Option<thread::JoinHandle<()>>,
    redaction_mode: HistoryRedactionMode,
    session_id: String,
    wait_for_worker_on_drop: bool,
    drop_wait_deadline: Option<Instant>,
}

impl HistoryWriter {
    /// Create a new history writer.
    ///
    /// The database path is passed to the worker thread, which opens the
    /// connection itself. This keeps all connection use on the dedicated
    /// history thread.
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
                        let status = if is_contention_error(&e) {
                            "busy_drop"
                        } else {
                            "storage_error"
                        };
                        history_diagnostic(status, format_args!("phase=open"));
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
                history_diagnostic("worker_error", format_args!("phase=spawn"));
                return Self::disabled();
            }
        };

        Self {
            sender: Some(sender),
            handle: Some(handle),
            redaction_mode: config.redaction_mode,
            session_id,
            wait_for_worker_on_drop: true,
            drop_wait_deadline: None,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            sender: None,
            handle: None,
            redaction_mode: HistoryRedactionMode::Pattern,
            session_id: String::new(),
            wait_for_worker_on_drop: true,
            drop_wait_deadline: None,
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

    /// Request a flush and wait up to the hook-safe bounded timeout.
    pub fn flush_sync(&self) {
        if let Some(handle) = self.flush_handle() {
            handle.flush_sync();
        }
    }

    /// Request a flush and wait for at most `timeout`.
    ///
    /// Returns `true` for a disabled writer or when the storage worker
    /// acknowledges processing before the deadline, not necessarily persistence.
    #[must_use]
    pub fn flush_sync_with_timeout(&self, timeout: Duration) -> bool {
        self.flush_handle()
            .is_none_or(|handle| handle.flush_sync_with_timeout(timeout))
    }

    /// Queue normal worker shutdown without waiting for storage during drop.
    ///
    /// Deadline paths call this only after their protocol response has been
    /// written and flushed. When the worker is still connected, its channel
    /// retains every queued entry followed by `Shutdown`; a wedged database can
    /// no longer keep the hook process alive after the safety budget is already
    /// exhausted.
    pub fn detach_worker_on_drop(&mut self) {
        self.wait_for_worker_on_drop = false;
    }

    /// Bound the normal drop wait to a budget measured from this call.
    ///
    /// Hook mode uses the evaluator's remaining absolute deadline so history
    /// shutdown can never extend a safety decision past its total budget.
    pub fn limit_drop_wait_to(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.drop_wait_deadline = Some(now.checked_add(timeout).unwrap_or(now));
    }
}

impl Drop for HistoryWriter {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let (ack_tx, ack_rx) = mpsc::channel();
            if sender.send(HistoryMessage::Shutdown(ack_tx)).is_ok() && self.wait_for_worker_on_drop
            {
                if let Some(deadline) = self.drop_wait_deadline {
                    // Hook mode never lets best-effort telemetry extend the
                    // guarded decision beyond its absolute deadline.
                    let started = Instant::now();
                    let timeout = deadline.saturating_duration_since(started);
                    let status = match ack_rx.recv_timeout(timeout) {
                        Ok(()) => "shutdown_complete",
                        Err(mpsc::RecvTimeoutError::Timeout) => "shutdown_timeout",
                        Err(mpsc::RecvTimeoutError::Disconnected) => "worker_disconnected",
                    };
                    history_diagnostic(
                        status,
                        format_args!(
                            "timeout_ms={} elapsed_ms={}",
                            timeout.as_millis(),
                            started.elapsed().as_millis()
                        ),
                    );
                } else {
                    // Library and CLI callers without a hook deadline receive
                    // the conventional writer guarantee: queued entries are
                    // drained before Drop returns.
                    let _ = ack_rx.recv();
                }
            }
        }

        if self.wait_for_worker_on_drop && self.drop_wait_deadline.is_none() {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        } else {
            // Hook deadlines and explicit detach requests must not inherit an
            // unbounded scheduler or storage wait.
            drop(self.handle.take());
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

/// No timer is armed for an empty batch unless periodic pruning is enabled.
/// In particular, an expired flush timer must not make an idle or disabled
/// worker poll the channel with a zero timeout forever.
fn history_receive_timeout(
    config: &WorkerConfig,
    batch_empty: bool,
    history_disabled: bool,
    last_flush: Instant,
    last_prune_check: Instant,
    now: Instant,
) -> Option<Duration> {
    if history_disabled {
        return None;
    }
    let flush = (!batch_empty).then(|| {
        config
            .flush_interval
            .saturating_sub(now.saturating_duration_since(last_flush))
    });
    let prune = config.auto_prune.then(|| {
        config
            .prune_check_interval
            .saturating_sub(now.saturating_duration_since(last_prune_check))
    });
    match (flush, prune) {
        (Some(flush), Some(prune)) => Some(flush.min(prune)),
        (Some(timeout), None) | (None, Some(timeout)) => Some(timeout),
        (None, None) => None,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn history_worker(
    db: HistoryDb,
    receiver: mpsc::Receiver<HistoryMessage>,
    config: WorkerConfig,
) {
    run_history_worker(db, config, |timeout| match timeout {
        Some(timeout) => receiver.recv_timeout(timeout),
        None => receiver
            .recv()
            .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
    });
}

/// Keep receipt of the next message separate from processing it. Besides
/// allowing deterministic mailbox tests with real SQLite, this makes the
/// flush barrier explicit: never consume messages after a flush before its ack.
fn run_history_worker(
    mut db: HistoryDb,
    config: WorkerConfig,
    mut receive: impl FnMut(Option<Duration>) -> Result<HistoryMessage, mpsc::RecvTimeoutError>,
) {
    let mut batch: Vec<CommandEntry> = Vec::with_capacity(config.batch_size);
    let mut last_flush = Instant::now();
    let mut last_prune_check = Instant::now();
    let db_path = db.path().map(std::path::Path::to_path_buf);

    // Reclaim expired rows before deciding whether an existing database is
    // irreducibly over its hard cap. Otherwise a database composed mostly of
    // expired data can disable this long-lived writer even though pruning
    // immediately brings it back under the configured limit.
    if config.auto_prune {
        check_and_prune(&db, config.retention_days);
        last_prune_check = Instant::now();
    }

    let mut history_disabled = match db.enforce_size_limit(config.max_size_bytes) {
        Ok(true) => false,
        Ok(false) => {
            warn!(
                max_size_bytes = config.max_size_bytes,
                "History database already exceeds max_size_mb with live data; disabling writes"
            );
            true
        }
        Err(e) => {
            error!(
                error = %e,
                max_size_bytes = config.max_size_bytes,
                "Failed to enforce history max_size_mb; disabling writes"
            );
            history_diagnostic("storage_error", format_args!("phase=size_limit"));
            true
        }
    };

    loop {
        let timeout = history_receive_timeout(
            &config,
            batch.is_empty(),
            history_disabled,
            last_flush,
            last_prune_check,
            Instant::now(),
        );
        // recv_timeout(0) still returns a buffered message. Service an expired
        // timer before receiving again, so a constantly readable channel cannot
        // starve a partial-batch flush or periodic maintenance.
        let message = if timeout == Some(Duration::ZERO) {
            Err(mpsc::RecvTimeoutError::Timeout)
        } else {
            receive(timeout)
        };
        match message {
            Ok(HistoryMessage::Entry(entry)) => {
                if history_disabled {
                    continue;
                }
                if batch.is_empty() {
                    // Measure batch age from its first entry, not worker
                    // startup, and do not postpone it for subsequent entries.
                    last_flush = Instant::now();
                }
                batch.push(*entry);

                if batch.len() >= config.batch_size {
                    flush_batch_with_recovery(
                        &mut db,
                        &mut batch,
                        db_path.as_ref(),
                        &mut history_disabled,
                        config.max_size_bytes,
                    );
                    last_flush = Instant::now();
                }
            }
            Ok(HistoryMessage::Flush(ack)) => {
                // mpsc is FIFO: every entry queued before this marker has
                // already been handled. Draining *later* messages here makes
                // the barrier a moving target under sustained producers.
                flush_batch_with_recovery(
                    &mut db,
                    &mut batch,
                    db_path.as_ref(),
                    &mut history_disabled,
                    config.max_size_bytes,
                );
                last_flush = Instant::now();
                let _ = ack.send(());
            }
            Ok(HistoryMessage::Shutdown(ack)) => {
                // HistoryWriter is the only entry producer, and queues this
                // marker after its final entry. Retained flush handles cannot
                // extend shutdown by submitting requests after the marker.
                flush_batch_with_recovery(
                    &mut db,
                    &mut batch,
                    db_path.as_ref(),
                    &mut history_disabled,
                    config.max_size_bytes,
                );
                // This acknowledgement is also a connection-close barrier.
                // Do not add an exclusive TRUNCATE checkpoint to hook shutdown.
                drop(db);
                let _ = ack.send(());
                return;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if !batch.is_empty() && last_flush.elapsed() >= config.flush_interval {
                    flush_batch_with_recovery(
                        &mut db,
                        &mut batch,
                        db_path.as_ref(),
                        &mut history_disabled,
                        config.max_size_bytes,
                    );
                    last_flush = Instant::now();
                }

                if !history_disabled
                    && config.auto_prune
                    && last_prune_check.elapsed() >= config.prune_check_interval
                {
                    check_and_prune(&db, config.retention_days);
                    last_prune_check = Instant::now();
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                debug!("History channel disconnected, performing final flush");
                flush_batch_with_recovery(
                    &mut db,
                    &mut batch,
                    db_path.as_ref(),
                    &mut history_disabled,
                    config.max_size_bytes,
                );
                if let Err(e) = db.checkpoint_truncate() {
                    warn!(error = %e, "WAL checkpoint failed on channel disconnect");
                }
                break;
            }
        }
    }
}

fn recover_history_db(
    db: &mut HistoryDb,
    db_path: Option<&std::path::PathBuf>,
    max_size_bytes: u64,
) -> bool {
    let Some(path) = db_path else {
        return false;
    };

    match HistoryDb::open(Some(path.clone())) {
        Ok(recovered_db) => match recovered_db.enforce_size_limit(max_size_bytes) {
            Ok(true) => {
                *db = recovered_db;
                true
            }
            Ok(false) => {
                error!(
                    max_size_bytes,
                    path = %path.display(),
                    "Recovered history DB exceeds max_size_mb with live data"
                );
                false
            }
            Err(e) => {
                error!(
                    error = %e,
                    path = %path.display(),
                    "Failed to reapply max_size_mb after history DB recovery"
                );
                false
            }
        },
        Err(e) => {
            error!(
                error = %e,
                path = %path.display(),
                "Failed to recover history DB after fatal storage error"
            );
            false
        }
    }
}

fn flush_batch_with_recovery(
    db: &mut HistoryDb,
    batch: &mut Vec<CommandEntry>,
    db_path: Option<&std::path::PathBuf>,
    history_disabled: &mut bool,
    max_size_bytes: u64,
) {
    if *history_disabled {
        batch.clear();
        return;
    }

    match flush_batch(db, batch) {
        FlushOutcome::Success => {}
        FlushOutcome::Contended => {
            batch.clear();
            debug!("History database is busy; dropped best-effort telemetry batch");
            history_diagnostic("busy_drop", format_args!("phase=write"));
        }
        FlushOutcome::CapacityReached => {
            *history_disabled = true;
            batch.clear();
            warn!("History max_size_mb reached; disabling history writes for this process");
            history_diagnostic("storage_error", format_args!("phase=capacity"));
        }
        FlushOutcome::Fatal => {
            history_diagnostic("storage_error", format_args!("phase=recovery"));
            warn!("Detected fatal history storage error; attempting DB recovery");
            if recover_history_db(db, db_path, max_size_bytes) {
                match flush_batch(db, batch) {
                    FlushOutcome::Success => {
                        debug!("History DB recovery succeeded");
                    }
                    FlushOutcome::Contended => {
                        batch.clear();
                        debug!(
                            "Recovered history database is busy; dropped best-effort telemetry batch"
                        );
                        history_diagnostic("busy_drop", format_args!("phase=recovery"));
                    }
                    FlushOutcome::Fatal => {
                        *history_disabled = true;
                        batch.clear();
                        error!(
                            "History DB remained unusable after recovery; disabling history writes for this process"
                        );
                    }
                    FlushOutcome::CapacityReached => {
                        *history_disabled = true;
                        batch.clear();
                        warn!(
                            "History max_size_mb reached after storage recovery; disabling history writes"
                        );
                    }
                }
            } else {
                *history_disabled = true;
                batch.clear();
                error!(
                    "History DB recovery unavailable; disabling history writes for this process"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushOutcome {
    Success,
    Fatal,
    CapacityReached,
    Contended,
}

fn is_fatal_storage_error(error: &HistoryError) -> bool {
    matches!(
        error,
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseCorrupt
                    | rusqlite::ErrorCode::NotADatabase
                    | rusqlite::ErrorCode::SystemIoFailure
                    | rusqlite::ErrorCode::CannotOpen
                    | rusqlite::ErrorCode::OutOfMemory
            )
    )
}

fn is_capacity_error(error: &HistoryError) -> bool {
    matches!(
        error,
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if code.code == rusqlite::ErrorCode::DiskFull
    )
}

fn is_contention_error(error: &HistoryError) -> bool {
    matches!(
        error,
        HistoryError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

/// Flush the batch to the database.
fn flush_batch(db: &HistoryDb, batch: &mut Vec<CommandEntry>) -> FlushOutcome {
    if batch.is_empty() {
        return FlushOutcome::Success;
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
                if is_contention_error(&e) {
                    debug!(
                        batch_size = batch_len,
                        "History database is busy; dropping best-effort telemetry batch"
                    );
                    return FlushOutcome::Contended;
                }
                if is_capacity_error(&e) {
                    return FlushOutcome::CapacityReached;
                }
                if is_fatal_storage_error(&e) {
                    error!(
                        error = %e,
                        batch_size = batch_len,
                        "Fatal history storage error in batch insert"
                    );
                    return FlushOutcome::Fatal;
                }
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
                            if is_contention_error(&insert_err) {
                                debug!(
                                    "History database became busy during fallback; dropping remaining telemetry"
                                );
                                return FlushOutcome::Contended;
                            }
                            if is_capacity_error(&insert_err) {
                                return FlushOutcome::CapacityReached;
                            }
                            if is_fatal_storage_error(&insert_err) {
                                error!(
                                    error = %insert_err,
                                    command = %entry.command,
                                    "Fatal history storage error in single-row insert"
                                );
                                return FlushOutcome::Fatal;
                            }
                            error_count += 1;
                            history_diagnostic("storage_error", format_args!("phase=insert"));
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
                Err(e) => {
                    if is_contention_error(&e) {
                        debug!("History database is busy; dropping best-effort telemetry entry");
                        return FlushOutcome::Contended;
                    }
                    if is_capacity_error(&e) {
                        return FlushOutcome::CapacityReached;
                    }
                    if is_fatal_storage_error(&e) {
                        error!(
                            error = %e,
                            command = %entry.command,
                            "Fatal history storage error in single-row insert"
                        );
                        return FlushOutcome::Fatal;
                    }
                    error!(
                        error = %e,
                        command = %entry.command,
                        "Failed to insert history entry"
                    );
                    history_diagnostic("storage_error", format_args!("phase=insert"));
                }
            }
        }
    }

    batch.clear();
    FlushOutcome::Success
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
                    if pruned_count > 0 {
                        if let Err(e) = db.vacuum() {
                            warn!(error = %e, "Failed to reclaim pages after auto-prune");
                        }
                        if let Err(e) = db.checkpoint_truncate() {
                            warn!(error = %e, "Failed to truncate WAL after auto-prune");
                        }
                    }
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
            // Secrets first, then argument truncation: truncation only ever
            // shortens *quoted* arguments, so on its own it leaves bare
            // credentials in the store verbatim (issue #386).
            let secrets_redacted = crate::redaction::redact_secrets(command);
            let config = RedactionConfig {
                enabled: true,
                mode: RedactionMode::Arguments,
                ..Default::default()
            };
            crate::logging::redact_command(&secrets_redacted, &config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_and_disabled_workers_have_no_flush_poll_timer() {
        let config = WorkerConfig::default();
        let started = Instant::now();
        let much_later = started + Duration::from_secs(7 * 24 * 3600);
        assert_eq!(
            history_receive_timeout(&config, true, false, started, started, much_later),
            None,
            "an expired empty-batch timer must not busy-spin"
        );
        let config = WorkerConfig {
            auto_prune: true,
            ..config
        };
        assert_eq!(
            history_receive_timeout(&config, true, true, started, started, much_later),
            None,
            "a disabled worker must wait for messages, not run maintenance"
        );
    }

    #[test]
    fn pending_batch_timer_expires_without_a_quiet_channel() {
        let config = WorkerConfig::default();
        let started = Instant::now();
        assert_eq!(
            history_receive_timeout(&config, false, false, started, started, started),
            Some(config.flush_interval)
        );
        assert_eq!(
            history_receive_timeout(
                &config,
                false,
                false,
                started,
                started,
                started + config.flush_interval
            ),
            Some(Duration::ZERO),
            "the batch deadline must be serviced even when a message is ready"
        );
    }

    #[test]
    fn idle_pruning_and_batch_flush_use_the_earliest_deadline() {
        let config = WorkerConfig {
            auto_prune: true,
            flush_interval: Duration::from_secs(10),
            prune_check_interval: Duration::from_secs(30),
            ..WorkerConfig::default()
        };
        let started = Instant::now();
        let now = started + Duration::from_secs(25);
        assert_eq!(
            history_receive_timeout(&config, true, false, now, started, now),
            Some(Duration::from_secs(5)),
            "an idle writer must still wake for pruning"
        );
        assert_eq!(
            history_receive_timeout(&config, false, false, now, started, now),
            Some(Duration::from_secs(5)),
            "maintenance must not wait for a younger batch"
        );
        assert_eq!(
            history_receive_timeout(&config, false, false, now, now, now),
            Some(Duration::from_secs(10)),
            "flushing must not wait for a later maintenance check"
        );
    }

    fn persisted_test_commands(path: &Path) -> Vec<String> {
        let connection = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open read-only observer");
        let mut statement = connection
            .prepare("SELECT command FROM commands ORDER BY id")
            .expect("prepare persisted command query");
        statement
            .query_map([], |row| row.get(0))
            .expect("query persisted commands")
            .collect::<Result<Vec<String>, _>>()
            .expect("read persisted commands")
    }

    #[test]
    fn flush_acknowledges_its_fifo_prefix_before_receiving_more_work() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("flush-prefix.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        // More than several batches: a flush must cover *all* prior entries,
        // but neither a later entry nor a later control message.
        for index in 0..257 {
            sender
                .send(HistoryMessage::Entry(Box::new(CommandEntry {
                    command: format!("before-{index}"),
                    ..Default::default()
                })))
                .unwrap();
        }
        let (first_tx, first_rx) = mpsc::channel();
        let (empty_tx, empty_rx) = mpsc::channel();
        let (last_tx, last_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        sender.send(HistoryMessage::Flush(first_tx)).unwrap();
        sender.send(HistoryMessage::Flush(empty_tx)).unwrap();
        sender
            .send(HistoryMessage::Entry(Box::new(CommandEntry {
                command: "after-marker".to_string(),
                ..Default::default()
            })))
            .unwrap();
        sender.send(HistoryMessage::Flush(last_tx)).unwrap();
        sender.send(HistoryMessage::Shutdown(shutdown_tx)).unwrap();
        drop(sender);

        let mut received = 0;
        run_history_worker(db, WorkerConfig::default(), |_| {
            match received {
                258 => {
                    first_rx.try_recv().expect("ack before the next receive");
                    let expected: Vec<_> = (0..257).map(|i| format!("before-{i}")).collect();
                    assert_eq!(persisted_test_commands(&path), expected);
                }
                259 => {
                    empty_rx
                        .try_recv()
                        .expect("consecutive empty flush acknowledged");
                }
                261 => {
                    last_rx
                        .try_recv()
                        .expect("later flush acknowledged independently");
                    assert_eq!(persisted_test_commands(&path).len(), 258);
                }
                _ => {}
            }
            received += 1;
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        });
        assert_eq!(received, 262);
        shutdown_rx.try_recv().expect("shutdown acknowledged");
        assert_eq!(
            persisted_test_commands(&path).last().unwrap(),
            "after-marker"
        );
    }

    #[test]
    fn expired_batch_flushes_before_receiving_an_already_queued_message() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ready-channel.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        sender
            .send(HistoryMessage::Entry(Box::new(CommandEntry {
                command: "timer-flush".to_string(),
                ..Default::default()
            })))
            .unwrap();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        sender.send(HistoryMessage::Shutdown(shutdown_tx)).unwrap();
        drop(sender);
        let config = WorkerConfig {
            // An already-expired timer makes the ordering deterministic:
            // no sleeps, throughput thresholds, or scheduler assumptions.
            flush_interval: Duration::ZERO,
            ..WorkerConfig::default()
        };
        let mut received = 0;
        run_history_worker(db, config, |timeout| {
            assert_eq!(timeout, None, "empty batches must block rather than poll");
            if received == 1 {
                assert_eq!(persisted_test_commands(&path), vec!["timer-flush"]);
            }
            received += 1;
            receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        });
        assert_eq!(received, 2);
        shutdown_rx.try_recv().unwrap();
    }

    #[test]
    fn shutdown_does_not_acknowledge_requests_queued_after_its_marker() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("shutdown-marker.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        sender
            .send(HistoryMessage::Entry(Box::new(CommandEntry {
                command: "final-entry".to_string(),
                ..Default::default()
            })))
            .unwrap();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let (late_tx, late_rx) = mpsc::channel();
        sender.send(HistoryMessage::Shutdown(shutdown_tx)).unwrap();
        sender.send(HistoryMessage::Flush(late_tx)).unwrap();
        // Retaining this sender models a cloned flush handle at writer drop.
        history_worker(db, receiver, WorkerConfig::default());
        shutdown_rx.try_recv().expect("shutdown completed");
        assert_eq!(
            late_rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected),
            "late control requests must not extend the shutdown barrier"
        );
        assert_eq!(persisted_test_commands(&path), vec!["final-entry"]);
        // A mode change requires all other connections to be gone. This is
        // checked after the shutdown ack, not after a grace-period sleep.
        let connection = rusqlite::Connection::open(&path).unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .expect("shutdown must close the writer connection");
        assert_eq!(mode, "delete");
        drop(sender);
    }

    #[test]
    fn channel_disconnect_flushes_the_final_partial_batch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("disconnect.db");
        let db = HistoryDb::open(Some(path.clone())).unwrap();
        let (sender, receiver) = mpsc::channel();
        for index in 0..3 {
            sender
                .send(HistoryMessage::Entry(Box::new(CommandEntry {
                    command: format!("last-{index}"),
                    ..Default::default()
                })))
                .unwrap();
        }
        drop(sender);
        history_worker(db, receiver, WorkerConfig::default());
        assert_eq!(
            persisted_test_commands(&path),
            vec!["last-0", "last-1", "last-2"]
        );
    }

    #[test]
    fn flush_timeout_does_not_consume_or_replay_queued_entries() {
        let (sender, receiver) = mpsc::channel();
        let flush = HistoryFlushHandle {
            sender: sender.clone(),
        };
        sender
            .send(HistoryMessage::Entry(Box::new(CommandEntry {
                command: "queued exactly once".to_string(),
                ..Default::default()
            })))
            .unwrap();

        // No worker is running: this must time out, regardless of host speed.
        assert!(!flush.flush_sync_with_timeout(Duration::ZERO));
        let HistoryMessage::Entry(entry) = receiver.try_recv().unwrap() else {
            panic!("timing out must leave the original entry queued");
        };
        assert_eq!(entry.command, "queued exactly once");
        let HistoryMessage::Flush(ack) = receiver.try_recv().unwrap() else {
            panic!("flush request must follow the entry");
        };
        assert!(ack.send(()).is_err(), "expired waiter must be disconnected");
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    /// Issue #386: `redaction_mode = "pattern"` is documented as redacting
    /// sensitive values, but for a long time it only truncated *quoted*
    /// arguments, so bare credentials were stored byte-for-byte. Every canary
    /// below is synthetic.
    #[test]
    fn pattern_mode_strips_bare_and_quoted_secrets() {
        let command = "deploy AKIAABCDEFGHIJKLMNOP \
             ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \
             sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ \
             \"sk_live_QUOTEDLONGTOKENQUOTEDLONGTOKENQUOTEDLONGTOKENQUOTEDLONGTOKEN\"";
        let stored = redact_for_history(command, HistoryRedactionMode::Pattern);
        for canary in [
            "AKIAABCDEFGHIJKLMNOP",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "sk_live_QUOTEDLONGTOKEN",
        ] {
            assert!(
                !stored.contains(canary),
                "canary {canary} survived pattern redaction: {stored}"
            );
        }
        assert!(stored.starts_with("deploy "), "{stored}");
    }

    #[test]
    fn none_mode_stores_verbatim_and_full_mode_stores_nothing() {
        let command = "psql postgres://admin:hunter2hunter2@db.internal/app";
        assert_eq!(
            redact_for_history(command, HistoryRedactionMode::None),
            command
        );
        assert_eq!(
            redact_for_history(command, HistoryRedactionMode::Full),
            "[REDACTED]"
        );
        let pattern = redact_for_history(command, HistoryRedactionMode::Pattern);
        assert!(!pattern.contains("hunter2hunter2"), "{pattern}");
    }

    #[test]
    fn worker_config_defensively_clamps_zero_runtime_limits() {
        let history = HistoryConfig {
            retention_days: 0,
            max_size_mb: 0,
            prune_check_interval_hours: 0,
            batch_size: 0,
            batch_flush_interval_ms: 0,
            ..HistoryConfig::default()
        };
        let worker = WorkerConfig::from(&history);
        assert_eq!(worker.retention_days, 1);
        assert_eq!(worker.max_size_bytes, 1024 * 1024);
        assert_eq!(worker.prune_check_interval, Duration::from_secs(3600));
        assert_eq!(worker.batch_size, 1);
        assert_eq!(worker.flush_interval, Duration::from_millis(1));
    }

    #[test]
    fn detached_drop_never_waits_for_history_worker() {
        let (release_tx, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            // Bound a future regression: if Drop accidentally rejoins this
            // worker, the test fails after two seconds instead of hanging the
            // entire suite forever.
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
        });
        let mut writer = HistoryWriter {
            sender: None,
            handle: Some(handle),
            redaction_mode: HistoryRedactionMode::Pattern,
            session_id: String::new(),
            wait_for_worker_on_drop: true,
            drop_wait_deadline: None,
        };
        writer.detach_worker_on_drop();

        let started = Instant::now();
        drop(writer);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "detached history drop waited for its worker"
        );

        let _ = release_tx.send(());
    }

    // ---- history database path resolution (#381) ----

    fn abs(segments: &[&str]) -> PathBuf {
        let mut path = if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/")
        };
        path.extend(segments);
        path
    }

    #[test]
    fn env_override_beats_config_legacy_and_default() {
        let env_path = abs(&["srv", "env.db"]);
        let resolved = ResolvedHistoryPath::from_parts(
            Some(env_path.to_str().unwrap()),
            Some(abs(&["cfg", "config.db"])),
            Some(abs(&["home", ".config", "dcg", "history.db"])),
            abs(&["home", ".local", "state", "dcg", "history.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Environment);
        assert_eq!(resolved.path, env_path);
    }

    #[test]
    fn blank_env_override_is_ignored() {
        let config_path = abs(&["cfg", "config.db"]);
        let resolved = ResolvedHistoryPath::from_parts(
            Some("   "),
            Some(config_path.clone()),
            None,
            abs(&["default.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Config);
        assert_eq!(resolved.path, config_path);
    }

    #[test]
    fn env_override_expands_tilde_and_relative_paths() {
        let Some(home) = dirs::home_dir() else {
            return;
        };
        let resolved = ResolvedHistoryPath::from_parts(
            Some("~/dcg-hist.db"),
            None,
            None,
            abs(&["default.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Environment);
        assert_eq!(resolved.path, home.join("dcg-hist.db"));

        let relative =
            ResolvedHistoryPath::from_parts(Some("rel/hist.db"), None, None, abs(&["default.db"]));
        assert!(
            relative.path.is_absolute(),
            "relative DCG_HISTORY_DB must resolve against the working directory: {}",
            relative.path.display()
        );
        assert!(relative.path.ends_with(Path::new("rel").join("hist.db")));
    }

    #[test]
    fn config_beats_legacy_and_default() {
        let config_path = abs(&["cfg", "config.db"]);
        let resolved = ResolvedHistoryPath::from_parts(
            None,
            Some(config_path.clone()),
            Some(abs(&["legacy.db"])),
            abs(&["default.db"]),
        );
        assert_eq!(resolved.source, HistoryPathSource::Config);
        assert_eq!(resolved.path, config_path);
    }

    #[test]
    fn existing_legacy_database_beats_default() {
        let legacy = abs(&["home", ".config", "dcg", "history.db"]);
        let resolved =
            ResolvedHistoryPath::from_parts(None, None, Some(legacy.clone()), abs(&["default.db"]));
        assert_eq!(resolved.source, HistoryPathSource::LegacyConfigDir);
        assert_eq!(resolved.path, legacy);
    }

    #[test]
    fn default_is_used_when_nothing_else_applies() {
        let default = abs(&["home", ".local", "state", "dcg", "history.db"]);
        let resolved = ResolvedHistoryPath::from_parts(None, None, None, default.clone());
        assert_eq!(resolved.source, HistoryPathSource::Default);
        assert_eq!(resolved.path, default);
    }

    #[test]
    fn default_state_path_prefers_xdg_state_home_on_unix() {
        let home = abs(&["home", "u"]);
        let xdg = abs(&["custom", "state"]);
        let local = abs(&["appdata", "local"]);
        let path = state_db_path_from(Some(xdg.as_os_str()), Some(&home), Some(&local));
        if cfg!(windows) {
            assert_eq!(path, local.join("dcg").join(DEFAULT_DB_FILENAME));
        } else {
            assert_eq!(path, xdg.join("dcg").join(DEFAULT_DB_FILENAME));
        }
    }

    #[test]
    fn default_state_path_falls_back_to_home_local_state() {
        let home = abs(&["home", "u"]);
        let expected = home
            .join(".local")
            .join("state")
            .join("dcg")
            .join(DEFAULT_DB_FILENAME);
        assert_eq!(state_db_path_from(None, Some(&home), None), expected);
        // A relative XDG_STATE_HOME is invalid per the spec and must be ignored.
        assert_eq!(
            state_db_path_from(
                Some(std::ffi::OsStr::new("relative/state")),
                Some(&home),
                None
            ),
            expected
        );
    }

    #[test]
    fn default_state_path_never_lands_in_the_config_directory() {
        let home = abs(&["home", "u"]);
        let path = state_db_path_from(None, Some(&home), Some(&abs(&["local"])));
        assert!(
            !path.starts_with(home.join(".config")),
            "history is state, not configuration: {}",
            path.display()
        );
    }

    #[test]
    fn default_state_path_without_home_is_relative_state_dir() {
        let path = state_db_path_from(None, None, None);
        assert_eq!(
            path,
            PathBuf::from(".local")
                .join("state")
                .join("dcg")
                .join(DEFAULT_DB_FILENAME)
        );
    }

    #[test]
    fn source_labels_are_stable() {
        assert_eq!(HistoryPathSource::Environment.describe(), "DCG_HISTORY_DB");
        assert_eq!(
            HistoryPathSource::Config.describe(),
            "[history] database_path"
        );
        assert_eq!(
            serde_json::to_string(&HistoryPathSource::LegacyConfigDir).unwrap(),
            "\"legacy_config_dir\""
        );
    }
}

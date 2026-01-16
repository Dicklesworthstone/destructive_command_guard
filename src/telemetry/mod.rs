//! Command telemetry database for DCG.
//!
//! This module provides SQLite-based telemetry collection and querying for
//! tracking all commands evaluated by DCG across agent sessions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      TelemetryDb                                 │
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
//! use destructive_command_guard::telemetry::{TelemetryDb, CommandEntry, Outcome};
//!
//! let db = TelemetryDb::open(None)?; // Uses default path
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

use crate::config::{TelemetryConfig, TelemetryRedactionMode};
use crate::logging::{RedactionConfig, RedactionMode};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub use schema::{
    CURRENT_SCHEMA_VERSION, CommandEntry, DEFAULT_DB_FILENAME, Outcome, TelemetryDb, TelemetryError,
};

/// Environment variable to override the telemetry database path.
pub const ENV_TELEMETRY_DB_PATH: &str = "DCG_TELEMETRY_DB";

/// Environment variable to disable telemetry collection entirely.
pub const ENV_TELEMETRY_DISABLED: &str = "DCG_TELEMETRY_DISABLED";

enum TelemetryMessage {
    Entry(Box<CommandEntry>),
    Flush(mpsc::Sender<()>),
    Shutdown,
}

#[derive(Clone)]
pub struct TelemetryFlushHandle {
    sender: mpsc::Sender<TelemetryMessage>,
}

impl TelemetryFlushHandle {
    /// Flush and wait for pending writes to complete.
    pub fn flush_sync(&self) {
        const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.sender.send(TelemetryMessage::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.recv_timeout(FLUSH_TIMEOUT);
        }
    }
}

/// Asynchronous telemetry writer.
pub struct TelemetryWriter {
    sender: Option<mpsc::Sender<TelemetryMessage>>,
    handle: Option<thread::JoinHandle<()>>,
    redaction_mode: TelemetryRedactionMode,
}

impl TelemetryWriter {
    /// Create a new telemetry writer.
    ///
    /// The writer is disabled when `config.enabled` is false.
    #[must_use]
    pub fn new(db: TelemetryDb, config: &TelemetryConfig) -> Self {
        if !config.enabled {
            return Self::disabled();
        }

        let (sender, receiver) = mpsc::channel::<TelemetryMessage>();
        let Ok(handle) = thread::Builder::new()
            .name("dcg-telemetry-writer".to_string())
            .spawn(move || telemetry_worker(db, receiver))
        else {
            // Thread spawn failed - return disabled writer to avoid leaking
            // messages into a channel with no receiver.
            return Self::disabled();
        };

        Self {
            sender: Some(sender),
            handle: Some(handle),
            redaction_mode: config.redaction_mode,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            sender: None,
            handle: None,
            redaction_mode: TelemetryRedactionMode::Pattern,
        }
    }

    #[must_use]
    pub fn flush_handle(&self) -> Option<TelemetryFlushHandle> {
        self.sender.as_ref().map(|sender| TelemetryFlushHandle {
            sender: sender.clone(),
        })
    }

    /// Log a command entry asynchronously.
    pub fn log(&self, mut entry: CommandEntry) {
        entry.command = redact_for_telemetry(&entry.command, self.redaction_mode);
        if let Some(sender) = &self.sender {
            let _ = sender.send(TelemetryMessage::Entry(Box::new(entry)));
        }
    }

    /// Request a flush without waiting for completion.
    pub fn flush(&self) {
        if let Some(sender) = &self.sender {
            let (ack_tx, _ack_rx) = mpsc::channel();
            let _ = sender.send(TelemetryMessage::Flush(ack_tx));
        }
    }

    /// Flush and wait for pending writes to complete.
    pub fn flush_sync(&self) {
        if let Some(handle) = self.flush_handle() {
            handle.flush_sync();
        }
    }
}

impl Drop for TelemetryWriter {
    fn drop(&mut self) {
        self.flush_sync();

        if let Some(sender) = self.sender.take() {
            let _ = sender.send(TelemetryMessage::Shutdown);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn telemetry_worker(db: TelemetryDb, receiver: mpsc::Receiver<TelemetryMessage>) {
    while let Ok(message) = receiver.recv() {
        match message {
            TelemetryMessage::Entry(entry) => {
                let _ = db.log_command(&entry);
            }
            TelemetryMessage::Flush(ack) => {
                let should_shutdown = drain_telemetry_messages(&db, &receiver);
                let _ = ack.send(());
                if should_shutdown {
                    break;
                }
            }
            TelemetryMessage::Shutdown => {
                break;
            }
        }
    }
}

fn drain_telemetry_messages(db: &TelemetryDb, receiver: &mpsc::Receiver<TelemetryMessage>) -> bool {
    let mut shutdown = false;
    for message in receiver.try_iter() {
        match message {
            TelemetryMessage::Entry(entry) => {
                let _ = db.log_command(&entry);
            }
            TelemetryMessage::Flush(ack) => {
                let _ = ack.send(());
            }
            TelemetryMessage::Shutdown => {
                shutdown = true;
            }
        }
    }
    shutdown
}

fn redact_for_telemetry(command: &str, mode: TelemetryRedactionMode) -> String {
    match mode {
        TelemetryRedactionMode::None => command.to_string(),
        TelemetryRedactionMode::Full => "[REDACTED]".to_string(),
        TelemetryRedactionMode::Pattern => {
            let config = RedactionConfig {
                enabled: true,
                mode: RedactionMode::Arguments,
                ..Default::default()
            };
            crate::logging::redact_command(command, &config)
        }
    }
}

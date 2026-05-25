//! Tool call payloads understood by [`crate::Engine`].
//!
//! The engine is tool-aware: instead of receiving a raw shell command, it gets
//! a [`ToolCall`] indicating which tool the agent invoked. This lets the engine
//! enforce mode-specific rules (e.g. `Plan` mode denies `Edit`/`Write` even
//! before pattern matching).
//!
//! # Mapping consumer tool taxonomies
//!
//! Different agent frameworks have different tool catalogs (Claude Code's
//! `Bash`/`Read`/`Edit`/`Write`/`Grep`/`Glob`/…, jcode's much larger set,
//! Codex's `run_terminal_cmd`, Hermes' `terminal`). Consumers map their
//! native tool names onto these five variants:
//!
//! | Native tool | `ToolCall` variant |
//! |-------------|--------------------|
//! | Bash, Shell, run_terminal_cmd, terminal | [`ToolCall::Bash`] |
//! | Read, Glob, Grep, Ls, AgentGrep | [`ToolCall::Read`] |
//! | Edit, MultiEdit, ApplyPatch, HashlineEdit | [`ToolCall::Edit`] |
//! | Write | [`ToolCall::Write`] |
//! | WebSearch, WebFetch, Browser, Network | [`ToolCall::Network`] |

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A tool invocation that the engine should evaluate.
///
/// The variants are intentionally narrow. Most agent tools collapse onto one
/// of these five categories. Consumers that want finer granularity can pass
/// extra metadata through their own layer; the engine itself only uses the
/// payloads exposed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolCall {
    /// Shell command execution.
    Bash {
        /// The command line as the agent intended to run it.
        cmd: String,
    },
    /// In-place edit of an existing file.
    Edit {
        /// Absolute or relative path to the file being edited.
        path: PathBuf,
    },
    /// Create or overwrite a file.
    Write {
        /// Absolute or relative path to the file being written.
        path: PathBuf,
    },
    /// Read a file's contents.
    Read {
        /// Absolute or relative path to the file being read.
        path: PathBuf,
    },
    /// Network operation (fetch, search, browser).
    Network {
        /// Target URL.
        url: String,
        /// HTTP method or operation name (`GET`, `POST`, `fetch`, `search`, …).
        method: String,
    },
}

impl ToolCall {
    /// Returns the path argument if this variant has one.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Edit { path } | Self::Write { path } | Self::Read { path } => Some(path),
            Self::Bash { .. } | Self::Network { .. } => None,
        }
    }

    /// Returns the kind name for logging/serialization.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Bash { .. } => "bash",
            Self::Edit { .. } => "edit",
            Self::Write { .. } => "write",
            Self::Read { .. } => "read",
            Self::Network { .. } => "network",
        }
    }

    /// Convenience constructor for `Bash` calls from anything string-like.
    pub fn bash<S: Into<String>>(cmd: S) -> Self {
        Self::Bash { cmd: cmd.into() }
    }

    /// Convenience constructor for `Read` calls from anything path-like.
    pub fn read<P: Into<PathBuf>>(path: P) -> Self {
        Self::Read { path: path.into() }
    }

    /// Convenience constructor for `Write` calls.
    pub fn write<P: Into<PathBuf>>(path: P) -> Self {
        Self::Write { path: path.into() }
    }

    /// Convenience constructor for `Edit` calls.
    pub fn edit<P: Into<PathBuf>>(path: P) -> Self {
        Self::Edit { path: path.into() }
    }

    /// Convenience constructor for `Network` calls.
    pub fn network<U: Into<String>, M: Into<String>>(url: U, method: M) -> Self {
        Self::Network {
            url: url.into(),
            method: method.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_constructor_round_trip() {
        let tc = ToolCall::bash("git status");
        assert_eq!(tc.kind(), "bash");
        assert_eq!(tc.path(), None);
        match tc {
            ToolCall::Bash { cmd } => assert_eq!(cmd, "git status"),
            _ => panic!("expected Bash variant"),
        }
    }

    #[test]
    fn read_exposes_path() {
        let tc = ToolCall::read("/tmp/data.txt");
        assert_eq!(tc.kind(), "read");
        assert_eq!(tc.path(), Some(Path::new("/tmp/data.txt")));
    }

    #[test]
    fn network_kind_and_no_path() {
        let tc = ToolCall::network("https://example.com", "GET");
        assert_eq!(tc.kind(), "network");
        assert_eq!(tc.path(), None);
    }

    #[test]
    fn json_serialization_uses_kind_tag() {
        let tc = ToolCall::bash("ls");
        let json = serde_json::to_string(&tc).expect("serialize");
        assert!(
            json.contains("\"kind\":\"bash\""),
            "expected kind tag in {json}"
        );
    }
}

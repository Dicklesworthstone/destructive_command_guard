//! `Engine` — top-level entry point that combines [`Mode`], [`ToolCall`],
//! and pack rules into a [`Decision`].
//!
//! # Evaluation order
//!
//! 1. Resolve the effects attributed to the tool call (Tier-A explicit ∪
//!    pack default).
//! 2. Determine whether the tool call's path is under any
//!    [`ProtectedPaths`] entry.
//! 3. Run [`Mode::pre_check`]. Short-circuits for `BypassPermissions`,
//!    `Plan`, and protected-path/dangerous-effects in `AcceptEdits`.
//! 4. Run pack rules (TODO Phase 2): if a destructive pattern matches,
//!    return `Deny` (or `Prompt` for warn-tier rules); otherwise fall
//!    through.
//! 5. Apply the mode's fallthrough policy:
//!    [`Mode::fallthrough_allows`] decides between `Allow` and `Deny`.
//!
//! Phase A delivers a self-contained engine that operates on caller-supplied
//! effect tags and a stub rule layer. Phase 2 wires the existing
//! `dcg::evaluator` into this engine.
//!
//! # Example
//!
//! ```
//! use std::path::PathBuf;
//! use dcg_core::{Engine, EngineConfig, Mode, Session, ToolCall, Effect};
//!
//! let cfg = EngineConfig::builder()
//!     .working_dir(PathBuf::from("/work/project"))
//!     .protected_paths(vec!["~/.ssh".into(), ".git".into()])
//!     .build();
//! let engine = Engine::new(cfg);
//! let mut session = Session::with_working_dir(PathBuf::from("/work/project"));
//!
//! let call = ToolCall::bash("git status");
//! let decision = engine.evaluate(
//!     &mut session,
//!     &call,
//!     Mode::Default,
//!     &[Effect::Read],
//! );
//! assert!(decision.is_allow());
//! ```

use std::path::{Path, PathBuf};

use crate::decision::Decision;
use crate::effect::Effect;
use crate::mode::{Mode, ModePreCheck};
use crate::protected_paths::ProtectedPaths;
use crate::session::Session;
use crate::tool_call::ToolCall;

/// Configuration for [`Engine`].
///
/// Use [`EngineConfig::builder`] to construct one. The engine compiles the
/// protected-path list once at construction time so per-call evaluation
/// avoids string parsing.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub(crate) working_dir: PathBuf,
    pub(crate) protected_paths_raw: Vec<String>,
}

impl EngineConfig {
    /// Start configuring an engine.
    #[must_use]
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::default()
    }

    /// Returns the working directory (used for protected-path anchoring).
    #[must_use]
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// Returns the raw (unexpanded) protected-path entries.
    #[must_use]
    pub fn protected_paths(&self) -> &[String] {
        &self.protected_paths_raw
    }
}

/// Builder for [`EngineConfig`].
#[derive(Debug, Default, Clone)]
pub struct EngineConfigBuilder {
    working_dir: Option<PathBuf>,
    protected_paths: Vec<String>,
}

impl EngineConfigBuilder {
    /// Set the working directory used to anchor relative protected paths.
    #[must_use]
    pub fn working_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Replace the protected-path list.
    #[must_use]
    pub fn protected_paths(mut self, paths: Vec<String>) -> Self {
        self.protected_paths = paths;
        self
    }

    /// Append a single protected-path entry.
    #[must_use]
    pub fn add_protected_path<S: Into<String>>(mut self, path: S) -> Self {
        self.protected_paths.push(path.into());
        self
    }

    /// Finalize the configuration.
    #[must_use]
    pub fn build(self) -> EngineConfig {
        let working_dir = self
            .working_dir
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        EngineConfig {
            working_dir,
            protected_paths_raw: self.protected_paths,
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Top-level command guard.
///
/// Cheaply cloneable: the protected-path list is the only non-trivial state.
#[derive(Debug, Clone)]
pub struct Engine {
    config: EngineConfig,
    protected: ProtectedPaths,
}

impl Engine {
    /// Build a new engine from configuration. Compiles the protected-path
    /// list once.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        let protected = ProtectedPaths::new(
            config.protected_paths_raw.iter().cloned(),
            &config.working_dir,
        );
        Self { config, protected }
    }

    /// Returns the configuration this engine was built from.
    #[must_use]
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Returns the compiled protected-path matcher.
    #[must_use]
    pub fn protected_paths(&self) -> &ProtectedPaths {
        &self.protected
    }

    /// Evaluate a tool call under a given permission mode.
    ///
    /// `effects` is the effect set the caller has resolved for this tool
    /// call (either from explicit Tier-A tags or pack defaults). Phase 2
    /// will wire this into the existing pack registry; Phase A keeps it
    /// caller-supplied so the API can be exercised end-to-end before the
    /// rule layer is moved in.
    pub fn evaluate(
        &self,
        session: &mut Session,
        tool: &ToolCall,
        mode: Mode,
        effects: &[Effect],
    ) -> Decision {
        let path_in_protected = match tool.path() {
            Some(p) => {
                let resolved = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    session.working_dir.join(p)
                };
                self.protected.contains(&resolved)
            }
            None => false,
        };

        match mode.pre_check(tool, effects, path_in_protected) {
            ModePreCheck::AllowImmediately => Decision::Allow,
            ModePreCheck::DenyImmediately => Decision::deny(plan_deny_reason(mode, effects)),
            ModePreCheck::PromptImmediately => {
                let cmd_repr = tool_repr(tool);
                let code = session.generate_allow_once_code(&cmd_repr);
                Decision::prompt(prompt_reason(mode, path_in_protected, effects), code)
            }
            ModePreCheck::Continue => Self::fallthrough(session, tool, mode),
        }
    }

    /// Fallthrough: no rule has matched (Phase 2 will plug rule evaluation
    /// here). Use the mode's fallthrough policy to decide.
    fn fallthrough(session: &mut Session, tool: &ToolCall, mode: Mode) -> Decision {
        if mode.fallthrough_allows() {
            Decision::Allow
        } else {
            // DontAsk falls through to Deny (no pre-approved rule matched).
            let cmd_repr = tool_repr(tool);
            session.bump_deny_counter(&cmd_repr);
            Decision::deny(format!(
                "tool call not on the explicit allow list (mode: {})",
                mode.as_str()
            ))
        }
    }
}

fn plan_deny_reason(mode: Mode, effects: &[Effect]) -> String {
    if mode == Mode::Plan {
        let bad: Vec<&str> = effects
            .iter()
            .filter(|e| !e.is_read_only())
            .map(|e| e.as_str())
            .collect();
        if bad.is_empty() {
            "plan mode: tool call is not read-only".to_string()
        } else {
            format!("plan mode: non-read-only effects ({})", bad.join(", "))
        }
    } else {
        format!("denied by {} mode", mode.as_str())
    }
}

fn prompt_reason(mode: Mode, path_in_protected: bool, effects: &[Effect]) -> String {
    if path_in_protected {
        return format!("{} mode: target path is in protected_paths", mode.as_str());
    }
    let dangerous: Vec<&str> = effects
        .iter()
        .filter(|e| matches!(e, Effect::Network | Effect::Spawn | Effect::Irreversible))
        .map(|e| e.as_str())
        .collect();
    if dangerous.is_empty() {
        format!("{} mode: confirmation required", mode.as_str())
    } else {
        format!(
            "{} mode: tool call has {} effect(s)",
            mode.as_str(),
            dangerous.join(", ")
        )
    }
}

fn tool_repr(tool: &ToolCall) -> String {
    match tool {
        ToolCall::Bash { cmd } => cmd.clone(),
        ToolCall::Edit { path } => format!("edit:{}", path.display()),
        ToolCall::Write { path } => format!("write:{}", path.display()),
        ToolCall::Read { path } => format!("read:{}", path.display()),
        ToolCall::Network { url, method } => format!("net:{method} {url}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with_protected(paths: Vec<String>, work: &str) -> Engine {
        Engine::new(
            EngineConfig::builder()
                .working_dir(work)
                .protected_paths(paths)
                .build(),
        )
    }

    #[test]
    fn bypass_always_allows() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("rm -rf /"),
            Mode::BypassPermissions,
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn plan_allows_read_only_bash() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git status"),
            Mode::Plan,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn plan_denies_write() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write("/work/output.txt"),
            Mode::Plan,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_deny(), "got {d:?}");
        assert!(d.reason().unwrap().contains("plan mode"));
    }

    #[test]
    fn accept_edits_allows_safe_write() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::edit("/work/src/foo.rs"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn accept_edits_prompts_in_protected_path() {
        let e = engine_with_protected(vec![".git".into()], "/work");
        let mut s = Session::with_id("test");
        s.working_dir = std::path::PathBuf::from("/work");
        let d = e.evaluate(
            &mut s,
            &ToolCall::write("/work/.git/config"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "got {d:?}");
        // The Prompt must carry an allow_once_code we can later consume.
        match d {
            Decision::Prompt {
                allow_once_code, ..
            } => {
                assert!(s.has_unused_allow_once(&allow_once_code));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn accept_edits_prompts_on_irreversible() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("rm -rf ./build"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
        );
        assert!(d.is_prompt(), "got {d:?}");
    }

    #[test]
    fn dont_ask_denies_unmatched_calls() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("anything"),
            Mode::DontAsk,
            &[Effect::Read],
        );
        assert!(d.is_deny(), "got {d:?}");
        assert_eq!(s.deny_count("anything"), 1);
    }

    #[test]
    fn default_falls_through_to_allow() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git log"),
            Mode::Default,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn auto_routes_as_default_for_now() {
        let e = engine_with_protected(vec![], "/work");
        let mut s = Session::with_id("test");
        let d = e.evaluate(
            &mut s,
            &ToolCall::bash("git log"),
            Mode::Auto,
            &[Effect::Read],
        );
        assert!(d.is_allow(), "got {d:?}");
    }

    #[test]
    fn protected_path_relative_to_session_working_dir() {
        // Engine working_dir set to /work; protected_paths includes ".git".
        let e = engine_with_protected(vec![".git".into()], "/work");
        let mut s = Session::with_id("test");
        s.working_dir = std::path::PathBuf::from("/work");
        // Tool call uses a relative path; engine must resolve against
        // session.working_dir.
        let d = e.evaluate(
            &mut s,
            &ToolCall::write(".git/config"),
            Mode::AcceptEdits,
            &[Effect::Write, Effect::Fs],
        );
        assert!(d.is_prompt(), "got {d:?}");
    }
}

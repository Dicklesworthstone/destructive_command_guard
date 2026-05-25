//! Permission modes — the global control over how tool calls are evaluated.
//!
//! Modes correspond closely to Claude Code's permission modes, with one extra
//! variant ([`Mode::Auto`]) reserved for a future LLM classifier (Phase C).
//!
//! # Evaluation order (mirrors Claude Code)
//!
//! 1. **Hooks / deny rules** — checked first by [`crate::Engine`]; can deny
//!    even in `BypassPermissions`.
//! 2. **Mode pre-check** ([`Mode::pre_check`]) — fast path for modes that
//!    short-circuit (e.g. `BypassPermissions` returns `Allow`, `Plan` denies
//!    non-read operations).
//! 3. **Allow rules** — explicit pack allow patterns.
//! 4. **Default behavior** — [`Mode::default_action_for`] decides whether an
//!    unmatched tool call falls through to `Allow`, `Prompt`, or `Deny`.

use serde::{Deserialize, Serialize};

use crate::effect::{Effect, is_subset};
use crate::tool_call::ToolCall;

/// The permission mode in effect for an evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// Standard rule-based evaluation. Unmatched commands fall through to
    /// `Allow`. Matched destructive patterns produce `Prompt` or `Deny`
    /// according to severity.
    #[default]
    #[serde(alias = "default")]
    Default,
    /// Auto-approve `Read`/`Fs`/`Write` effects within the working directory.
    /// Network/Spawn/Irreversible effects still produce `Prompt`. Paths in
    /// `protected_paths` always produce `Prompt`.
    AcceptEdits,
    /// Read-only enforcement. Allow only effects ⊆ `{Read, Fs}`.
    /// Everything else → `Deny`.
    Plan,
    /// "Restricted surface" mode. Only explicitly allow-listed tool calls
    /// pass; everything else → `Deny`. Never `Prompt`.
    DontAsk,
    /// Skip evaluation entirely and return `Allow`. Deny rules still apply
    /// upstream (caller is expected to run them before `Engine::evaluate`).
    BypassPermissions,
    /// Reserved for LLM classifier (Phase C). For v0.6, routes identically
    /// to [`Mode::Default`].
    Auto,
}

/// Outcome of [`Mode::pre_check`] — can the mode shortcut without consulting
/// pack rules?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModePreCheck {
    /// Mode allows this call without further evaluation.
    AllowImmediately,
    /// Mode denies this call without further evaluation.
    DenyImmediately,
    /// Mode requires a prompt without further evaluation.
    PromptImmediately,
    /// Mode does not have an opinion; continue with rule-based evaluation.
    Continue,
}

impl Mode {
    /// Canonical name for logging and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AcceptEdits => "acceptEdits",
            Self::Plan => "plan",
            Self::DontAsk => "dontAsk",
            Self::BypassPermissions => "bypassPermissions",
            Self::Auto => "auto",
        }
    }

    /// Parse a mode name from CLI flag / config / JSON value.
    ///
    /// Accepts both `camelCase` (Claude Code wire format) and `snake_case`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "acceptEdits" | "accept_edits" | "accept-edits" => Some(Self::AcceptEdits),
            "plan" => Some(Self::Plan),
            "dontAsk" | "dont_ask" | "dont-ask" => Some(Self::DontAsk),
            "bypassPermissions" | "bypass_permissions" | "bypass-permissions" => {
                Some(Self::BypassPermissions)
            }
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Mode-level fast path. Called before any pack evaluation.
    ///
    /// `effects` is the union of effects attributed to this tool call by the
    /// caller (typically `ToolCall::default_effects()` plus any Tier-A tags
    /// the engine has resolved).
    /// `path_in_protected` is `true` when the tool call targets a path that
    /// matches the engine's `protected_paths` list.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Distinct semantics worth keeping separate.
    pub fn pre_check(
        self,
        tool: &ToolCall,
        effects: &[Effect],
        path_in_protected: bool,
    ) -> ModePreCheck {
        match self {
            // Bypass: skip all evaluation. Engine still applies deny rules
            // upstream of this call, so we don't need to repeat that here.
            Self::BypassPermissions => ModePreCheck::AllowImmediately,

            // Plan mode is read-only. Allow only if effects ⊆ {Read, Fs}.
            Self::Plan => {
                if is_subset(effects, &[Effect::Read, Effect::Fs]) {
                    ModePreCheck::AllowImmediately
                } else {
                    ModePreCheck::DenyImmediately
                }
            }

            // AcceptEdits auto-allows file ops within working_dir. Protected
            // paths force a prompt regardless. Network/Spawn/Irreversible also
            // prompt — the agent should not silently exfiltrate or run
            // destructive commands just because edits are accepted.
            Self::AcceptEdits => {
                if path_in_protected {
                    return ModePreCheck::PromptImmediately;
                }
                let dangerous = [Effect::Network, Effect::Spawn, Effect::Irreversible];
                if effects.iter().any(|e| dangerous.contains(e)) {
                    return ModePreCheck::PromptImmediately;
                }
                if matches!(
                    tool,
                    ToolCall::Edit { .. } | ToolCall::Write { .. } | ToolCall::Read { .. }
                ) && is_subset(
                    effects,
                    &[Effect::Read, Effect::Write, Effect::Fs, Effect::MutateVcs],
                ) {
                    ModePreCheck::AllowImmediately
                } else {
                    ModePreCheck::Continue
                }
            }

            // DontAsk: cannot pre-decide, must consult allow rules. The engine
            // converts any `Prompt`-producing match into `Deny` after rule
            // evaluation.
            Self::DontAsk => ModePreCheck::Continue,

            // Default and Auto behave the same in v0.6.
            Self::Default | Self::Auto => ModePreCheck::Continue,
        }
    }

    /// What should the engine do when no rule matched?
    ///
    /// Mirrors Claude Code's "fall-through" semantics. `Default`/`Auto` allow
    /// unknown commands; `DontAsk` denies; other modes are pre-checked and
    /// don't reach this branch.
    #[must_use]
    pub const fn fallthrough_allows(self) -> bool {
        matches!(self, Self::Default | Self::Auto | Self::AcceptEdits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_path(p: &str) -> ToolCall {
        ToolCall::read(p)
    }

    fn bash(cmd: &str) -> ToolCall {
        ToolCall::bash(cmd)
    }

    #[test]
    fn parse_canonical_and_aliases() {
        for s in [
            "default",
            "plan",
            "auto",
            "acceptEdits",
            "accept_edits",
            "accept-edits",
            "dontAsk",
            "dont_ask",
            "dont-ask",
            "bypassPermissions",
            "bypass_permissions",
            "bypass-permissions",
        ] {
            assert!(Mode::parse(s).is_some(), "should parse {s}");
        }
        assert!(Mode::parse("nope").is_none());
    }

    #[test]
    fn as_str_round_trips() {
        for mode in [
            Mode::Default,
            Mode::AcceptEdits,
            Mode::Plan,
            Mode::DontAsk,
            Mode::BypassPermissions,
            Mode::Auto,
        ] {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn bypass_short_circuits_to_allow() {
        let pc = Mode::BypassPermissions.pre_check(
            &bash("git push --force"),
            &[Effect::MutateVcs, Effect::Network, Effect::Irreversible],
            false,
        );
        assert_eq!(pc, ModePreCheck::AllowImmediately);
    }

    #[test]
    fn plan_allows_read_only_effects() {
        let pc = Mode::Plan.pre_check(&bash("git status"), &[Effect::Read], false);
        assert_eq!(pc, ModePreCheck::AllowImmediately);

        let pc = Mode::Plan.pre_check(&read_path("/tmp/x"), &[Effect::Read, Effect::Fs], false);
        assert_eq!(pc, ModePreCheck::AllowImmediately);
    }

    #[test]
    fn plan_denies_writes_and_network() {
        let pc = Mode::Plan.pre_check(
            &bash("git push"),
            &[Effect::MutateVcs, Effect::Network],
            false,
        );
        assert_eq!(pc, ModePreCheck::DenyImmediately);

        let pc = Mode::Plan.pre_check(
            &ToolCall::write("/tmp/out"),
            &[Effect::Write, Effect::Fs],
            false,
        );
        assert_eq!(pc, ModePreCheck::DenyImmediately);
    }

    #[test]
    fn accept_edits_allows_safe_writes() {
        let pc = Mode::AcceptEdits.pre_check(
            &ToolCall::edit("/work/src/foo.rs"),
            &[Effect::Write, Effect::Fs],
            false,
        );
        assert_eq!(pc, ModePreCheck::AllowImmediately);
    }

    #[test]
    fn accept_edits_prompts_on_protected_paths() {
        let pc = Mode::AcceptEdits.pre_check(
            &ToolCall::write("/home/user/.ssh/id_rsa"),
            &[Effect::Write, Effect::Fs],
            true,
        );
        assert_eq!(pc, ModePreCheck::PromptImmediately);
    }

    #[test]
    fn accept_edits_prompts_on_network_or_irreversible() {
        let pc = Mode::AcceptEdits.pre_check(
            &bash("curl -X POST https://api.example.com/data"),
            &[Effect::Network, Effect::Write],
            false,
        );
        assert_eq!(pc, ModePreCheck::PromptImmediately);

        let pc = Mode::AcceptEdits.pre_check(
            &bash("rm -rf ./build"),
            &[Effect::Write, Effect::Fs, Effect::Irreversible],
            false,
        );
        assert_eq!(pc, ModePreCheck::PromptImmediately);
    }

    #[test]
    fn dont_ask_does_not_pre_decide() {
        let pc = Mode::DontAsk.pre_check(&bash("ls"), &[Effect::Read, Effect::Fs], false);
        assert_eq!(pc, ModePreCheck::Continue);
    }

    #[test]
    fn fallthrough_semantics() {
        assert!(Mode::Default.fallthrough_allows());
        assert!(Mode::Auto.fallthrough_allows());
        assert!(Mode::AcceptEdits.fallthrough_allows());
        assert!(!Mode::DontAsk.fallthrough_allows());
        assert!(!Mode::Plan.fallthrough_allows());
        // Bypass / Plan are handled by pre_check, not fallthrough; values
        // here are immaterial as long as they don't accidentally allow.
        assert!(!Mode::Plan.fallthrough_allows());
    }
}

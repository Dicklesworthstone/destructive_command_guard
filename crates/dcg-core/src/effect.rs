//! Effect taxonomy for tool calls and rules.
//!
//! `Effect` is the unit of analysis used by [`crate::Mode`] policies to decide
//! whether a tool call is allowed without prompting. Each rule can be tagged
//! with a slice of effects (Tier-A explicit). Rules without explicit tags fall
//! back to their pack's `default_effects` (Tier-B).
//!
//! # Effect set semantics
//!
//! When a tool call carries multiple effects, the policy is evaluated against
//! the **set** of effects, not individual effects. For example:
//!
//! - `git push --force` → `[MutateVcs, Network, Irreversible]`
//! - In `Mode::Plan` the allowed set is `{Read, Fs}`. The push effects are not
//!   a subset → command is denied.

use serde::{Deserialize, Serialize};

/// A single observable effect of a tool call.
///
/// Effects are coarse on purpose — the goal is to let permission modes make
/// boolean decisions ("can I run this without prompting?") without enumerating
/// every concrete operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Reads filesystem contents, command output, or network responses.
    Read,
    /// Writes data anywhere (filesystem, remote service, VCS object store, …).
    Write,
    /// Performs network I/O.
    Network,
    /// Spawns a long-running process or background daemon.
    Spawn,
    /// Cannot be undone by `dcg` or by trivial follow-up commands.
    ///
    /// Examples: `rm -rf`, `git push --force`, `git reset --hard`,
    /// `DROP TABLE`, `terraform destroy`.
    Irreversible,
    /// Mutates VCS state (commits, branches, refs, history).
    MutateVcs,
    /// Touches the filesystem layout (cd, mkdir, mv, cp, rm).
    Fs,
}

impl Effect {
    /// Returns the canonical name as used in YAML pack schemas and JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Network => "network",
            Self::Spawn => "spawn",
            Self::Irreversible => "irreversible",
            Self::MutateVcs => "mutate_vcs",
            Self::Fs => "fs",
        }
    }

    /// Parses an effect name from its canonical string form.
    ///
    /// Accepts both `snake_case` and `kebab-case` to be lenient with YAML inputs.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "network" => Some(Self::Network),
            "spawn" => Some(Self::Spawn),
            "irreversible" => Some(Self::Irreversible),
            "mutate_vcs" | "mutate-vcs" => Some(Self::MutateVcs),
            "fs" => Some(Self::Fs),
            _ => None,
        }
    }

    /// Returns true if `self` is a "side-effect-free" read.
    ///
    /// Plan mode uses this to allow read-only filesystem inspection.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::Read | Self::Fs)
    }
}

/// Convenience helper: does `effects` only contain effects from `allowed`?
#[must_use]
pub fn is_subset(effects: &[Effect], allowed: &[Effect]) -> bool {
    effects.iter().all(|e| allowed.contains(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_via_str() {
        for effect in [
            Effect::Read,
            Effect::Write,
            Effect::Network,
            Effect::Spawn,
            Effect::Irreversible,
            Effect::MutateVcs,
            Effect::Fs,
        ] {
            assert_eq!(Effect::parse(effect.as_str()), Some(effect));
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert_eq!(Effect::parse("bogus"), None);
        assert_eq!(Effect::parse(""), None);
    }

    #[test]
    fn from_str_accepts_kebab_for_mutate_vcs() {
        assert_eq!(Effect::parse("mutate-vcs"), Some(Effect::MutateVcs));
        assert_eq!(Effect::parse("mutate_vcs"), Some(Effect::MutateVcs));
    }

    #[test]
    fn is_read_only_classification() {
        assert!(Effect::Read.is_read_only());
        assert!(Effect::Fs.is_read_only());
        assert!(!Effect::Write.is_read_only());
        assert!(!Effect::Network.is_read_only());
        assert!(!Effect::Irreversible.is_read_only());
    }

    #[test]
    fn is_subset_basic() {
        assert!(is_subset(&[Effect::Read], &[Effect::Read, Effect::Fs]));
        assert!(is_subset(&[], &[Effect::Read]));
        assert!(!is_subset(&[Effect::Write], &[Effect::Read, Effect::Fs]));
        assert!(!is_subset(
            &[Effect::Read, Effect::Network],
            &[Effect::Read, Effect::Fs]
        ));
    }
}

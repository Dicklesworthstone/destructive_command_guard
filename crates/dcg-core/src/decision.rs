//! Three-state decision returned by [`crate::Engine::evaluate`].
//!
//! `Decision` replaces the binary allow/deny verdict from dcg v0.5. The
//! `Prompt` variant carries an `allow_once_code` that the consumer can show
//! to the user; if approved, the consumer calls
//! [`crate::Session::consume_allow_once`] with the same code to record the
//! exception.

use serde::{Deserialize, Serialize};

/// Outcome of evaluating a [`crate::ToolCall`] under a given [`crate::Mode`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Tool call is approved. Caller may execute.
    Allow,
    /// Tool call is risky but not categorically forbidden. Caller should
    /// present the reason to a human and, if approved, call
    /// [`crate::Session::consume_allow_once`] with `allow_once_code`.
    Prompt {
        /// Short human-readable explanation of why the prompt was raised.
        reason: String,
        /// Single-use code (6 hex chars) that scopes the eventual approval
        /// to the exact command in this session.
        allow_once_code: String,
        /// Suggested safer commands (e.g. "use `git stash` first").
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alternatives: Vec<String>,
    },
    /// Tool call is denied. Caller must not execute.
    Deny {
        /// Short human-readable explanation of why the call was denied.
        reason: String,
        /// Suggested safer commands.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alternatives: Vec<String>,
    },
}

impl Decision {
    /// Convenience constructor for `Allow`.
    #[must_use]
    pub const fn allow() -> Self {
        Self::Allow
    }

    /// Convenience constructor for `Prompt` with no alternatives.
    pub fn prompt<R: Into<String>, C: Into<String>>(reason: R, allow_once_code: C) -> Self {
        Self::Prompt {
            reason: reason.into(),
            allow_once_code: allow_once_code.into(),
            alternatives: Vec::new(),
        }
    }

    /// Convenience constructor for `Prompt` with alternatives.
    pub fn prompt_with_alternatives<R, C>(
        reason: R,
        allow_once_code: C,
        alternatives: Vec<String>,
    ) -> Self
    where
        R: Into<String>,
        C: Into<String>,
    {
        Self::Prompt {
            reason: reason.into(),
            allow_once_code: allow_once_code.into(),
            alternatives,
        }
    }

    /// Convenience constructor for `Deny` with no alternatives.
    pub fn deny<R: Into<String>>(reason: R) -> Self {
        Self::Deny {
            reason: reason.into(),
            alternatives: Vec::new(),
        }
    }

    /// Convenience constructor for `Deny` with alternatives.
    pub fn deny_with_alternatives<R: Into<String>>(reason: R, alternatives: Vec<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
            alternatives,
        }
    }

    /// `true` if and only if this is the `Allow` variant.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// `true` if this is the `Prompt` variant.
    #[must_use]
    pub const fn is_prompt(&self) -> bool {
        matches!(self, Self::Prompt { .. })
    }

    /// `true` if this is the `Deny` variant.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Stable string tag (`allow` / `prompt` / `deny`) for logging.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Prompt { .. } => "prompt",
            Self::Deny { .. } => "deny",
        }
    }

    /// Returns the reason string for `Prompt` and `Deny` variants.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Prompt { reason, .. } | Self::Deny { reason, .. } => Some(reason),
        }
    }

    /// Returns the alternatives slice for `Prompt` and `Deny` variants.
    #[must_use]
    pub fn alternatives(&self) -> &[String] {
        match self {
            Self::Allow => &[],
            Self::Prompt { alternatives, .. } | Self::Deny { alternatives, .. } => alternatives,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_is_allow() {
        let d = Decision::allow();
        assert!(d.is_allow());
        assert!(!d.is_prompt());
        assert!(!d.is_deny());
        assert_eq!(d.tag(), "allow");
        assert_eq!(d.reason(), None);
        assert!(d.alternatives().is_empty());
    }

    #[test]
    fn prompt_carries_code_and_reason() {
        let d = Decision::prompt("dangerous", "abc123");
        assert!(d.is_prompt());
        assert_eq!(d.reason(), Some("dangerous"));
        match d {
            Decision::Prompt {
                allow_once_code, ..
            } => assert_eq!(allow_once_code, "abc123"),
            _ => panic!("expected Prompt"),
        }
    }

    #[test]
    fn deny_with_alternatives() {
        let d = Decision::deny_with_alternatives(
            "git reset --hard destroys uncommitted changes",
            vec!["git stash".to_string()],
        );
        assert!(d.is_deny());
        assert_eq!(d.alternatives().len(), 1);
        assert_eq!(d.alternatives()[0], "git stash");
    }

    #[test]
    fn json_round_trip_allow() {
        let d = Decision::Allow;
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(s, r#"{"decision":"allow"}"#);
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn json_round_trip_prompt() {
        let d = Decision::prompt("foo", "abc");
        let s = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn json_round_trip_deny_with_alts() {
        let d = Decision::deny_with_alternatives(
            "blocked",
            vec!["alt1".to_string(), "alt2".to_string()],
        );
        let s = serde_json::to_string(&d).unwrap();
        let back: Decision = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn empty_alternatives_omitted_in_json() {
        let d = Decision::deny("blocked");
        let s = serde_json::to_string(&d).unwrap();
        assert!(
            !s.contains("alternatives"),
            "empty alternatives should be omitted, got {s}"
        );
    }
}

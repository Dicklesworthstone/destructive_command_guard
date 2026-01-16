//! Pulumi patterns - protections against destructive pulumi commands.
//!
//! This includes patterns for:
//! - pulumi destroy
//! - pulumi up with -y (auto-approve)
//! - pulumi state delete

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Pulumi pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "infrastructure.pulumi".to_string(),
        name: "Pulumi",
        description: "Protects against destructive Pulumi operations like destroy \
                      and up with -y (auto-approve)",
        keywords: &["pulumi", "destroy", "state"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // preview is safe (read-only)
        safe_pattern!("pulumi-preview", r"pulumi\s+preview"),
        // stack ls/select/init are safe
        safe_pattern!("pulumi-stack-ls", r"pulumi\s+stack\s+ls"),
        safe_pattern!("pulumi-stack-select", r"pulumi\s+stack\s+select"),
        safe_pattern!("pulumi-stack-init", r"pulumi\s+stack\s+init"),
        // config is safe
        safe_pattern!("pulumi-config", r"pulumi\s+config"),
        // whoami is safe
        safe_pattern!("pulumi-whoami", r"pulumi\s+whoami"),
        // version is safe
        safe_pattern!("pulumi-version", r"pulumi\s+version"),
        // about is safe
        safe_pattern!("pulumi-about", r"pulumi\s+about"),
        // logs is safe
        safe_pattern!("pulumi-logs", r"pulumi\s+logs"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // destroy
        destructive_pattern!(
            "destroy",
            r"pulumi\s+destroy",
            "pulumi destroy removes ALL managed infrastructure. Use 'pulumi preview --diff' first."
        ),
        // up with -y or --yes (auto-approve)
        destructive_pattern!(
            "up-yes",
            r"pulumi\s+up\s+.*(?:-y\b|--yes\b)",
            "pulumi up -y skips confirmation. Remove -y flag for safety."
        ),
        // state delete
        destructive_pattern!(
            "state-delete",
            r"pulumi\s+state\s+delete",
            "pulumi state delete removes resource from state without destroying it."
        ),
        // stack rm (remove stack)
        destructive_pattern!(
            "stack-rm",
            r"pulumi\s+stack\s+rm",
            "pulumi stack rm removes the stack. Use --force only if stack is empty."
        ),
        // refresh with -y
        destructive_pattern!(
            "refresh-yes",
            r"pulumi\s+refresh\s+.*(?:-y\b|--yes\b)",
            "pulumi refresh -y auto-approves state changes. Review changes first."
        ),
        // cancel (cancels in-progress update)
        destructive_pattern!(
            "cancel",
            r"pulumi\s+cancel",
            "pulumi cancel terminates an in-progress update, which may leave resources in inconsistent state."
        ),
    ]
}

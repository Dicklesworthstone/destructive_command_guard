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
            "pulumi destroy removes ALL managed infrastructure. Use 'pulumi preview --diff' first.",
            Critical,
            "pulumi destroy removes ALL managed infrastructure:\n\n\
             - Every resource in your stack is destroyed\n\
             - Cloud resources (VMs, databases, networks) deleted\n\
             - Cannot be undone without backups/recreation\n\
             - Use --target to destroy specific resources only\n\n\
             Preview first: pulumi preview --diff"
        ),
        // up with -y or --yes (auto-approve)
        destructive_pattern!(
            "up-yes",
            r"pulumi\s+up\s+.*(?:-y\b|--yes\b)",
            "pulumi up -y skips confirmation. Remove -y flag for safety.",
            High,
            "pulumi up -y skips confirmation:\n\n\
             - No opportunity to review changes before applying\n\
             - Intended for CI/CD, not interactive use\n\
             - Changes may destroy or recreate resources\n\
             - Replacements can cause downtime\n\n\
             For safety: remove -y and review the preview"
        ),
        // state delete
        destructive_pattern!(
            "state-delete",
            r"pulumi\s+state\s+delete",
            "pulumi state delete removes resource from state without destroying it.",
            High,
            "pulumi state delete orphans resources:\n\n\
             - Resource removed from Pulumi state\n\
             - Actual cloud resource still exists\n\
             - Resource becomes 'unmanaged' (Pulumi ignores it)\n\
             - May cause drift between state and reality\n\n\
             Consider: pulumi refresh to sync state with reality"
        ),
        // stack rm (remove stack)
        destructive_pattern!(
            "stack-rm",
            r"pulumi\s+stack\s+rm",
            "pulumi stack rm removes the stack. Use --force only if stack is empty.",
            High,
            "pulumi stack rm removes the entire stack:\n\n\
             - Stack and its state deleted\n\
             - Does NOT destroy actual infrastructure (unless empty)\n\
             - --force required if resources still exist\n\
             - Resources become unmanaged (orphaned)\n\n\
             Destroy resources first: pulumi destroy, then rm stack"
        ),
        // refresh with -y
        destructive_pattern!(
            "refresh-yes",
            r"pulumi\s+refresh\s+.*(?:-y\b|--yes\b)",
            "pulumi refresh -y auto-approves state changes. Review changes first.",
            Medium,
            "pulumi refresh -y auto-approves state sync:\n\n\
             - Syncs Pulumi state with actual cloud resources\n\
             - May delete resources from state if not found\n\
             - May update state with drift from cloud\n\n\
             Run without -y first to review detected changes"
        ),
        // cancel (cancels in-progress update)
        destructive_pattern!(
            "cancel",
            r"pulumi\s+cancel",
            "pulumi cancel terminates an in-progress update, which may leave resources in inconsistent state.",
            High,
            "pulumi cancel stops in-progress operations:\n\n\
             - Terminates currently running update/destroy\n\
             - Resources may be left in inconsistent state\n\
             - Some resources created, others not\n\
             - May require manual cleanup\n\n\
             Use only when operation is stuck/hung"
        ),
    ]
}

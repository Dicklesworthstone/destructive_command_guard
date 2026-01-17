//! Helm patterns - protections against destructive helm commands.
//!
//! This includes patterns for:
//! - uninstall releases
//! - rollback without dry-run
//! - delete commands

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Helm pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "kubernetes.helm".to_string(),
        name: "Helm",
        description: "Protects against destructive Helm operations like uninstall \
                      and rollback without dry-run",
        keywords: &["helm", "uninstall", "delete", "rollback"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // list/status/history are safe (read-only)
        safe_pattern!("helm-list", r"helm\s+list"),
        safe_pattern!("helm-status", r"helm\s+status"),
        safe_pattern!("helm-history", r"helm\s+history"),
        // show/inspect are safe (read-only)
        safe_pattern!("helm-show", r"helm\s+show"),
        safe_pattern!("helm-inspect", r"helm\s+inspect"),
        // get is safe (read-only)
        safe_pattern!("helm-get", r"helm\s+get"),
        // search is safe
        safe_pattern!("helm-search", r"helm\s+search"),
        // repo operations are generally safe
        safe_pattern!("helm-repo", r"helm\s+repo"),
        // dry-run flags
        safe_pattern!("helm-dry-run", r"helm\s+.*--dry-run"),
        // template only generates manifests
        safe_pattern!("helm-template", r"helm\s+template"),
        // lint is safe (validation)
        safe_pattern!("helm-lint", r"helm\s+lint"),
        // diff plugin is safe
        safe_pattern!("helm-diff", r"helm\s+diff"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // uninstall / delete
        destructive_pattern!(
            "uninstall",
            r"helm\s+(?:uninstall|delete)\b(?!.*--dry-run)",
            "helm uninstall removes the release and all its resources. Use --dry-run first."
        ),
        // rollback without dry-run
        destructive_pattern!(
            "rollback",
            r"helm\s+rollback\b(?!.*--dry-run)",
            "helm rollback reverts to a previous release. Use --dry-run to preview changes."
        ),
        // upgrade --force
        destructive_pattern!(
            "upgrade-force",
            r"helm\s+upgrade\s+.*--force",
            "helm upgrade --force deletes and recreates resources, causing downtime."
        ),
        // upgrade --reset-values
        destructive_pattern!(
            "upgrade-reset-values",
            r"helm\s+upgrade\s+.*--reset-values",
            "helm upgrade --reset-values discards all previously set values."
        ),
    ]
}

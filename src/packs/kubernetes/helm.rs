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
            "helm uninstall removes the release and all its resources. Use --dry-run first.",
            Critical,
            "helm uninstall deletes the release and ALL Kubernetes resources created by it:\n\n\
             - Deployments, services, and pods are terminated\n\
             - ConfigMaps and secrets are deleted\n\
             - Persistent volume claims may be deleted (depends on chart)\n\
             - Release history is purged (no rollback possible)\n\n\
             Safer alternatives:\n\
             - helm uninstall <release> --dry-run: Preview what will be deleted\n\
             - helm status <release>: Review current release state\n\
             - helm get all <release>: See all resources managed by release\n\
             - helm get manifest <release>: Get the actual Kubernetes manifests"
        ),
        // rollback without dry-run
        destructive_pattern!(
            "rollback",
            r"helm\s+rollback\b(?!.*--dry-run)",
            "helm rollback reverts to a previous release. Use --dry-run to preview changes.",
            High,
            "helm rollback reverts the release to a previous revision. This can cause unexpected \
             behavior if the previous version differs significantly:\n\n\
             - Pod configurations are reverted (may break dependencies)\n\
             - ConfigMaps and secrets are rolled back\n\
             - Database migrations are NOT automatically undone\n\
             - Downtime may occur during the transition\n\n\
             Safer alternatives:\n\
             - helm rollback <release> <revision> --dry-run: Preview changes\n\
             - helm history <release>: Review available revisions\n\
             - helm diff rollback <release> <revision>: Compare changes (requires diff plugin)"
        ),
        // upgrade --force
        destructive_pattern!(
            "upgrade-force",
            r"helm\s+upgrade\s+.*--force",
            "helm upgrade --force deletes and recreates resources, causing downtime.",
            High,
            "The --force flag causes Helm to delete and recreate resources instead of updating \
             them in place. This can cause service disruption:\n\n\
             - Pods are terminated and recreated (downtime between)\n\
             - Persistent volume claims may be deleted and recreated\n\
             - In-flight requests are dropped during recreation\n\
             - Service IP addresses may change\n\n\
             Safer alternatives:\n\
             - Remove --force to use rolling updates\n\
             - helm upgrade --dry-run --debug: Preview changes\n\
             - helm diff upgrade: Compare before upgrading (requires diff plugin)"
        ),
        // upgrade --reset-values
        destructive_pattern!(
            "upgrade-reset-values",
            r"helm\s+upgrade\s+.*--reset-values",
            "helm upgrade --reset-values discards all previously set values.",
            High,
            "The --reset-values flag discards all values from previous releases, using only \
             chart defaults and explicitly provided values. This can unexpectedly change:\n\n\
             - Resource limits and replica counts\n\
             - Database connection strings and credentials\n\
             - Feature flags and environment variables\n\
             - Any customization from previous 'helm upgrade' commands\n\n\
             Safer alternatives:\n\
             - helm get values <release>: Review current values first\n\
             - helm upgrade --reuse-values: Keep existing values (default)\n\
             - helm upgrade -f values.yaml: Explicitly set all needed values"
        ),
    ]
}

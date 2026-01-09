//! Kustomize patterns - protections against destructive kustomize commands.
//!
//! This includes patterns for:
//! - kustomize with kubectl delete
//! - Potentially dangerous kustomize builds applied directly

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Kustomize pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "kubernetes.kustomize".to_string(),
        name: "Kustomize",
        description: "Protects against destructive Kustomize operations when combined \
                      with kubectl delete or applied without review",
        keywords: &["kustomize", "kubectl"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // kustomize build alone is safe (just renders)
        safe_pattern!("kustomize-build", r"kustomize\s+build(?!\s*\|)"),
        // kubectl kustomize is safe (just renders)
        safe_pattern!("kubectl-kustomize", r"kubectl\s+kustomize(?!\s*\|)"),
        // kustomize with diff is safe
        safe_pattern!(
            "kustomize-diff",
            r"kustomize\s+build\s+.*\|\s*kubectl\s+diff"
        ),
        // kustomize with dry-run
        safe_pattern!(
            "kustomize-dry-run",
            r"kustomize\s+build\s+.*\|\s*kubectl\s+.*--dry-run"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // kustomize build | kubectl delete
        destructive_pattern!(
            "kustomize-delete",
            r"kustomize\s+build\s+.*\|\s*kubectl\s+delete",
            "kustomize build | kubectl delete removes all resources in the kustomization."
        ),
        // kubectl kustomize | kubectl delete
        destructive_pattern!(
            "kubectl-kustomize-delete",
            r"kubectl\s+kustomize\s+.*\|\s*kubectl\s+delete",
            "kubectl kustomize | kubectl delete removes all resources in the kustomization."
        ),
        // kubectl delete -k (kustomize flag)
        destructive_pattern!(
            "kubectl-delete-k",
            r"kubectl\s+delete\s+-k\b(?!.*--dry-run)",
            "kubectl delete -k removes all resources defined in the kustomization. Use --dry-run first."
        ),
    ]
}

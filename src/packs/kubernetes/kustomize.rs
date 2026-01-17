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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
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
            "kustomize build | kubectl delete removes all resources in the kustomization.",
            Critical,
            "Piping kustomize build to kubectl delete removes ALL resources defined in the \
             kustomization directory. This can delete entire applications:\n\n\
             - Every resource in kustomization.yaml and its bases is deleted\n\
             - Deployments, services, configmaps, secrets all removed\n\
             - Overlays may include resources you didn't expect\n\
             - No confirmation or preview by default\n\n\
             Safer alternatives:\n\
             - kustomize build <dir>: Review manifests first\n\
             - kustomize build <dir> | kubectl delete --dry-run=client -f -: Preview\n\
             - kustomize build <dir> | kubectl diff -f -: Compare with cluster state"
        ),
        // kubectl kustomize | kubectl delete
        destructive_pattern!(
            "kubectl-kustomize-delete",
            r"kubectl\s+kustomize\s+.*\|\s*kubectl\s+delete",
            "kubectl kustomize | kubectl delete removes all resources in the kustomization.",
            Critical,
            "Piping kubectl kustomize to kubectl delete removes ALL resources defined in the \
             kustomization directory. This is equivalent to kustomize build | kubectl delete:\n\n\
             - Entire application stack can be deleted\n\
             - Base and overlay resources are all affected\n\
             - Includes resources from remote URLs if referenced\n\
             - Order of deletion may cause cascading failures\n\n\
             Safer alternatives:\n\
             - kubectl kustomize <dir>: Review manifests first\n\
             - kubectl delete --dry-run=client -k <dir>: Preview deletion\n\
             - kubectl diff -k <dir>: Compare with cluster state"
        ),
        // kubectl delete -k (kustomize flag)
        destructive_pattern!(
            "kubectl-delete-k",
            r"kubectl\s+delete\s+-k\b(?!.*--dry-run)",
            "kubectl delete -k removes all resources defined in the kustomization. Use --dry-run first.",
            Critical,
            "kubectl delete -k removes all resources defined in a kustomization directory. \
             This is a convenient but dangerous shorthand:\n\n\
             - All resources in kustomization.yaml are deleted\n\
             - Includes base resources and all overlays\n\
             - May include namespaces, PVCs, and other critical resources\n\
             - No confirmation prompt by default\n\n\
             Safer alternatives:\n\
             - kubectl delete -k <dir> --dry-run=client: Preview what will be deleted\n\
             - kubectl kustomize <dir>: Review manifests before deleting\n\
             - kubectl get -k <dir>: List resources that would be affected"
        ),
    ]
}

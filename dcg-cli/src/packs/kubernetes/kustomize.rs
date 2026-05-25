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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // kustomize build alone is safe (just renders)
        safe_pattern!(
            "kustomize-build",
            r"kustomize\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build\b(?!.*\|)"
        ),
        // kubectl kustomize is safe (just renders)
        safe_pattern!(
            "kubectl-kustomize",
            r"kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+kustomize\b(?!.*\|)"
        ),
        // kustomize with diff is safe
        safe_pattern!(
            "kustomize-diff",
            r"kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b.*?\s+diff\b"
        ),
        // kustomize with dry-run
        safe_pattern!(
            "kustomize-dry-run",
            r"kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b.*--dry-run(?:=(?:client|server))?(?:\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // kustomize build | kubectl delete
        destructive_pattern!(
            "kustomize-delete",
            r"kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$)).*?\bdelete",
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
            r"kubectl\b.*?\bkustomize\s+.*\|\s*kubectl\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$)).*?\bdelete",
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
            r"kubectl\b.*?\bdelete\s+-k\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn kustomize_blocks_piped_delete() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "kustomize build ./overlays/prod | kubectl delete -f -",
            "kustomize",
        );
        assert_blocks(
            &pack,
            "kubectl kustomize ./overlays/prod | kubectl delete -f -",
            "kustomize",
        );
    }

    #[test]
    fn kustomize_blocks_kubectl_delete_k() {
        let pack = create_pack();
        assert_blocks(&pack, "kubectl delete -k ./overlays/prod", "delete -k");
    }

    #[test]
    fn kustomize_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "kustomize build ./prod | kubectl delete -f -",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "kubectl kustomize ./prod | kubectl delete -f -",
            Severity::Critical,
        );
        assert_blocks_with_severity(&pack, "kubectl delete -k ./prod", Severity::Critical);
    }

    #[test]
    fn kustomize_safe_build_alone() {
        let pack = create_pack();
        assert_allows(&pack, "kustomize build ./overlays/prod");
        assert_allows(&pack, "kubectl kustomize ./overlays/prod");
    }

    #[test]
    fn kustomize_safe_with_diff() {
        let pack = create_pack();
        assert_allows(&pack, "kustomize build ./overlays/prod | kubectl diff -f -");
    }

    #[test]
    fn kustomize_safe_with_dry_run() {
        let pack = create_pack();
        assert_allows(
            &pack,
            "kustomize build ./overlays/prod | kubectl apply --dry-run=client -f -",
        );
        assert_allows(
            &pack,
            "kustomize build ./overlays/prod | kubectl delete --dry-run=client -f -",
        );
        assert_allows(
            &pack,
            "kubectl kustomize ./overlays/prod | kubectl delete --dry-run=server -f -",
        );
        assert_allows(&pack, "kubectl delete -k ./prod --dry-run=client");
    }

    #[test]
    fn kustomize_dry_run_none_does_not_bypass_delete() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "kustomize build ./overlays/prod | kubectl delete --dry-run=none -f -",
            "kustomize",
        );
        assert_blocks(
            &pack,
            "kubectl delete -k ./prod --dry-run=none",
            "delete -k",
        );
        assert_no_safe_match(
            &pack,
            "kustomize build ./overlays/prod | kubectl delete --dry-run=none -f -",
        );
    }

    #[test]
    fn kustomize_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}

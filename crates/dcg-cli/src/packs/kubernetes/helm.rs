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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each read-only subcommand stops a release name that
    // contains the subcommand keyword as a substring from making a
    // destructive command short-circuit as safe. Without this anchor,
    // `helm uninstall get-operator` would match the `helm-get` safe rule
    // via `get` in `get-operator` and bypass the uninstall check.
    vec![
        // list/status/history are safe (read-only)
        safe_pattern!(
            "helm-list",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "helm-status",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s|$)"
        ),
        safe_pattern!(
            "helm-history",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+history(?=\s|$)"
        ),
        // show/inspect are safe (read-only)
        safe_pattern!(
            "helm-show",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)"
        ),
        safe_pattern!(
            "helm-inspect",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s|$)"
        ),
        // get is safe (read-only)
        safe_pattern!("helm-get", r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+get(?=\s|$)"),
        // search is safe
        safe_pattern!(
            "helm-search",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+search(?=\s|$)"
        ),
        // repo operations are generally safe
        safe_pattern!(
            "helm-repo",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+repo(?=\s|$)"
        ),
        // dry-run flags
        safe_pattern!(
            "helm-dry-run",
            r"helm\b.*--dry-run(?:=(?:true|client|server))?(?:\s|$)"
        ),
        // template only generates manifests
        safe_pattern!(
            "helm-template",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+template(?=\s|$)"
        ),
        // lint is safe (validation)
        safe_pattern!(
            "helm-lint",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+lint(?=\s|$)"
        ),
        // diff plugin is safe
        safe_pattern!(
            "helm-diff",
            r"helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // uninstall / delete
        destructive_pattern!(
            "uninstall",
            r"helm\b.*?\b(?:uninstall|delete)\b(?!.*--dry-run(?:=(?:true|client|server))?(?:\s|$))",
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
            r"helm\b.*?\brollback\b(?!.*--dry-run(?:=(?:true|client|server))?(?:\s|$))",
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
            r"helm\b.*?\bupgrade\s+.*--force",
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
            r"helm\b.*?\bupgrade\s+.*--reset-values",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn helm_patterns_match_with_global_flags() {
        // Helm global flags (`--kube-context`, `--kubeconfig`,
        // `--namespace`/`-n`, `--debug`, `--registry-config`, …)
        // between `helm` and the subcommand broke every `helm\s+<sub>`
        // pattern until the `helm\b.*?\b<sub>` sweep.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "helm --kube-context prod uninstall critical-release",
            "uninstall",
        );
        assert_blocks(
            &pack,
            "helm --kubeconfig /tmp/prod.yaml delete prod-svc",
            "uninstall",
        );
        assert_blocks(
            &pack,
            "helm -n prod rollback critical-release 2",
            "rollback",
        );
        assert_blocks(
            &pack,
            "helm --kube-context prod upgrade prod-svc ./chart --force",
            "force",
        );
    }

    #[test]
    fn helm_safe_patterns_do_not_bypass_via_flag_value() {
        // Flag-value bypass class: `--get-values`, `--list-all` etc.
        // must not match safe patterns.  `\s+<sub>\b` form enforces
        // that the subcommand is preceded by whitespace (not `-`).
        let pack = create_pack();
        assert_allows(&pack, "helm list");
        assert_allows(&pack, "helm --kube-context prod list");
        assert_allows(&pack, "helm get values prod-release");
        assert_allows(&pack, "helm status prod-release");
    }

    #[test]
    fn helm_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "helm uninstall my-release", "uninstall");
        assert_blocks(&pack, "helm delete my-release", "uninstall");
        assert_blocks(&pack, "helm rollback my-release 3", "rollback");
        assert_blocks(&pack, "helm upgrade my-release ./chart --force", "force");
        assert_blocks(
            &pack,
            "helm upgrade my-release ./chart --reset-values",
            "reset-values",
        );
    }

    #[test]
    fn helm_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "helm uninstall prod-release", Severity::Critical);
        assert_blocks_with_severity(&pack, "helm rollback prod-release 2", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "helm upgrade prod-release ./chart --force",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "helm upgrade prod-release ./chart --reset-values",
            Severity::High,
        );
    }

    #[test]
    fn helm_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "helm list");
        assert_safe_pattern_matches(&pack, "helm status my-release");
        assert_safe_pattern_matches(&pack, "helm history my-release");
        assert_safe_pattern_matches(&pack, "helm show chart stable/nginx");
        assert_safe_pattern_matches(&pack, "helm inspect values stable/nginx");
        assert_safe_pattern_matches(&pack, "helm get all my-release");
        assert_safe_pattern_matches(&pack, "helm search repo nginx");
        assert_safe_pattern_matches(&pack, "helm repo list");
        assert_safe_pattern_matches(&pack, "helm template my-release ./chart");
        assert_safe_pattern_matches(&pack, "helm lint ./chart");
        assert_safe_pattern_matches(&pack, "helm diff upgrade my-release ./chart");
    }

    #[test]
    fn helm_dry_run_overrides_destructive() {
        let pack = create_pack();
        assert_allows(&pack, "helm uninstall my-release --dry-run");
        assert_allows(&pack, "helm uninstall my-release --dry-run=true");
        assert_allows(&pack, "helm rollback my-release 3 --dry-run");
    }

    #[test]
    fn helm_false_or_none_dry_run_values_do_not_bypass() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "helm uninstall my-release --dry-run=false",
            "uninstall",
        );
        assert_blocks(&pack, "helm delete my-release --dry-run=false", "uninstall");
        assert_blocks(
            &pack,
            "helm rollback my-release 3 --dry-run=false",
            "rollback",
        );
        assert_blocks(
            &pack,
            "helm uninstall my-release --dry-run=none",
            "uninstall",
        );
        assert_no_safe_match(&pack, "helm uninstall my-release --dry-run=false");
        assert_no_safe_match(&pack, "helm uninstall my-release --dry-run=none");
    }

    #[test]
    fn helm_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo helm");
    }
}

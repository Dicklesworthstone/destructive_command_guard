//! Helm patterns - protections against destructive helm commands.
//!
//! This includes patterns for:
//! - uninstall releases
//! - rollback without dry-run
//! - delete commands

use crate::destructive_pattern;
use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, SafePattern};

// These grammars are for exemptions ONLY (#429/#435). Never use them to
// narrow the destructive expressions: those also see synthesized shell
// views, where a stricter grammar could lose a denial.
//
// A required pflag value consumes the following token even when it begins
// with `--`. It must not be optional, or a description/context/value can
// supply the apparent dry-run flag. Unknown options, quoting, shell syntax,
// and a bare `--` conservatively withdraw the regex exemption.
macro_rules! helm_global_option {
    () => {
        concat!(
            r"(?:--(?:burst-limit|kube-apiserver|kube-as-group|kube-as-user|kube-ca-file|kube-context|kube-tls-server-name|kube-token|kubeconfig|namespace|qps|registry-config|repository-cache|repository-config)",
            r"(?:=[^\s;&|<>()\x22'\\$`]+|[ \t]+[^\s;&|<>()\x22'\\$`]+)",
            r"|-n(?:[^\s;&|<>()\x22'\\$`]+|[ \t]+[^\s;&|<>()\x22'\\$`]+)",
            r"|--(?:debug|kube-insecure-skip-tls-verify)(?:=(?:true|false))?)"
        )
    };
}

macro_rules! helm_argument {
    () => {
        concat!(
            r"(?:",
            helm_global_option!(),
            r"|--(?:description|cascade|timeout|history-max|output|version|repo|username|password|ca-file|cert-file|key-file|keyring|post-renderer|post-renderer-args|values|set|set-file|set-json|set-literal|set-string|labels)",
            r"(?:=[^\s;&|<>()\x22'\\$`]+|[ \t]+[^\s;&|<>()\x22'\\$`]+)",
            r"|-[fo](?:[^\s;&|<>()\x22'\\$`]+|[ \t]+[^\s;&|<>()\x22'\\$`]+)",
            r"|--(?:no-hooks|ignore-not-found|keep-history|force|force-replace|force-conflicts|reset-values|reuse-values|reset-then-reuse-values|install|atomic|cleanup-on-fail|disable-openapi-validation|skip-schema-validation|skip-crds|create-namespace|verify|wait|wait-for-jobs|devel|dependency-update|enable-dns|hide-notes|hide-secret|insecure-skip-tls-verify|plain-http|render-subchart-notes|take-ownership)(?:=(?:true|false|watcher|hookOnly|legacy))?",
            r"|-i|[^\s;&|<>()\x22'\\$`-][^\s;&|<>()\x22'\\$`]*|-)"
        )
    };
}

macro_rules! helm_safe_pattern {
    ($name:literal, $suffix:expr) => {
        SafePattern {
            name: $name,
            regex: LazyCompiledRegex::new(concat!(
                r"^[ \t]*(?:[^\s;&|<>()\x22'\\$`]+/)?helm[ \t]+(?:",
                helm_global_option!(),
                r"[ \t]+)*",
                $suffix
            )),
        }
    };
}

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
        // Read-only verbs must be the actual subcommand, not release names
        // or words skipped as the fictitious value of a boolean option.
        helm_safe_pattern!("helm-list", r"list(?=\s|$)"),
        helm_safe_pattern!("helm-status", r"status(?=\s|$)"),
        helm_safe_pattern!("helm-history", r"history(?=\s|$)"),
        helm_safe_pattern!("helm-show", r"show(?=\s|$)"),
        helm_safe_pattern!("helm-inspect", r"inspect(?=\s|$)"),
        helm_safe_pattern!("helm-get", r"get(?=\s|$)"),
        helm_safe_pattern!("helm-search", r"search(?=\s|$)"),
        helm_safe_pattern!("helm-repo", r"repo(?=\s|$)"),
        // Consume complete arguments on BOTH sides of the evidence. In
        // particular, a later `--dry-run=false` must revoke an earlier
        // preview. Mixed disabling/enabling flags are conservatively denied;
        // positive repeats and dry-run text consumed as data remain valid.
        // This expression remains compatible with the linear regex engine.
        helm_safe_pattern!(
            "helm-dry-run",
            concat!(
                r"(?:uninstall|delete|rollback|upgrade)(?:[ \t]+",
                helm_argument!(),
                r")*[ \t]+--dry-run(?:=(?:true|client|server))?(?:[ \t]+(?:",
                helm_argument!(),
                r"|--dry-run(?:=(?:true|client|server))?))*[ \t]*$"
            )
        ),
        helm_safe_pattern!("helm-template", r"template(?=\s|$)"),
        helm_safe_pattern!("helm-lint", r"lint(?=\s|$)"),
        helm_safe_pattern!("helm-diff", r"diff(?=\s|$)"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Preview exemptions live on the safe side only. The old negative
    // lookaheads repeated the same argument-data bug and would still miss
    // uninstall/rollback after the safe pattern correctly refused to match.
    vec![
        // uninstall / delete
        destructive_pattern!(
            "uninstall",
            r"helm\b.*?\b(?:uninstall|delete)\b",
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
            r"helm\b.*?\brollback\b",
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
        // Destructive matching must remain permissive in synthesized views.
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
        let pack = create_pack();
        assert_allows(&pack, "helm list");
        assert_allows(&pack, "helm --kube-context prod list");
        assert_allows(&pack, "helm get values prod-release");
        assert_allows(&pack, "helm status prod-release");
        for command in [
            "helm --debug uninstall list",
            "helm --kube-context prod uninstall list",
            "helm uninstall my-release --description helm list",
            "helm uninstall my-release --description 'helm list'",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks(&pack, command, "uninstall");
        }
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
        assert_safe_pattern_matches(&pack, "helm --debug --kube-context prod list");
    }

    #[test]
    fn helm_dry_run_overrides_destructive() {
        let pack = create_pack();
        for command in [
            "helm uninstall my-release --dry-run",
            "helm uninstall my-release --dry-run=true",
            "helm rollback my-release 3 --dry-run",
            "helm --kube-context prod uninstall my-release --dry-run",
            "helm uninstall my-release --description note --dry-run",
            "helm uninstall my-release --description=note --dry-run",
            "helm uninstall my-release --dry-run --kube-context prod",
            "helm uninstall my-release --dry-run --dry-run=true",
            "helm uninstall my-release --dry-run --description --dry-run=false",
            "helm upgrade my-release ./chart --force --dry-run=client",
            "helm upgrade my-release ./chart -fvalues.yaml --reset-values --dry-run=server",
        ] {
            assert_safe_pattern_matches(&pack, command);
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn helm_dry_run_evidence_must_be_an_option() {
        let pack = create_pack();
        for command in [
            "helm uninstall my-release --kube-context --dry-run",
            "helm uninstall my-release --description --dry-run",
            "helm uninstall my-release --description=--dry-run",
            "helm uninstall my-release --namespace=--dry-run",
            "helm uninstall my-release -n --dry-run",
            "helm uninstall my-release -n--dry-run",
            "helm uninstall my-release -- --dry-run",
            "helm uninstall my-release --description 'note --dry-run'",
            "helm uninstall my-release --unknown-option --dry-run",
            "helm uninstall my-release; echo --dry-run",
            "helm uninstall my-release && echo --dry-run",
            "helm uninstall my-release | grep -- --dry-run",
            "helm uninstall my-release\necho --dry-run",
            "helm uninstall my-release -n \"$(echo --dry-run)\"",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks(&pack, command, "uninstall");
        }
        assert_blocks(
            &pack,
            "helm rollback my-release 1 --kube-context --dry-run",
            "rollback",
        );
        assert_blocks(
            &pack,
            "helm upgrade my-release ./chart --force --set-string note=--dry-run",
            "force",
        );
    }

    #[test]
    fn helm_false_or_none_dry_run_values_do_not_bypass() {
        let pack = create_pack();
        for command in [
            "helm uninstall my-release --dry-run=false",
            "helm delete my-release --dry-run=false",
            "helm uninstall my-release --dry-run=none",
            "helm uninstall my-release --dry-run --dry-run=false",
            "helm uninstall my-release --dry-run=true --dry-run=none",
            "helm uninstall my-release --dry-run --dry-run=0",
            "helm uninstall my-release --dry-run=false --dry-run",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks(&pack, command, "uninstall");
        }
        assert_blocks(
            &pack,
            "helm rollback my-release 3 --dry-run=false",
            "rollback",
        );
    }

    #[test]
    fn helm_long_argument_list_cannot_supply_preview_evidence() {
        let pack = create_pack();
        let command = format!(
            "helm uninstall {}--description --dry-run",
            "release ".repeat(4_000)
        );
        assert_no_safe_match(&pack, &command);
        assert_blocks(&pack, &command, "uninstall");
        let dry_run = pack
            .safe_patterns
            .iter()
            .find(|pattern| pattern.name == "helm-dry-run")
            .expect("dry-run rule exists");
        assert!(!crate::packs::regex_engine::needs_backtracking_engine(
            dry_run.regex.as_str()
        ));
    }

    #[test]
    fn helm_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo helm");
    }
}

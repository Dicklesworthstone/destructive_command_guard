//! Kustomize patterns - protections against destructive kustomize commands.
//!
//! This includes patterns for:
//! - kustomize with kubectl delete
//! - Potentially dangerous kustomize builds applied directly

use crate::destructive_pattern;
use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, SafePattern};

// Exemption-only pflag grammar. A required value consumes the next token,
// including a token that looks like --dry-run. Boolean options do not.
// Unknown options, quoting, expansion syntax, and `--` refuse the exemption.
// Do not use this grammar to narrow destructive matching (#429/#435).
macro_rules! kubectl_global_option {
    () => {
        concat!(
            r"(?:--(?:as|as-group|as-uid|as-user-extra|cache-dir|certificate-authority|client-certificate|client-key|cluster|context|kubeconfig|kuberc|namespace|password|profile|profile-output|proxy-url|request-timeout|server|tls-server-name|token|user|username|v|vmodule)",
            r"(?:=[^\s;&|<>()\x22'\\$`*?\[\]{}~]+|[ \t]+[^\s;&|<>()\x22'\\$`*?\[\]{}~]+)",
            r"|-[nsv](?:[^\s;&|<>()\x22'\\$`*?\[\]{}~]+|[ \t]+[^\s;&|<>()\x22'\\$`*?\[\]{}~]+)",
            r"|--(?:disable-compression|insecure-skip-tls-verify|match-server-version|warnings-as-errors|help)(?:=(?:true|false))?|-h)"
        )
    };
}

macro_rules! kubectl_delete_argument {
    () => {
        concat!(
            r"(?:",
            kubectl_global_option!(),
            r"|--(?:filename|kustomize|selector|field-selector|grace-period|timeout|output)",
            r"(?:=[^\s;&|<>()\x22'\\$`*?\[\]{}~]+|[ \t]+[^\s;&|<>()\x22'\\$`*?\[\]{}~]+)",
            r"|-[fklo](?:[^\s;&|<>()\x22'\\$`*?\[\]{}~]+|[ \t]+[^\s;&|<>()\x22'\\$`*?\[\]{}~]+)",
            r"|--(?:all|all-namespaces|force|ignore-not-found|now|wait|interactive|recursive)(?:=(?:true|false))?",
            r"|--cascade(?:=(?:background|foreground|orphan|true|false))?",
            r"|-[ARi]|[^\s;&|<>()\x22'\\$`*?\[\]{}~-][^\s;&|<>()\x22'\\$`*?\[\]{}~]*|-)"
        )
    };
}

// One proof for BOTH the pack whitelist and the evaluator's whole-command
// destructive fallback. Evaluating safe patterns per segment alone is not
// enough: the fallback legitimately matches a rendering/deletion pipeline.
// The optional producer is one literal rendering command, and the receiving
// kubectl must have a positive preview in an option slot. The full-input
// exclusion below additionally enforces \A/\z and uses only the linear engine.
const PREVIEW_PATTERN: &str = concat!(
    r"^[ \t]*(?:(?:(?:[^\s;&|<>()\x22'\\$`*?\[\]{}~]+/)?kustomize[ \t]+build|(?:[^\s;&|<>()\x22'\\$`*?\[\]{}~]+/)?kubectl[ \t]+kustomize)",
    r"(?:[ \t]+[^\s;&|<>()\x22'\\$`*?\[\]{}~]+)*[ \t]*\|[ \t]*)?",
    r"(?:[^\s;&|<>()\x22'\\$`*?\[\]{}~]+/)?kubectl[ \t]+(?:",
    kubectl_global_option!(),
    r"[ \t]+)*delete(?:[ \t]+",
    kubectl_delete_argument!(),
    r")*[ \t]+--dry-run(?:=(?:client|server))?(?:[ \t]+(?:",
    kubectl_delete_argument!(),
    r"|--dry-run(?:=(?:client|server))?))*[ \t]*$"
);

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
    // Plain build/render/diff commands do not need exemptions: they do not
    // match the delete rules. Searching for those words in arbitrary argv
    // data can instead shield a deletion (`--cache-dir diff`, for example).
    // --raw is intentionally not part of the preview grammar.
    vec![SafePattern {
        name: "kustomize-dry-run",
        regex: LazyCompiledRegex::new(PREVIEW_PATTERN),
    }]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    // Keep candidates permissive. Preview proofs run separately below, not
    // inside negative lookaheads whose backtracking failure can lose a denial.
    vec![
        // kustomize build | kubectl delete
        destructive_pattern!(
            "kustomize-delete",
            r"kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b.*?\bdelete",
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
            r"kubectl\b.*?\bkustomize\s+.*\|\s*kubectl\b.*?\bdelete",
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
        // Match -k after other flags too, including attached/long values.
        destructive_pattern!(
            "kubectl-delete-k",
            r"kubectl\b.*?\bdelete\b.*(?:\s-k\S*|\s--kustomize(?:=|\s|$))",
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
    .into_iter()
    .map(|mut pattern| {
        pattern.regex = pattern.regex.excluding_full_match(PREVIEW_PATTERN);
        pattern
    })
    .collect()
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
    fn kustomize_diff_argument_does_not_exempt_delete() {
        // Exercise this pack alone: kubernetes.kubectl must not be needed
        // to compensate for a pipeline-wide safe match in this pack.
        let pack = create_pack();
        for command in [
            "kustomize build ./prod | kubectl delete -f - --cache-dir diff",
            "kustomize build ./prod | kubectl --cache-dir diff delete -f -",
            "kustomize build ./prod | kubectl delete -f - --context diff",
            "kustomize build ./prod | kubectl delete -f - --cache-dir 'diff'",
            "kustomize build ./prod | kubectl delete -f - diff",
            "kustomize build ./prod | kubectl delete -f -; echo diff",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks(&pack, command, "kustomize");
        }
    }

    #[test]
    fn kustomize_blocks_kubectl_delete_k() {
        let pack = create_pack();
        for command in [
            "kubectl delete -k ./overlays/prod",
            "kubectl delete --context prod -k ./overlays/prod",
            "kubectl delete --force -k./overlays/prod",
            "kubectl delete --kustomize ./overlays/prod",
            "kubectl delete --kustomize=./overlays/prod",
            "kubectl delete -k ./prod --cache-dir 'kustomize build'",
        ] {
            assert_blocks_with_pattern(&pack, command, "kubectl-delete-k");
        }
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
        for command in [
            "kustomize build ./overlays/prod | kubectl diff -f -",
            "kustomize build ./overlays/prod | kubectl --context prod diff -f -",
            "kubectl kustomize ./overlays/prod | kubectl diff -f -",
        ] {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn kustomize_safe_with_dry_run() {
        let pack = create_pack();
        assert_allows(
            &pack,
            "kustomize build ./overlays/prod | kubectl apply --dry-run=client -f -",
        );
        for command in [
            "kustomize build ./overlays/prod | kubectl delete --dry-run=client -f -",
            "kubectl kustomize ./overlays/prod | kubectl delete --dry-run=server -f -",
            "kustomize build ./prod | kubectl --context prod delete -f - --dry-run=client",
            "kubectl delete -k ./prod --dry-run=client",
            "kubectl delete --dry-run=client -k ./prod",
            "kubectl delete -k./prod --dry-run=client",
            "kubectl delete --kustomize=./prod --dry-run=server",
            "kubectl delete --context prod -k ./prod --dry-run=server",
            "kubectl delete -k ./prod --cascade=foreground --dry-run=client",
            "kubectl delete -k ./prod --dry-run=client --dry-run=server",
            "kubectl delete -k ./prod --dry-run=client --cache-dir --dry-run=none",
        ] {
            assert_safe_pattern_matches(&pack, command);
            assert_allows(&pack, command);
            // The hook's whole-command fallback does not consult the pack
            // whitelist again. Test the matching APIs that it actually uses.
            for pattern in &pack.destructive_patterns {
                assert_eq!(pattern.regex.full_match_exclusion(), Some(PREVIEW_PATTERN));
                assert!(!pattern.regex.is_match(command), "fallback: {command}");
                assert_eq!(pattern.regex.find(command), None);
                assert_eq!(pattern.regex.find_from(command, 0), None);
            }
        }
    }

    #[test]
    fn kustomize_dry_run_data_and_disabling_repeats_do_not_exempt_delete() {
        let pack = create_pack();
        for command in [
            "kustomize build ./prod | kubectl delete -f - --cache-dir --dry-run=client",
            "kustomize build ./prod | kubectl delete -f - --cache-dir=--dry-run=client",
            "kubectl kustomize ./prod | kubectl delete -f - --context --dry-run=server",
            "kubectl delete -k ./prod --context --dry-run=client",
            "kubectl delete -k ./prod --cache-dir=--dry-run=client",
            "kubectl delete -k ./prod -- --dry-run=client",
            "kubectl delete -k ./prod --dry-run=client --dry-run=none",
            "kubectl delete -k ./prod --dry-run=server --dry-run=false",
            "kubectl delete -k ./prod --dry-run=none --dry-run=client",
            "kubectl delete -k ./prod --dry-run=client --cache-dir *",
            "kubectl delete -k ./prod --dry-run=client --raw /api/v1/pods",
            "kustomize build ./prod | kubectl delete --dry-run=client -f - | kubectl delete -f -",
            "kustomize build 'x | kubectl delete --dry-run=client' | kubectl delete -f -",
            "kustomize build ./prod | kubectl delete -f - --cache-dir 'note --dry-run=client'",
        ] {
            assert_no_safe_match(&pack, command);
            assert_blocks(&pack, command, "kustomiz");
            assert!(
                pack.destructive_patterns
                    .iter()
                    .any(|pattern| pattern.regex.find_from(command, 0).is_some()),
                "whole-command fallback must retain a denial: {command}"
            );
        }
    }

    #[test]
    fn quoted_preview_evidence_stays_data_after_normalization() {
        let pack = create_pack();
        let source =
            "kustomize build ./prod | kubectl delete -f - --cache-dir \"note --dry-run=client\"";
        let normalized = crate::normalize::normalize_command(source);
        assert!(normalized.contains("\"note --dry-run=client\""));
        assert_blocks(&pack, normalized.as_ref(), "kustomize");
        let sanitized = crate::context::sanitize_for_pattern_matching(normalized.as_ref());
        assert_blocks(&pack, sanitized.as_ref(), "kustomize");
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

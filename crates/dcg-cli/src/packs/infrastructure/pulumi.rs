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
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand stops a stack name containing the
    // subcommand keyword (e.g. `preview-stack`, `config-backup`) from
    // making a destructive command short-circuit as safe. Without this
    // anchor, `pulumi destroy preview-stack` would match `pulumi-preview`
    // via `preview` in `preview-stack` and bypass the destroy rule.
    vec![
        // preview is safe (read-only)
        safe_pattern!(
            "pulumi-preview",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+preview(?=\s|$)"
        ),
        // stack ls/select/init are safe
        safe_pattern!(
            "pulumi-stack-ls",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stack\s+ls(?=\s|$)"
        ),
        safe_pattern!(
            "pulumi-stack-select",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stack\s+select(?=\s|$)"
        ),
        safe_pattern!(
            "pulumi-stack-init",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stack\s+init(?=\s|$)"
        ),
        // config is safe
        safe_pattern!(
            "pulumi-config",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s|$)"
        ),
        // whoami is safe
        safe_pattern!(
            "pulumi-whoami",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s|$)"
        ),
        // version is safe
        safe_pattern!(
            "pulumi-version",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)"
        ),
        // about is safe
        safe_pattern!(
            "pulumi-about",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+about(?=\s|$)"
        ),
        // logs is safe
        safe_pattern!(
            "pulumi-logs",
            r"pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // destroy. Trailing `(?=\s|$)` so `pulumi up destroy-plan.yaml`
        // (a stack with "destroy" in its name) doesn't false-match.
        destructive_pattern!(
            "destroy",
            r"pulumi\b.*?\bdestroy(?=\s|$)",
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
            r"pulumi\b.*?\bup\s+.*(?:-y\b|--yes\b)",
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
            r"pulumi\b.*?\bstate\s+delete",
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
            r"pulumi\b.*?\bstack\s+rm",
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
            r"pulumi\b.*?\brefresh\s+.*(?:-y\b|--yes\b)",
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
            r"pulumi\b.*?\bcancel\b",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn pulumi_patterns_match_with_global_flags() {
        // Pulumi global flags (`--cwd`, `--logflow`, `--logtostderr`,
        // `--verbose`, `--profiling`, `--non-interactive`) between
        // `pulumi` and the subcommand broke every pattern until the
        // `pulumi\b.*?\b<sub>` sweep.
        let pack = create_pack();
        assert_blocks(&pack, "pulumi --cwd ./prod destroy", "destroy");
        assert_blocks(&pack, "pulumi --non-interactive --cwd ./prod up -y", "-y");
        assert_blocks(
            &pack,
            "pulumi --cwd ./prod state delete urn:pulumi:prod::db::aws:rds/instance:Instance::main",
            "state",
        );
        assert_blocks(
            &pack,
            "pulumi --verbose --cwd ./prod stack rm prod-old",
            "stack rm",
        );
    }

    #[test]
    fn pulumi_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "pulumi destroy", "destroy");
        assert_blocks(&pack, "pulumi up -y", "skips confirmation");
        assert_blocks(&pack, "pulumi up --yes", "skips confirmation");
        assert_blocks(
            &pack,
            "pulumi state delete urn:pulumi:prod::db::aws:rds/instance:Instance::main",
            "state delete",
        );
        assert_blocks(&pack, "pulumi stack rm prod-old", "stack rm");
        assert_blocks(&pack, "pulumi refresh -y", "refresh -y");
        assert_blocks(&pack, "pulumi refresh --yes", "refresh");
        assert_blocks(&pack, "pulumi cancel", "cancel");
    }

    #[test]
    fn pulumi_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "pulumi destroy", Severity::Critical);
        assert_blocks_with_severity(&pack, "pulumi up -y", Severity::High);
        assert_blocks_with_severity(&pack, "pulumi state delete urn:foo", Severity::High);
        assert_blocks_with_severity(&pack, "pulumi stack rm prod", Severity::High);
        assert_blocks_with_severity(&pack, "pulumi refresh -y", Severity::Medium);
        assert_blocks_with_severity(&pack, "pulumi cancel", Severity::High);
    }

    #[test]
    fn pulumi_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "pulumi preview");
        assert_safe_pattern_matches(&pack, "pulumi stack ls");
        assert_safe_pattern_matches(&pack, "pulumi stack select prod");
        assert_safe_pattern_matches(&pack, "pulumi stack init dev");
        assert_safe_pattern_matches(&pack, "pulumi config");
        assert_safe_pattern_matches(&pack, "pulumi whoami");
        assert_safe_pattern_matches(&pack, "pulumi version");
        assert_safe_pattern_matches(&pack, "pulumi about");
        assert_safe_pattern_matches(&pack, "pulumi logs");
    }

    #[test]
    fn pulumi_safe_with_global_flags() {
        let pack = create_pack();
        assert_allows(&pack, "pulumi --cwd ./prod preview");
        assert_allows(&pack, "pulumi --non-interactive stack ls");
        assert_allows(&pack, "pulumi --verbose config get key");
    }

    #[test]
    fn pulumi_destroy_does_not_false_match_stack_name() {
        let pack = create_pack();
        assert_allows(&pack, "pulumi up destroy-plan.yaml");
    }

    #[test]
    fn pulumi_subcommand_as_substring_does_not_bypass() {
        let pack = create_pack();
        assert_blocks(&pack, "pulumi destroy preview-stack", "destroy");
        assert_blocks(&pack, "pulumi destroy config-backup", "destroy");
    }

    #[test]
    fn pulumi_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo pulumi");
    }
}

//! Atmos patterns - protections against destructive Atmos CLI operations.
//!
//! Atmos (atmos.tools) is a CLI from Cloud Posse that orchestrates
//! Terraform/OpenTofu and Helmfile across "stacks" and "components". It wraps
//! those tools but adds its own verbs, so this pack mirrors the terraform pack's
//! destructive coverage for `atmos terraform <verb>` AND adds the Atmos-specific
//! gaps that no terraform rule can reach:
//!
//! - `atmos terraform deploy` -> runs `apply` with `-auto-approve` injected
//!   (the `deploy` verb has no native terraform counterpart).
//! - `atmos terraform clean`  -> deletes local state and generated files
//!   (`.terraform/`, varfiles, backend config, `terraform.tfstate.d`).
//! - `atmos helmfile destroy` -> removes Helm releases (the command contains
//!   `helmfile`, not `terraform`/`tofu`, so no terraform rule matches it).
//!
//! The pack is SELF-CONTAINED: it protects Atmos users even when the
//! `infrastructure.terraform` pack is not enabled. (An Atmos repo keeps its
//! `.tf` files nested under `components/terraform/<name>/`, so the terraform
//! pack's project auto-detection often does not fire.) When both packs are
//! enabled the overlap is harmless - the first matching pattern wins.
//!
//! Design (mirrors `infrastructure.terraform`): destructive rules use a loose
//! `.*?` between tokens so global flags - including quoted multi-word values
//! like `--base-path './my dir'` - cannot defeat the match. Safe (whitelist)
//! rules instead anchor the subcommand to its slot with a flag-skipping prefix,
//! and because `Pack::check` evaluates safe patterns FIRST, a component/stack
//! literally named `deploy`/`clean`/`destroy` under a read-only subcommand
//! (e.g. `atmos terraform plan deploy -s prod`) is whitelisted before the
//! destructive rules run.
//!
//! OpenTofu under Atmos is selected via `atmos.yaml`
//! (`components.terraform.command: tofu`) and is still invoked as
//! `atmos terraform ...`; the `tofu`/`opentofu` tokens are accepted defensively.
//! Interactive `atmos terraform apply` (no `-auto-approve`) is intentionally
//! allowed, matching the terraform pack's philosophy.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Atmos pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "infrastructure.atmos".to_string(),
        name: "Atmos",
        description: "Protects against destructive Atmos operations like terraform deploy \
                      (auto-approve), destroy, clean, state rm/taint, and helmfile destroy",
        keywords: &["atmos"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Whitelist read-only subcommands. The `(?:\s+--?\S+(?:\s+\S+)?)*` fragments
    // skip optional global flags after `atmos` and after the tool word, and the
    // subcommand is anchored to its slot with `(?=\s|$)` so a component named
    // like a verb cannot be whitelisted by accident. Evaluated before the
    // destructive rules (see module docs), so these also stop a safe subcommand
    // with a verb-like component from tripping a destructive rule.
    vec![
        // plan is safe (read-only) - but NOT `plan -destroy` (handled below).
        safe_pattern!(
            "atmos-terraform-plan",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tf|tofu|opentofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+plan(?=\s|$)(?!\s+.*-destroy)"
        ),
        // output is safe (read-only)
        safe_pattern!(
            "atmos-terraform-output",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tf|tofu|opentofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+output(?=\s|$)"
        ),
        // validate is safe (read-only)
        safe_pattern!(
            "atmos-terraform-validate",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:terraform|tf|tofu|opentofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+validate(?=\s|$)"
        ),
        // describe is safe (read-only inspection of stacks/components/config)
        safe_pattern!(
            "atmos-describe",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+describe\b"
        ),
        // helmfile diff is safe (read-only)
        safe_pattern!(
            "atmos-helmfile-diff",
            r"atmos\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:helmfile|hf)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // plan -destroy is a preview but worth flagging. Keep BEFORE the broader
        // destroy rule so the preview keeps its Medium severity (mirrors the
        // terraform pack ordering).
        destructive_pattern!(
            "atmos-plan-destroy",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bplan\s+.*-destroy",
            "atmos terraform plan -destroy previews destruction. Review carefully before deploying.",
            Medium,
            "atmos terraform plan -destroy shows a destruction preview:\n\n\
             - Read-only (safe to run), but shows what WOULD be destroyed\n\
             - Review the output carefully before applying/deploying\n\n\
             This is the safe way to preview a destroy."
        ),
        // destroy tears down all managed infrastructure for the component/stack.
        destructive_pattern!(
            "atmos-destroy",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bdestroy(?=\s|$)",
            "atmos terraform destroy removes ALL managed infrastructure for the component/stack.",
            Critical,
            "atmos terraform destroy removes managed infrastructure:\n\n\
             - Every resource in the component's state is destroyed\n\
             - --all / --affected destroy across MANY components at once\n\
             - Cannot be undone without backups/recreation\n\n\
             Preview first: atmos terraform plan -destroy <component> -s <stack>"
        ),
        // deploy = apply -auto-approve. Atmos rewrites `deploy` to `apply` and
        // injects -auto-approve, so it never reaches the apply-auto-approve rule.
        destructive_pattern!(
            "atmos-deploy",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bdeploy(?=\s|$)",
            "atmos terraform deploy runs apply with -auto-approve (no confirmation). Preview with 'atmos terraform plan' first.",
            High,
            "atmos terraform deploy auto-approves an apply:\n\n\
             - Atmos rewrites 'deploy' to 'apply' and injects -auto-approve\n\
             - Changes are applied immediately, with no confirmation prompt\n\
             - May destroy or recreate resources\n\
             - --all / --affected deploy across MANY components at once\n\n\
             Preview first: atmos terraform plan <component> -s <stack>"
        ),
        // explicit apply -auto-approve (e.g. when a user passes the flag directly).
        destructive_pattern!(
            "atmos-apply-auto-approve",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bapply\s+.*-auto-approve",
            "atmos terraform apply -auto-approve skips confirmation. Remove -auto-approve for safety.",
            High,
            "atmos terraform apply -auto-approve skips confirmation:\n\n\
             - No opportunity to review changes before applying\n\
             - Changes may destroy or recreate resources\n\n\
             For safety: remove -auto-approve and review the plan"
        ),
        // clean deletes local Terraform artifacts/state. With no component it
        // cleans ALL components; --everything also removes local state dirs.
        destructive_pattern!(
            "atmos-clean",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bclean(?=\s|$)",
            "atmos terraform clean deletes local Terraform state and generated files.",
            High,
            "atmos terraform clean removes local Terraform artifacts:\n\n\
             - Deletes .terraform/, generated varfiles, and backend config\n\
             - --everything also removes local state (terraform.tfstate.d)\n\
             - With no component specified, cleans ALL components\n\
             - --force/-f skips the confirmation prompt\n\n\
             Ensure state is in a remote backend or backed up first"
        ),
        // taint marks a resource for destruction + recreation on next apply.
        destructive_pattern!(
            "atmos-taint",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\btaint\b",
            "atmos terraform taint marks a resource to be destroyed and recreated on next apply.",
            High,
            "atmos terraform taint marks a resource for recreation:\n\n\
             - Resource will be destroyed on the next apply/deploy\n\
             - May cause downtime during recreation\n\n\
             Use -replace in plan/apply instead (Terraform 0.15.2+)"
        ),
        // state rm orphans a resource (removes from state, leaves it in the cloud).
        destructive_pattern!(
            "atmos-state-rm",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bstate\s+rm\b",
            "atmos terraform state rm removes a resource from state without destroying it. Resource becomes unmanaged.",
            High,
            "atmos terraform state rm orphans resources:\n\n\
             - Resource removed from Terraform state\n\
             - Actual cloud resource still exists but becomes unmanaged\n\
             - May cause drift between state and reality\n\n\
             Back up state first"
        ),
        // state mv can cause recreation if done incorrectly.
        destructive_pattern!(
            "atmos-state-mv",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bstate\s+mv\b",
            "atmos terraform state mv moves resources in state. Incorrect moves can cause resource recreation.",
            High,
            "atmos terraform state mv moves resources in state:\n\n\
             - Renames a resource address in the state file\n\
             - A wrong move can cause destruction/recreation\n\n\
             Preview first: terraform state mv -dry-run SOURCE DEST"
        ),
        // force-unlock removes a state lock (risk of corruption if misused).
        destructive_pattern!(
            "atmos-force-unlock",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bforce-unlock\b",
            "atmos terraform force-unlock removes a state lock. Only use if the lock is stale.",
            High,
            "atmos terraform force-unlock removes state locks:\n\n\
             - May cause corruption if another operation is running\n\
             - Only use when you're sure no other operation is active\n\n\
             Verify no other operations: check CI/CD pipelines, other users"
        ),
        // workspace delete removes a workspace and its state.
        destructive_pattern!(
            "atmos-workspace-delete",
            r"atmos\b.*?\b(?:terraform|tf|tofu|opentofu)\b.*?\bworkspace\s+delete\b",
            "atmos terraform workspace delete removes a workspace and its state.",
            Medium,
            "atmos terraform workspace delete removes a workspace:\n\n\
             - Workspace and its state file are deleted\n\
             - Resources become unmanaged (orphaned)\n\
             - Cannot be undone without a state backup\n\n\
             Destroy resources first, then delete the workspace"
        ),
        // helmfile destroy removes Helm releases from the cluster. The command
        // contains `helmfile`, not `terraform`/`tofu`, so no terraform rule
        // matches it. Full teardown -> Critical (parity with terraform destroy).
        destructive_pattern!(
            "atmos-helmfile-destroy",
            r"atmos\b.*?\b(?:helmfile|hf)\b.*?\bdestroy(?=\s|$)",
            "atmos helmfile destroy removes Helm releases from the cluster.",
            Critical,
            "atmos helmfile destroy tears down Helm releases:\n\n\
             - Deletes the component's Helm releases from the cluster\n\
             - Workloads, services, and their data may be removed\n\
             - Cannot be undone without redeploying\n\n\
             Inspect first: atmos helmfile diff <component> -s <stack>"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn atmos_blocks_atmos_specific_verbs() {
        let pack = create_pack();
        // deploy = apply -auto-approve, the core gap.
        assert_blocks(&pack, "atmos terraform deploy vpc -s prod", "auto-approve");
        assert_blocks(&pack, "atmos tf deploy vpc -s prod", "auto-approve");
        // OpenTofu tool tokens accepted defensively.
        assert_blocks(&pack, "atmos tofu deploy vpc -s prod", "auto-approve");
        // Mass deploy across components.
        assert_blocks(&pack, "atmos terraform deploy --affected", "auto-approve");
        // clean deletes local state/artifacts.
        assert_blocks(&pack, "atmos terraform clean", "clean");
        assert_blocks(&pack, "atmos terraform clean --everything --force", "clean");
        // helmfile destroy (no terraform token in the string).
        assert_blocks(&pack, "atmos helmfile destroy app -s prod", "Helm");
        assert_blocks(&pack, "atmos hf destroy app -s prod", "Helm");
    }

    #[test]
    fn atmos_blocks_terraform_passthrough_verbs_when_pack_standalone() {
        // The pack is self-contained: these must block even if the terraform
        // pack is disabled (an Atmos repo often won't auto-enable it).
        let pack = create_pack();
        assert_blocks(&pack, "atmos terraform destroy vpc -s prod", "destroy");
        assert_blocks(
            &pack,
            "atmos terraform plan -destroy vpc -s prod",
            "plan -destroy",
        );
        assert_blocks(
            &pack,
            "atmos terraform apply -auto-approve vpc -s prod",
            "auto-approve",
        );
        assert_blocks(
            &pack,
            "atmos terraform taint vpc -s prod aws_instance.x",
            "taint",
        );
        assert_blocks(
            &pack,
            "atmos terraform state rm vpc -s prod aws_s3_bucket.data",
            "state rm",
        );
        assert_blocks(
            &pack,
            "atmos terraform state mv vpc -s prod a b",
            "state mv",
        );
        assert_blocks(
            &pack,
            "atmos terraform force-unlock vpc -s prod abc123",
            "force-unlock",
        );
        assert_blocks(
            &pack,
            "atmos terraform workspace delete old-workspace",
            "workspace delete",
        );
    }

    #[test]
    fn atmos_tofu_and_aliases_have_parity() {
        // OpenTofu under Atmos normally rides through `atmos terraform ...`
        // (selected via atmos.yaml config), but the `tofu`/`opentofu`/`tf`
        // tool tokens are accepted so every rule covers them identically.
        let pack = create_pack();
        assert_blocks(&pack, "atmos tofu deploy vpc -s prod", "auto-approve");
        assert_blocks(&pack, "atmos tofu destroy vpc -s prod", "destroy");
        assert_blocks(&pack, "atmos tofu clean --everything --force", "clean");
        assert_blocks(
            &pack,
            "atmos tofu taint vpc -s prod aws_instance.x",
            "taint",
        );
        assert_blocks(
            &pack,
            "atmos tofu state rm vpc -s prod aws_s3_bucket.data",
            "state rm",
        );
        assert_blocks(
            &pack,
            "atmos tofu plan -destroy vpc -s prod",
            "plan -destroy",
        );
        assert_blocks(&pack, "atmos opentofu deploy vpc -s prod", "auto-approve");
        assert_blocks(&pack, "atmos tf destroy vpc -s prod", "destroy");
        // Severity parity for the tofu token.
        assert_blocks_with_severity(&pack, "atmos tofu destroy vpc -s prod", Severity::Critical);
        assert_blocks_with_severity(&pack, "atmos tofu deploy vpc -s prod", Severity::High);
        // Read-only and interactive apply stay allowed for tofu too.
        assert_allows(&pack, "atmos tofu plan vpc -s prod");
        assert_allows(&pack, "atmos tofu apply vpc -s prod");
        assert_allows(&pack, "atmos tofu output vpc -s prod");
    }

    #[test]
    fn atmos_quoted_multiword_flag_does_not_bypass() {
        // A quoted, space-containing global-flag value must not let a
        // destructive subcommand escape (regression for the flag-skip bypass).
        let pack = create_pack();
        assert_blocks(
            &pack,
            "atmos --base-path './my long dir' terraform clean vpc -s prod",
            "clean",
        );
        assert_blocks(
            &pack,
            "atmos --logs-level 'Trace and more' terraform deploy vpc -s prod",
            "auto-approve",
        );
    }

    #[test]
    fn atmos_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(
            &pack,
            "atmos terraform destroy vpc -s prod",
            Severity::Critical,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos terraform plan -destroy vpc -s prod",
            Severity::Medium,
        );
        assert_blocks_with_severity(&pack, "atmos terraform deploy vpc -s prod", Severity::High);
        assert_blocks_with_severity(&pack, "atmos terraform clean", Severity::High);
        assert_blocks_with_severity(
            &pack,
            "atmos terraform taint vpc -s prod aws_instance.x",
            Severity::High,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos terraform workspace delete dev",
            Severity::Medium,
        );
        assert_blocks_with_severity(
            &pack,
            "atmos helmfile destroy app -s prod",
            Severity::Critical,
        );
    }

    #[test]
    fn atmos_allows_read_only_and_interactive_apply() {
        let pack = create_pack();
        // Interactive apply (no -auto-approve) is intentionally allowed,
        // mirroring the terraform pack.
        assert_allows(&pack, "atmos terraform apply vpc -s prod");
        assert_allows(&pack, "atmos terraform plan vpc -s prod");
        assert_allows(&pack, "atmos terraform output vpc -s prod");
        assert_allows(&pack, "atmos terraform validate vpc -s prod");
        assert_allows(&pack, "atmos describe stacks");
        assert_allows(&pack, "atmos helmfile diff app -s prod");
        // A workflow name is arbitrary and unpredictable - not matched.
        assert_allows(&pack, "atmos workflow deploy-all");
    }

    #[test]
    fn atmos_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "atmos terraform plan vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos terraform output vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos terraform validate vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos describe component vpc -s prod");
        assert_safe_pattern_matches(&pack, "atmos helmfile diff app -s prod");
    }

    #[test]
    fn atmos_component_named_like_verb_does_not_bypass() {
        // A read-only subcommand with a component named like a destructive verb
        // is whitelisted by the safe pattern (checked first), so it stays
        // ALLOWED - the verb is not in the subcommand slot.
        let pack = create_pack();
        assert_allows(&pack, "atmos terraform plan deploy -s prod");
        assert_allows(&pack, "atmos terraform plan clean -s prod");
        assert_allows(&pack, "atmos terraform output destroy -s prod");
    }

    #[test]
    fn atmos_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "echo atmos");
        assert_no_match(&pack, "atmos version");
        assert_no_match(&pack, "git status");
    }
}

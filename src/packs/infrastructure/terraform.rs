//! Terraform/OpenTofu patterns - protections against destructive commands.
//!
//! OpenTofu (`tofu`) is a drop-in fork of Terraform and shares the same
//! subcommands, so every rule matches both the `terraform` and `tofu`
//! binaries.
//!
//! This includes patterns for:
//! - terraform destroy
//! - terraform taint
//! - terraform apply with -auto-approve
//! - terraform state rm

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Terraform pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "infrastructure.terraform".to_string(),
        name: "Terraform",
        description: "Protects against destructive Terraform/OpenTofu operations like destroy, \
                      taint, and apply with -auto-approve",
        keywords: &["terraform", "tofu", "destroy", "taint", "state"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // `(?=\s|$)` on each subcommand stops a workspace/module name that
    // contains the subcommand keyword as a substring from making a
    // destructive command short-circuit as safe. Without this anchor,
    // `terraform destroy plan-stack` would match `terraform-plan` via
    // `plan` in `plan-stack` and bypass the destroy rule.
    vec![
        // plan is safe (read-only)
        safe_pattern!(
            "terraform-plan",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+plan(?=\s|$)(?!\s+.*-destroy)"
        ),
        // init is safe
        safe_pattern!(
            "terraform-init",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+init(?=\s|$)"
        ),
        // validate is safe
        safe_pattern!(
            "terraform-validate",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+validate(?=\s|$)"
        ),
        // fmt is safe
        safe_pattern!(
            "terraform-fmt",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+fmt(?=\s|$)"
        ),
        // show is safe
        safe_pattern!(
            "terraform-show",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)"
        ),
        // output is safe
        safe_pattern!(
            "terraform-output",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+output(?=\s|$)"
        ),
        // state list/show are safe (read-only)
        safe_pattern!(
            "terraform-state-list",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+state\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "terraform-state-show",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+state\s+show(?=\s|$)"
        ),
        // graph is safe
        safe_pattern!(
            "terraform-graph",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+graph(?=\s|$)"
        ),
        // version is safe
        safe_pattern!(
            "terraform-version",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)"
        ),
        // providers is safe
        safe_pattern!(
            "terraform-providers",
            r"(?:terraform|tofu)\b(?:\s+--?\S+(?:\s+\S+)?)*\s+providers(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // plan -destroy is a preview but can be scary. Keep this before the
        // broader destroy rule so the preview keeps its Medium severity.
        destructive_pattern!(
            "plan-destroy",
            r"(?:terraform|tofu)\b.*?\bplan\s+.*-destroy",
            "terraform/tofu plan -destroy shows what would be destroyed. Review carefully before applying.",
            Medium,
            "terraform plan -destroy shows destruction preview:\n\n\
             - This is a read-only operation (safe to run)\n\
             - Shows what WOULD be destroyed if you apply\n\
             - Review output carefully before proceeding\n\n\
             This is actually the safe way to preview destroy."
        ),
        // destroy. Trailing `(?=\s|$)` so `terraform apply destroy-plan.tf`
        // (a plan file literally named `destroy-plan.tf`) doesn't false-match.
        destructive_pattern!(
            "destroy",
            r"(?:terraform|tofu)\b.*?\bdestroy(?=\s|$)",
            "terraform/tofu destroy removes ALL managed infrastructure. Use 'terraform plan -destroy' first.",
            Critical,
            "terraform destroy removes ALL managed infrastructure:\n\n\
             - Every resource in your state file is destroyed\n\
             - Cloud resources (VMs, databases, networks) deleted\n\
             - Cannot be undone without backups/recreation\n\
             - Use -target to destroy specific resources only\n\n\
             Preview first: terraform plan -destroy"
        ),
        // apply with -auto-approve (skips confirmation)
        destructive_pattern!(
            "apply-auto-approve",
            r"(?:terraform|tofu)\b.*?\bapply\s+.*-auto-approve",
            "terraform/tofu apply -auto-approve skips confirmation. Remove -auto-approve for safety.",
            High,
            "terraform apply -auto-approve skips confirmation:\n\n\
             - No opportunity to review changes before applying\n\
             - Intended for CI/CD, not interactive use\n\
             - Changes may destroy or recreate resources\n\n\
             For safety: remove -auto-approve and review the plan"
        ),
        // taint marks resource for recreation
        destructive_pattern!(
            "taint",
            r"(?:terraform|tofu)\b.*?\btaint\b",
            "terraform/tofu taint marks a resource to be destroyed and recreated on next apply.",
            High,
            "terraform taint marks resource for recreation:\n\n\
             - Resource will be destroyed on next apply\n\
             - New resource created with same config\n\
             - May cause downtime during recreation\n\
             - IP addresses and identifiers may change\n\n\
             Use -replace in plan/apply instead (Terraform 0.15.2+)"
        ),
        // state rm removes from state (orphans resource)
        destructive_pattern!(
            "state-rm",
            r"(?:terraform|tofu)\b.*?\bstate\s+rm\b",
            "terraform/tofu state rm removes resource from state without destroying it. Resource becomes unmanaged.",
            High,
            "terraform state rm orphans resources:\n\n\
             - Resource removed from Terraform state\n\
             - Actual cloud resource still exists\n\
             - Resource becomes 'unmanaged' (Terraform ignores it)\n\
             - May cause drift between state and reality\n\n\
             Back up state first: terraform state pull > backup.tfstate"
        ),
        // state mv can cause issues if done incorrectly
        destructive_pattern!(
            "state-mv",
            r"(?:terraform|tofu)\b.*?\bstate\s+mv\b",
            "terraform/tofu state mv moves resources in state. Incorrect moves can cause resource recreation.",
            High,
            "terraform state mv moves resources in state:\n\n\
             - Renames resource address in state file\n\
             - Wrong move can cause destruction/recreation\n\
             - Use -dry-run to preview the move first\n\
             - Does not affect actual cloud resources\n\n\
             Preview first: terraform state mv -dry-run SOURCE DEST"
        ),
        // force-unlock
        destructive_pattern!(
            "force-unlock",
            r"(?:terraform|tofu)\b.*?\bforce-unlock\b",
            "terraform/tofu force-unlock removes state lock. Only use if lock is stale.",
            High,
            "terraform force-unlock removes state locks:\n\n\
             - Forces removal of a state lock\n\
             - May cause corruption if another process is running\n\
             - Only use when you're sure no other operation is active\n\
             - Lock ID required to prevent accidents\n\n\
             Verify no other operations: check CI/CD pipelines, other users"
        ),
        // workspace delete
        destructive_pattern!(
            "workspace-delete",
            r"(?:terraform|tofu)\b.*?\bworkspace\s+delete\b",
            "terraform/tofu workspace delete removes a workspace. Ensure it's not in use.",
            Medium,
            "terraform workspace delete removes workspace:\n\n\
             - Workspace and its state file deleted\n\
             - Does NOT destroy actual infrastructure\n\
             - Resources become unmanaged (orphaned)\n\
             - Cannot be undone without state backup\n\n\
             Destroy resources first: terraform destroy, then delete workspace"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn terraform_patterns_match_with_chdir_flag() {
        // Same class bug as cloud/container packs: terraform's
        // `-chdir=<path>` global flag goes BEFORE the subcommand:
        //
        //   terraform -chdir=./environments/prod destroy -auto-approve
        //
        // With `terraform\s+destroy` the `\s+` can't skip over `-chdir=…`,
        // so this destructive command escapes every rule. Enterprise
        // multi-environment setups use -chdir routinely.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "terraform -chdir=./environments/prod destroy -auto-approve",
            "destroy",
        );
        assert_blocks(
            &pack,
            "terraform -chdir=./prod apply -auto-approve",
            "auto-approve",
        );
        assert_blocks(
            &pack,
            "terraform -chdir=./prod state rm aws_instance.important",
            "state",
        );
        assert_blocks(
            &pack,
            "terraform -chdir=./prod workspace delete prod-old",
            "workspace",
        );
        assert_blocks(
            &pack,
            "terraform -chdir=./prod force-unlock abc123",
            "force-unlock",
        );
    }

    #[test]
    fn terraform_safe_patterns_do_not_bypass_via_flag_value() {
        // `-chdir=./plan-output` or `--out=plan` must not falsely
        // match safe patterns and bypass destructive rules. `\s+<sub>\b`
        // form fixes this.
        let pack = create_pack();
        assert_allows(&pack, "terraform plan");
        assert_allows(&pack, "terraform -chdir=./prod plan");
        assert_allows(&pack, "terraform show");
        assert_allows(&pack, "terraform state list");
        // Genuine destructive still blocks
        assert_blocks(&pack, "terraform destroy -auto-approve", "destroy");
    }

    #[test]
    fn terraform_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "terraform destroy", "destroy");
        assert_blocks(&pack, "terraform plan -destroy", "plan -destroy");
        assert_blocks(&pack, "terraform apply -auto-approve", "auto-approve");
        assert_blocks(&pack, "terraform taint aws_instance.web", "taint");
        assert_blocks(&pack, "terraform state rm aws_s3_bucket.data", "state rm");
        assert_blocks(
            &pack,
            "terraform state mv aws_instance.a aws_instance.b",
            "state mv",
        );
        assert_blocks(&pack, "terraform force-unlock 12345", "force-unlock");
        assert_blocks(
            &pack,
            "terraform workspace delete staging",
            "workspace delete",
        );
    }

    #[test]
    fn terraform_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "terraform destroy", Severity::Critical);
        assert_blocks_with_severity(&pack, "terraform plan -destroy", Severity::Medium);
        assert_blocks_with_severity(&pack, "terraform apply -auto-approve", Severity::High);
        assert_blocks_with_severity(&pack, "terraform taint aws_instance.x", Severity::High);
        assert_blocks_with_severity(&pack, "terraform state rm aws_instance.x", Severity::High);
        assert_blocks_with_severity(&pack, "terraform state mv a b", Severity::High);
        assert_blocks_with_severity(&pack, "terraform force-unlock 123", Severity::High);
        assert_blocks_with_severity(&pack, "terraform workspace delete dev", Severity::Medium);
    }

    #[test]
    fn terraform_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "terraform plan");
        assert_safe_pattern_matches(&pack, "terraform init");
        assert_safe_pattern_matches(&pack, "terraform validate");
        assert_safe_pattern_matches(&pack, "terraform fmt");
        assert_safe_pattern_matches(&pack, "terraform show");
        assert_safe_pattern_matches(&pack, "terraform output");
        assert_safe_pattern_matches(&pack, "terraform state list");
        assert_safe_pattern_matches(&pack, "terraform state show aws_instance.web");
        assert_safe_pattern_matches(&pack, "terraform graph");
        assert_safe_pattern_matches(&pack, "terraform version");
        assert_safe_pattern_matches(&pack, "terraform providers");
    }

    #[test]
    fn terraform_destroy_does_not_false_match_plan_file_name() {
        let pack = create_pack();
        assert_allows(&pack, "terraform apply destroy-plan.tf");
    }

    #[test]
    fn terraform_subcommand_as_substring_does_not_bypass() {
        // A workspace named "plan-stack" must not trigger the safe
        // "terraform-plan" pattern and allow "terraform destroy plan-stack".
        let pack = create_pack();
        assert_blocks(&pack, "terraform destroy plan-stack", "destroy");
        assert_blocks(&pack, "terraform destroy init-resources", "destroy");
    }

    #[test]
    fn terraform_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo terraform");
    }

    // --- OpenTofu (`tofu`) parity ---------------------------------------
    // OpenTofu is a drop-in fork of Terraform and shares the same CLI
    // surface. Every rule that fires for `terraform <x>` must fire
    // identically for `tofu <x>`. The keyword quick-reject gate in
    // src/packs/mod.rs already lists "tofu"; these tests pin the patterns
    // to it so a tofu command can never silently bypass the pack.

    #[test]
    fn tofu_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "tofu destroy", "destroy");
        assert_blocks(&pack, "tofu plan -destroy", "plan -destroy");
        assert_blocks(&pack, "tofu apply -auto-approve", "auto-approve");
        assert_blocks(&pack, "tofu taint aws_instance.web", "taint");
        assert_blocks(&pack, "tofu state rm aws_s3_bucket.data", "state rm");
        assert_blocks(
            &pack,
            "tofu state mv aws_instance.a aws_instance.b",
            "state mv",
        );
        assert_blocks(&pack, "tofu force-unlock 123", "force-unlock");
        assert_blocks(&pack, "tofu workspace delete staging", "workspace delete");
    }

    #[test]
    fn tofu_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "tofu destroy", Severity::Critical);
        assert_blocks_with_severity(&pack, "tofu plan -destroy", Severity::Medium);
        assert_blocks_with_severity(&pack, "tofu apply -auto-approve", Severity::High);
        assert_blocks_with_severity(&pack, "tofu taint aws_instance.x", Severity::High);
        assert_blocks_with_severity(&pack, "tofu state rm aws_instance.x", Severity::High);
        assert_blocks_with_severity(&pack, "tofu state mv a b", Severity::High);
        assert_blocks_with_severity(&pack, "tofu force-unlock 123", Severity::High);
        assert_blocks_with_severity(&pack, "tofu workspace delete dev", Severity::Medium);
    }

    #[test]
    fn tofu_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "tofu plan");
        assert_safe_pattern_matches(&pack, "tofu init");
        assert_safe_pattern_matches(&pack, "tofu validate");
        assert_safe_pattern_matches(&pack, "tofu fmt");
        assert_safe_pattern_matches(&pack, "tofu show");
        assert_safe_pattern_matches(&pack, "tofu output");
        assert_safe_pattern_matches(&pack, "tofu state list");
        assert_safe_pattern_matches(&pack, "tofu state show aws_instance.web");
        assert_safe_pattern_matches(&pack, "tofu graph");
        assert_safe_pattern_matches(&pack, "tofu version");
        assert_safe_pattern_matches(&pack, "tofu providers");
    }

    #[test]
    fn tofu_interactive_apply_is_allowed() {
        // Interactive `apply` (no -auto-approve) is intentionally NOT
        // blocked. Parity with terraform, not stricter.
        let pack = create_pack();
        assert_allows(&pack, "tofu apply");
        assert_allows(&pack, "terraform apply");
    }

    #[test]
    fn tofu_patterns_match_with_chdir_flag() {
        // The global `-chdir=<path>` flag precedes the subcommand for tofu
        // exactly as it does for terraform.
        let pack = create_pack();
        assert_blocks(&pack, "tofu -chdir=./environments/prod destroy", "destroy");
        assert_blocks(
            &pack,
            "tofu -chdir=./prod apply -auto-approve",
            "auto-approve",
        );
        assert_blocks(
            &pack,
            "tofu -chdir=./prod state rm aws_instance.important",
            "state",
        );
    }

    #[test]
    fn tofu_safe_patterns_do_not_bypass_via_flag_value() {
        // A flag value like `-chdir=./plan-output` must not falsely match a
        // safe pattern and bypass destructive rules for tofu either.
        let pack = create_pack();
        assert_allows(&pack, "tofu plan");
        assert_allows(&pack, "tofu -chdir=./prod plan");
        assert_allows(&pack, "tofu show");
        assert_allows(&pack, "tofu state list");
        // Genuine destructive still blocks
        assert_blocks(&pack, "tofu destroy -auto-approve", "destroy");
    }

    #[test]
    fn tofu_destroy_does_not_false_match_plan_file_name() {
        // A plan file literally named `destroy-plan.tf` must not trip the
        // destroy rule (the trailing `(?=\s|$)` guards this).
        let pack = create_pack();
        assert_allows(&pack, "tofu apply destroy-plan.tf");
    }

    #[test]
    fn tofu_subcommand_as_substring_does_not_bypass() {
        // A workspace named "plan-stack" must not trigger the safe
        // "terraform-plan" pattern and allow "tofu destroy plan-stack".
        let pack = create_pack();
        assert_blocks(&pack, "tofu destroy plan-stack", "destroy");
        assert_blocks(&pack, "tofu destroy init-resources", "destroy");
    }

    #[test]
    fn tofu_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "echo tofu");
        assert_no_match(&pack, "cat tofu-notes.txt");
    }
}

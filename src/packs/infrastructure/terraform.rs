//! Terraform patterns - protections against destructive terraform commands.
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
        description: "Protects against destructive Terraform operations like destroy, \
                      taint, and apply with -auto-approve",
        keywords: &["terraform", "destroy", "taint", "state"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // plan is safe (read-only)
        safe_pattern!("terraform-plan", r"terraform\s+plan(?!\s+.*-destroy)"),
        // init is safe
        safe_pattern!("terraform-init", r"terraform\s+init"),
        // validate is safe
        safe_pattern!("terraform-validate", r"terraform\s+validate"),
        // fmt is safe
        safe_pattern!("terraform-fmt", r"terraform\s+fmt"),
        // show is safe
        safe_pattern!("terraform-show", r"terraform\s+show"),
        // output is safe
        safe_pattern!("terraform-output", r"terraform\s+output"),
        // state list/show are safe (read-only)
        safe_pattern!("terraform-state-list", r"terraform\s+state\s+list"),
        safe_pattern!("terraform-state-show", r"terraform\s+state\s+show"),
        // graph is safe
        safe_pattern!("terraform-graph", r"terraform\s+graph"),
        // version is safe
        safe_pattern!("terraform-version", r"terraform\s+version"),
        // providers is safe
        safe_pattern!("terraform-providers", r"terraform\s+providers"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // destroy
        destructive_pattern!(
            "destroy",
            r"terraform\s+destroy",
            "terraform destroy removes ALL managed infrastructure. Use 'terraform plan -destroy' first.",
            Critical,
            "terraform destroy removes ALL managed infrastructure:\n\n\
             - Every resource in your state file is destroyed\n\
             - Cloud resources (VMs, databases, networks) deleted\n\
             - Cannot be undone without backups/recreation\n\
             - Use -target to destroy specific resources only\n\n\
             Preview first: terraform plan -destroy"
        ),
        // plan -destroy is a preview but can be scary
        destructive_pattern!(
            "plan-destroy",
            r"terraform\s+plan\s+.*-destroy",
            "terraform plan -destroy shows what would be destroyed. Review carefully before applying.",
            Medium,
            "terraform plan -destroy shows destruction preview:\n\n\
             - This is a read-only operation (safe to run)\n\
             - Shows what WOULD be destroyed if you apply\n\
             - Review output carefully before proceeding\n\n\
             This is actually the safe way to preview destroy."
        ),
        // apply with -auto-approve (skips confirmation)
        destructive_pattern!(
            "apply-auto-approve",
            r"terraform\s+apply\s+.*-auto-approve",
            "terraform apply -auto-approve skips confirmation. Remove -auto-approve for safety.",
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
            r"terraform\s+taint\b",
            "terraform taint marks a resource to be destroyed and recreated on next apply.",
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
            r"terraform\s+state\s+rm\b",
            "terraform state rm removes resource from state without destroying it. Resource becomes unmanaged.",
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
            r"terraform\s+state\s+mv\b",
            "terraform state mv moves resources in state. Incorrect moves can cause resource recreation.",
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
            r"terraform\s+force-unlock\b",
            "terraform force-unlock removes state lock. Only use if lock is stale.",
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
            r"terraform\s+workspace\s+delete\b",
            "terraform workspace delete removes a workspace. Ensure it's not in use.",
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

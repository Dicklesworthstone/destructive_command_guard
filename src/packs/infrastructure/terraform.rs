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
            "terraform destroy removes ALL managed infrastructure. Use 'terraform plan -destroy' first."
        ),
        // plan -destroy is a preview but can be scary
        destructive_pattern!(
            "plan-destroy",
            r"terraform\s+plan\s+.*-destroy",
            "terraform plan -destroy shows what would be destroyed. Review carefully before applying."
        ),
        // apply with -auto-approve (skips confirmation)
        destructive_pattern!(
            "apply-auto-approve",
            r"terraform\s+apply\s+.*-auto-approve",
            "terraform apply -auto-approve skips confirmation. Remove -auto-approve for safety."
        ),
        // taint marks resource for recreation
        destructive_pattern!(
            "taint",
            r"terraform\s+taint\b",
            "terraform taint marks a resource to be destroyed and recreated on next apply."
        ),
        // state rm removes from state (orphans resource)
        destructive_pattern!(
            "state-rm",
            r"terraform\s+state\s+rm\b",
            "terraform state rm removes resource from state without destroying it. Resource becomes unmanaged."
        ),
        // state mv can cause issues if done incorrectly
        destructive_pattern!(
            "state-mv",
            r"terraform\s+state\s+mv\b",
            "terraform state mv moves resources in state. Incorrect moves can cause resource recreation."
        ),
        // import without plan can be dangerous
        destructive_pattern!(
            "force-unlock",
            r"terraform\s+force-unlock\b",
            "terraform force-unlock removes state lock. Only use if lock is stale."
        ),
        // workspace delete
        destructive_pattern!(
            "workspace-delete",
            r"terraform\s+workspace\s+delete\b",
            "terraform workspace delete removes a workspace. Ensure it's not in use."
        ),
    ]
}

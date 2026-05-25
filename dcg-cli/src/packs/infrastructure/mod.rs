//! Infrastructure pack - protections for `IaC` tool commands.
//!
//! This pack provides protection against destructive infrastructure operations:
//! - `Terraform` (`terraform destroy`, `terraform taint`)
//! - `Ansible` (with dangerous flags)
//! - `Pulumi` (`pulumi destroy`)

pub mod ansible;
pub mod pulumi;
pub mod terraform;

//! Infrastructure pack - protections for `IaC` tool commands.
//!
//! This pack provides protection against destructive infrastructure operations:
//! - `Terraform`/`OpenTofu` (`terraform destroy`, `terraform taint`)
//! - `Ansible` (with dangerous flags)
//! - `Pulumi` (`pulumi destroy`)
//! - `Atmos` (`atmos terraform deploy`, `atmos terraform clean`, `atmos helmfile destroy`)

pub mod ansible;
pub mod atmos;
pub mod pulumi;
pub mod terraform;

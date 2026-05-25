//! Kubernetes pack - protections for Kubernetes management commands.
//!
//! This pack provides protection against destructive Kubernetes operations:
//! - kubectl (delete, drain, cordon)
//! - Helm (uninstall, delete)
//! - Kustomize (with dangerous flags)

pub mod helm;
pub mod kubectl;
pub mod kustomize;

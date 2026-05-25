//! Cloud pack - protections for cloud provider CLI commands.
//!
//! This pack provides protection against destructive cloud operations:
//! - AWS CLI (aws)
//! - Google Cloud SDK (gcloud)
//! - Azure CLI (az)

pub mod aws;
pub mod azure;
pub mod gcp;

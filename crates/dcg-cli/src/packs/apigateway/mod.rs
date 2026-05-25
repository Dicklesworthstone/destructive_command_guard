//! API Gateway packs - protections for API gateway management platforms.
//!
//! Provides protection for:
//! - AWS API Gateway (REST and HTTP APIs)
//! - Kong API Gateway (CLI, deck, Admin API)
//! - Google Apigee

pub mod apigee;
pub mod aws;
pub mod kong;

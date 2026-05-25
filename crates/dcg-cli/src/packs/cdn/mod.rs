//! CDN and edge compute pack category.
//!
//! Provides protection for CDN and edge computing platforms:
//! - Cloudflare Workers, KV, R2, D1
//! - Fastly CDN
//! - AWS `CloudFront`

pub mod cloudflare_workers;
pub mod cloudfront;
pub mod fastly;

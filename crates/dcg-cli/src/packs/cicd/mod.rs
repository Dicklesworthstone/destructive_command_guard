//! CI/CD packs - protections for common CI/CD tooling.
//!
//! These packs focus on destructive or high-impact operations in CI/CD systems.

pub mod circleci;
pub mod github_actions;
pub mod gitlab_ci;
pub mod jenkins;

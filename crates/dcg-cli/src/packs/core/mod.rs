//! Core pack - fundamental git and filesystem protections.
//!
//! This pack is always enabled and cannot be disabled.
//! It provides protection against:
//! - Git commands that destroy uncommitted work
//! - Git commands that rewrite history
//! - Git commands that destroy stashes
//! - Filesystem commands that recursively delete outside temp directories

pub mod filesystem;
pub mod git;

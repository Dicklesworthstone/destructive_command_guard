//! Container pack - protections for container management commands.
//!
//! This pack provides protection against destructive container operations:
//! - Docker (docker)
//! - Docker Compose (docker-compose, docker compose)
//! - Podman (podman)

pub mod compose;
pub mod docker;
pub mod podman;

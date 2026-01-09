//! Docker Compose patterns - protections against destructive compose commands.
//!
//! This includes patterns for:
//! - down with volumes flag
//! - rm with volumes
//! - config validation (safe)

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Docker Compose pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "containers.compose".to_string(),
        name: "Docker Compose",
        description: "Protects against destructive Docker Compose operations like \
                      'down -v' which removes volumes",
        keywords: &["docker-compose", "docker compose", "compose"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // config validation is safe
        safe_pattern!(
            "compose-config",
            r"(?:docker-compose|docker\s+compose)\s+config"
        ),
        // ps is safe (read-only)
        safe_pattern!("compose-ps", r"(?:docker-compose|docker\s+compose)\s+ps"),
        // logs is safe
        safe_pattern!(
            "compose-logs",
            r"(?:docker-compose|docker\s+compose)\s+logs"
        ),
        // up is generally safe (creates)
        safe_pattern!("compose-up", r"(?:docker-compose|docker\s+compose)\s+up"),
        // build is safe
        safe_pattern!(
            "compose-build",
            r"(?:docker-compose|docker\s+compose)\s+build"
        ),
        // pull is safe
        safe_pattern!(
            "compose-pull",
            r"(?:docker-compose|docker\s+compose)\s+pull"
        ),
        // down without -v is less destructive
        safe_pattern!(
            "compose-down-no-volumes",
            r"(?:docker-compose|docker\s+compose)\s+down(?!\s+.*(?:-v|--volumes))"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // down -v / down --volumes removes volumes
        destructive_pattern!(
            "down-volumes",
            r"(?:docker-compose|docker\s+compose)\s+down\s+.*(?:-v\b|--volumes)",
            "docker-compose down -v removes volumes and their data permanently."
        ),
        // down --rmi all removes images
        destructive_pattern!(
            "down-rmi-all",
            r"(?:docker-compose|docker\s+compose)\s+down\s+.*--rmi\s+all",
            "docker-compose down --rmi all removes all images used by services."
        ),
        // rm -v removes volumes
        destructive_pattern!(
            "rm-volumes",
            r"(?:docker-compose|docker\s+compose)\s+rm\s+.*(?:-v\b|--volumes)",
            "docker-compose rm -v removes volumes attached to containers."
        ),
        // rm -f force removes
        destructive_pattern!(
            "rm-force",
            r"(?:docker-compose|docker\s+compose)\s+rm\s+.*(?:-f\b|--force)",
            "docker-compose rm -f forcibly removes containers without confirmation."
        ),
    ]
}

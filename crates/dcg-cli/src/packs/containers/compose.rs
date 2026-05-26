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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
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
        // down without -v/--rmi is less destructive
        safe_pattern!(
            "compose-down-no-volumes",
            r"(?:docker-compose|docker\s+compose)\s+down(?!\s+.*(?:-v\b|--volumes|--rmi))"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // down -v / down --volumes removes volumes
        destructive_pattern!(
            "down-volumes",
            r"(?:docker-compose|docker\s+compose)\s+down\s+.*(?:-v\b|--volumes)",
            "docker-compose down -v removes volumes and their data permanently.",
            Critical,
            "The -v/--volumes flag causes docker-compose down to remove named volumes declared \
             in the volumes section of the Compose file, as well as anonymous volumes attached \
             to containers. This permanently destroys:\n\n\
             - Database data (PostgreSQL, MySQL, MongoDB volumes)\n\
             - User uploads and application state\n\
             - Any persistent configuration stored in volumes\n\n\
             Safer alternatives:\n\
             - docker-compose down: Stops and removes containers without touching volumes\n\
             - docker-compose stop: Stops containers, preserving everything\n\
             - docker volume ls: List volumes before removal"
        ),
        // down --rmi all removes images
        destructive_pattern!(
            "down-rmi-all",
            r"(?:docker-compose|docker\s+compose)\s+down\s+.*--rmi\s+all",
            "docker-compose down --rmi all removes all images used by services.",
            High,
            "The --rmi all flag removes all images used by services in the Compose file. \
             This forces re-downloading or rebuilding images on next 'up':\n\n\
             - Base images must be pulled again (bandwidth, time)\n\
             - Custom built images need rebuilding\n\
             - Layers not in registry are lost\n\n\
             Safer alternatives:\n\
             - docker-compose down: Preserves images for faster restarts\n\
             - docker-compose down --rmi local: Only removes images without custom tag\n\
             - docker image ls: Review images before removal"
        ),
        // rm -v removes volumes
        destructive_pattern!(
            "rm-volumes",
            r"(?:docker-compose|docker\s+compose)\s+rm\s+.*(?:-v\b|--volumes)",
            "docker-compose rm -v removes volumes attached to containers.",
            High,
            "The -v flag with docker-compose rm removes anonymous volumes attached to the \
             containers being removed. This can cause data loss if volumes contain:\n\n\
             - Application state or session data\n\
             - Cached data that takes time to rebuild\n\
             - Temporary but important processing results\n\n\
             Safer alternatives:\n\
             - docker-compose rm: Removes containers without volumes\n\
             - docker-compose stop: Stops without removing anything\n\
             - docker volume ls: Check what volumes exist"
        ),
        // rm -f force removes
        destructive_pattern!(
            "rm-force",
            r"(?:docker-compose|docker\s+compose)\s+rm\s+.*(?:-f\b|--force)",
            "docker-compose rm -f forcibly removes containers without confirmation.",
            Medium,
            "The -f/--force flag removes containers without asking for confirmation. While \
             this doesn't directly cause data loss, it can be risky:\n\n\
             - Running containers are stopped abruptly (SIGKILL)\n\
             - No graceful shutdown for applications\n\
             - In-flight requests or transactions may be lost\n\n\
             Safer alternatives:\n\
             - docker-compose stop: Graceful shutdown first\n\
             - docker-compose rm: Asks for confirmation\n\
             - docker-compose ps: Check container status first"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn compose_blocks_down_with_volumes() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose down -v", "removes volumes");
        assert_blocks(&pack, "docker-compose down --volumes", "removes volumes");
        assert_blocks(&pack, "docker compose down -v", "removes volumes");
        assert_blocks(&pack, "docker compose down --volumes", "removes volumes");
    }

    #[test]
    fn compose_blocks_down_rmi_all() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose down --rmi all", "removes all images");
        assert_blocks(&pack, "docker compose down --rmi all", "removes all images");
    }

    #[test]
    fn compose_blocks_rm_with_volumes() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose rm -v", "removes volumes");
        assert_blocks(&pack, "docker compose rm --volumes", "removes volumes");
    }

    #[test]
    fn compose_blocks_rm_force() {
        let pack = create_pack();
        assert_blocks(&pack, "docker-compose rm -f", "forcibly removes");
        assert_blocks(&pack, "docker compose rm --force", "forcibly removes");
    }

    #[test]
    fn compose_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "docker-compose down -v", Severity::Critical);
        assert_blocks_with_severity(&pack, "docker-compose down --rmi all", Severity::High);
        assert_blocks_with_severity(&pack, "docker-compose rm -v", Severity::High);
        assert_blocks_with_severity(&pack, "docker-compose rm -f", Severity::Medium);
    }

    #[test]
    fn compose_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "docker-compose config");
        assert_safe_pattern_matches(&pack, "docker compose config");
        assert_safe_pattern_matches(&pack, "docker-compose ps");
        assert_safe_pattern_matches(&pack, "docker compose ps");
        assert_safe_pattern_matches(&pack, "docker-compose logs");
        assert_safe_pattern_matches(&pack, "docker compose logs");
        assert_safe_pattern_matches(&pack, "docker-compose up");
        assert_safe_pattern_matches(&pack, "docker compose up -d");
        assert_safe_pattern_matches(&pack, "docker-compose build");
        assert_safe_pattern_matches(&pack, "docker compose pull");
    }

    #[test]
    fn compose_down_without_volumes_is_safe() {
        let pack = create_pack();
        assert_allows(&pack, "docker-compose down");
        assert_allows(&pack, "docker compose down");
    }

    #[test]
    fn compose_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
    }
}

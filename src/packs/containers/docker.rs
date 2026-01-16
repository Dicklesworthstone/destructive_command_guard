//! Docker patterns - protections against destructive docker commands.
//!
//! This includes patterns for:
//! - system prune (removes unused data)
//! - rm/rmi with force flags
//! - volume/network prune
//! - container stop/kill without confirmation

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Docker pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "containers.docker".to_string(),
        name: "Docker",
        description: "Protects against destructive Docker operations like system prune, \
                      volume prune, and force removal",
        keywords: &["docker", "prune", "rmi", "volume"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // docker ps/images/logs are safe (read-only)
        safe_pattern!("docker-ps", r"docker\s+ps"),
        safe_pattern!("docker-images", r"docker\s+images"),
        safe_pattern!("docker-logs", r"docker\s+logs"),
        // docker inspect is safe
        safe_pattern!("docker-inspect", r"docker\s+inspect"),
        // docker build is generally safe
        safe_pattern!("docker-build", r"docker\s+build"),
        // docker pull is safe
        safe_pattern!("docker-pull", r"docker\s+pull"),
        // docker run is allowed (creates, doesn't destroy)
        safe_pattern!("docker-run", r"docker\s+run"),
        // docker exec is generally safe
        safe_pattern!("docker-exec", r"docker\s+exec"),
        // docker stats is safe
        safe_pattern!("docker-stats", r"docker\s+stats"),
        // Dry-run flags
        safe_pattern!("docker-dry-run", r"docker\s+.*--dry-run"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // system prune - removes all unused data
        destructive_pattern!(
            "system-prune",
            r"docker\s+system\s+prune",
            "docker system prune removes ALL unused containers, networks, images. Use 'docker system df' to preview."
        ),
        // volume prune - removes all unused volumes
        destructive_pattern!(
            "volume-prune",
            r"docker\s+volume\s+prune",
            "docker volume prune removes ALL unused volumes and their data permanently."
        ),
        // network prune - removes all unused networks
        destructive_pattern!(
            "network-prune",
            r"docker\s+network\s+prune",
            "docker network prune removes ALL unused networks."
        ),
        // image prune - removes unused images (Medium: only affects unused images)
        destructive_pattern!(
            "image-prune",
            r"docker\s+image\s+prune",
            "docker image prune removes unused images. Use 'docker images' to review first.",
            Medium
        ),
        // container prune - removes stopped containers (Medium: only affects stopped)
        destructive_pattern!(
            "container-prune",
            r"docker\s+container\s+prune",
            "docker container prune removes ALL stopped containers.",
            Medium
        ),
        // rm -f (force remove containers)
        destructive_pattern!(
            "rm-force",
            r"docker\s+rm\s+.*(?:-[a-zA-Z0-9]*f|--force)",
            "docker rm -f forcibly removes containers, potentially losing data."
        ),
        // rmi -f (force remove images)
        destructive_pattern!(
            "rmi-force",
            r"docker\s+rmi\s+.*(?:-[a-zA-Z0-9]*f|--force)",
            "docker rmi -f forcibly removes images even if in use."
        ),
        // volume rm
        destructive_pattern!(
            "volume-rm",
            r"docker\s+volume\s+rm",
            "docker volume rm permanently deletes volumes and their data."
        ),
        // stop/kill all containers pattern
        destructive_pattern!(
            "stop-all",
            r"docker\s+(?:stop|kill)\s+\$\(docker\s+ps",
            "Stopping/killing all containers can disrupt services. Be specific about which containers."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_rm_force() {
        let pack = create_pack();
        assert_blocks(&pack, "docker rm -f container", "forcibly removes");
        assert_blocks(&pack, "docker rm --force container", "forcibly removes");
        assert_blocks(&pack, "docker rm -vf container", "forcibly removes"); // Combined flags
        assert_blocks(&pack, "docker rm -fv container", "forcibly removes");

        assert_allows(&pack, "docker rm container");
    }

    #[test]
    fn test_rmi_force() {
        let pack = create_pack();
        assert_blocks(&pack, "docker rmi -f image", "forcibly removes");
        assert_blocks(&pack, "docker rmi --force image", "forcibly removes");
        assert_blocks(&pack, "docker rmi -nf image", "forcibly removes"); // Combined flags (no-prune + force)

        assert_allows(&pack, "docker rmi image");
    }
}

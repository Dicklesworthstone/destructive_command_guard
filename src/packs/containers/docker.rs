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

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // system prune - removes all unused data
        destructive_pattern!(
            "system-prune",
            r"docker\s+system\s+prune",
            "docker system prune removes ALL unused containers, networks, images. Use 'docker system df' to preview.",
            High,
            "docker system prune is Docker's most aggressive cleanup command. It removes:\n\n\
             - All stopped containers\n\
             - All networks not used by at least one container\n\
             - All dangling images (untagged)\n\
             - All dangling build cache\n\n\
             With -a flag, it also removes all unused images, not just dangling ones.\n\
             With --volumes flag, it removes all unused volumes (data loss!).\n\n\
             Preview what would be removed:\n  \
             docker system df          # Show disk usage\n  \
             docker system df -v       # Verbose with details\n\n\
             Safer alternative:\n  \
             docker container prune    # Only stopped containers\n  \
             docker image prune        # Only dangling images"
        ),
        // volume prune - removes all unused volumes
        destructive_pattern!(
            "volume-prune",
            r"docker\s+volume\s+prune",
            "docker volume prune removes ALL unused volumes and their data permanently.",
            High,
            "docker volume prune permanently deletes ALL volumes not currently attached \
             to a running container. This is extremely dangerous because:\n\n\
             - Database data stored in volumes is lost forever\n\
             - Application state and uploads are destroyed\n\
             - There is NO recovery mechanism\n\n\
             Even stopped containers' volumes are considered 'unused' and will be deleted.\n\n\
             Preview before pruning:\n  \
             docker volume ls                    # List all volumes\n  \
             docker volume ls -f dangling=true   # Show only unused\n\n\
             Safer approach:\n  \
             docker volume rm <specific-volume>  # Remove by name"
        ),
        // network prune - removes all unused networks
        destructive_pattern!(
            "network-prune",
            r"docker\s+network\s+prune",
            "docker network prune removes ALL unused networks.",
            High,
            "docker network prune removes all user-defined networks not used by any container. \
             While less destructive than volume prune, it can still cause issues:\n\n\
             - Custom network configurations are lost\n\
             - Containers may fail to communicate after restart\n\
             - Service discovery between containers breaks\n\n\
             Preview unused networks:\n  \
             docker network ls\n  \
             docker network ls -f dangling=true\n\n\
             Safer alternative:\n  \
             docker network rm <specific-network>"
        ),
        // image prune - removes unused images (Medium: only affects unused images)
        destructive_pattern!(
            "image-prune",
            r"docker\s+image\s+prune",
            "docker image prune removes unused images. Use 'docker images' to review first.",
            Medium,
            "docker image prune removes 'dangling' images (untagged layers). \
             With -a flag, it removes ALL images not used by existing containers.\n\n\
             Consequences:\n\
             - Build cache layers are deleted (slower rebuilds)\n\
             - With -a: base images must be re-pulled\n\n\
             Preview what would be removed:\n  \
             docker images -f dangling=true\n  \
             docker images                       # With -a flag\n\n\
             Usually safe, but may slow down builds."
        ),
        // container prune - removes stopped containers (Medium: only affects stopped)
        destructive_pattern!(
            "container-prune",
            r"docker\s+container\s+prune",
            "docker container prune removes ALL stopped containers.",
            Medium,
            "docker container prune removes all stopped containers. This is relatively \
             safe but can cause issues:\n\n\
             - Container logs are lost\n\
             - Container filesystem layers are deleted\n\
             - Cannot restart or inspect removed containers\n\n\
             Preview stopped containers:\n  \
             docker ps -a -f status=exited\n  \
             docker ps -a -f status=created\n\n\
             Consider keeping recent containers for debugging."
        ),
        // rm -f (force remove containers)
        destructive_pattern!(
            "rm-force",
            r"docker\s+rm\s+.*(?:-[a-zA-Z0-9]*f|--force)",
            "docker rm -f forcibly removes containers, potentially losing data.",
            High,
            "docker rm -f forcibly stops and removes containers. This is dangerous because:\n\n\
             - Running processes are killed immediately (SIGKILL)\n\
             - No graceful shutdown - data may be corrupted\n\
             - In-flight requests are dropped\n\
             - Uncommitted data in the container is lost\n\n\
             Safer approach:\n  \
             docker stop <container>  # Graceful shutdown (SIGTERM)\n  \
             docker rm <container>    # Then remove\n\n\
             Check container status first:\n  \
             docker ps -a | grep <container>"
        ),
        // rmi -f (force remove images)
        destructive_pattern!(
            "rmi-force",
            r"docker\s+rmi\s+.*(?:-[a-zA-Z0-9]*f|--force)",
            "docker rmi -f forcibly removes images even if in use.",
            High,
            "docker rmi -f forcibly removes images, even if containers are using them. \
             This can cause:\n\n\
             - Running containers to fail on restart\n\
             - Broken references to deleted layers\n\
             - Loss of build cache\n\n\
             Check what's using the image:\n  \
             docker ps -a --filter ancestor=<image>\n\n\
             Safer approach:\n  \
             docker rmi <image>  # Fails safely if in use"
        ),
        // volume rm
        destructive_pattern!(
            "volume-rm",
            r"docker\s+volume\s+rm",
            "docker volume rm permanently deletes volumes and their data.",
            High,
            "docker volume rm permanently deletes named volumes and all data stored in them. \
             This is irreversible:\n\n\
             - Database files are gone\n\
             - User uploads are lost\n\
             - Configuration data is destroyed\n\
             - No trash or undo mechanism exists\n\n\
             Check volume contents first:\n  \
             docker run --rm -v <volume>:/data alpine ls -la /data\n\n\
             Consider backing up:\n  \
             docker run --rm -v <volume>:/data -v $(pwd):/backup alpine \\\n    \
             tar czf /backup/volume-backup.tar.gz /data"
        ),
        // stop/kill all containers pattern
        destructive_pattern!(
            "stop-all",
            r"docker\s+(?:stop|kill)\s+\$\(docker\s+ps",
            "Stopping/killing all containers can disrupt services. Be specific about which containers.",
            High,
            "This pattern stops or kills ALL running containers on the system. \
             This is dangerous in shared environments:\n\n\
             - Production services go down\n\
             - Database connections are severed\n\
             - In-flight requests fail\n\
             - Other users' containers are affected\n\n\
             Be specific instead:\n  \
             docker stop <container-name>     # Stop by name\n  \
             docker stop $(docker ps -q -f name=myapp)  # Filter by name\n\n\
             Preview what would be stopped:\n  \
             docker ps --format '{{.Names}}: {{.Status}}'"
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

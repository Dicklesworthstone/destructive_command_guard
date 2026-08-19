//! Docker patterns - protections against destructive docker commands.
//!
//! This includes patterns for:
//! - system prune (removes unused data)
//! - rm/rmi with force flags
//! - volume/network prune
//! - container stop/kill without confirmation

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

// ============================================================================
// Suggestion constants (must be 'static for the pattern struct)
// ============================================================================

/// Suggestions for `docker system prune` pattern.
const SYSTEM_PRUNE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker system df -v",
        "Preview what would be removed without deleting anything",
    ),
    PatternSuggestion::gated(
        "docker system prune --filter 'until=24h'",
        "Only removes items older than 24 hours — still a prune, so it is gated as well",
    ),
    PatternSuggestion::gated(
        "docker container prune",
        "Remove only stopped containers (preserves images and volumes) — gated as well",
    ),
    PatternSuggestion::gated(
        "docker image prune",
        "Remove only dangling images (preserves containers and volumes) — gated as well",
    ),
];

/// Suggestions for `docker volume prune` pattern.
const VOLUME_PRUNE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker volume ls -q -f dangling=true",
        "List unused volumes first to review what would be deleted",
    ),
    PatternSuggestion::gated(
        "docker volume rm {volume-name}",
        "Removes named volumes instead of all unused — still deletes volume data, so dcg gates it too",
    ),
    PatternSuggestion::new(
        "docker volume inspect {volume-name}",
        "Inspect volume contents and metadata before removal",
    ),
];

/// Suggestions for `docker network prune` pattern.
const NETWORK_PRUNE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker network ls",
        "List all networks to review before pruning",
    ),
    PatternSuggestion::new(
        "docker network rm {network-name}",
        "Remove specific networks by name instead of all unused",
    ),
];

/// Suggestions for `docker image prune` pattern.
const IMAGE_PRUNE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker images -f dangling=true",
        "List dangling images first to see what would be removed",
    ),
    PatternSuggestion::new(
        "docker rmi {image-id}",
        "Remove specific images by ID or tag",
    ),
];

/// Suggestions for `docker container prune` pattern.
const CONTAINER_PRUNE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker ps -a -f status=exited",
        "List stopped containers first to review before removal",
    ),
    PatternSuggestion::new(
        "docker rm {container-id}",
        "Remove specific containers instead of all stopped",
    ),
];

/// Suggestions for `docker rm -f` pattern.
const RM_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker stop {container} && docker rm {container}",
        "Graceful shutdown with SIGTERM before removal",
    ),
    PatternSuggestion::gated(
        "docker container prune",
        "Removes only stopped containers — still a prune, so dcg gates it too",
    ),
    PatternSuggestion::new(
        "docker ps -a | grep {container}",
        "Check container status before removal",
    ),
];

/// Suggestions for `docker rmi -f` pattern.
const RMI_FORCE_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker rmi {image}",
        "Remove without force - fails safely if image is in use",
    ),
    PatternSuggestion::gated(
        "docker image prune",
        "Removes only dangling images — still a prune, so dcg gates it too",
    ),
    PatternSuggestion::new(
        "docker ps -a --filter ancestor={image}",
        "Check what containers are using the image first",
    ),
];

/// Suggestions for `docker volume rm` pattern.
const VOLUME_RM_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker volume inspect {volume}",
        "Inspect volume metadata and mount point before removal",
    ),
    PatternSuggestion::new(
        "docker run --rm -v {volume}:/data alpine ls -la /data",
        "List volume contents before deletion",
    ),
    PatternSuggestion::new(
        "docker run --rm -v {volume}:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz /data",
        "Backup volume data before removal",
    ),
];

/// Suggestions for `docker stop/kill $(docker ps ...)` pattern.
const STOP_ALL_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "docker stop {container-name}",
        "Stop specific containers by name",
    ),
    PatternSuggestion::gated(
        "docker stop $(docker ps -q -f name={pattern})",
        "Stop containers matching a name filter — dcg gates any stop over a $(docker ps …) expansion",
    ),
    PatternSuggestion::new(
        "docker ps --format '{{.Names}}: {{.Status}}'",
        "List running containers before stopping",
    ),
];

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
    // Four safeguards on each safe subcommand:
    //   1. `^\s*docker\b` keeps the match on the top-level Docker command.
    //      Nested command substitutions like `docker stop $(docker ps -q)`
    //      must not satisfy the `docker-ps` safe pattern.
    //   2. `(?:\s+--?\S+(?:\s+\S+)?)*` only accepts flag-value pairs between
    //      `docker` and the safe subcommand — so a destructive command like
    //      `docker rm -f ps` (container literally named `ps`) can't match
    //      `docker-ps` via the positional arg.
    //   3. `(?=\s|$)` on the trailing side so a container name that starts
    //      with the subcommand keyword (e.g. `ps-container`, `logs-archive`)
    //      can't short-circuit destructive ops either.
    //   4. The trailing argument matcher excludes shell separators and command
    //      substitution markers, so a safe prefix inside a compound shell form
    //      cannot shield a destructive Docker operation.
    vec![
        // docker ps/images/logs are safe (read-only)
        safe_pattern!(
            "docker-ps",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ps(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        safe_pattern!(
            "docker-images",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+images(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        safe_pattern!(
            "docker-logs",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // docker inspect is safe
        safe_pattern!(
            "docker-inspect",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // docker build is generally safe
        safe_pattern!(
            "docker-build",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // docker pull is safe
        safe_pattern!(
            "docker-pull",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+pull(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // docker run is allowed (creates, doesn't destroy)
        safe_pattern!(
            "docker-run",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // docker exec is generally safe
        safe_pattern!(
            "docker-exec",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+exec(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // docker stats is safe
        safe_pattern!(
            "docker-stats",
            r"^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stats(?=\s|$)(?:\s+[^;&|`$()]*)*$"
        ),
        // Dry-run flags
        safe_pattern!(
            "docker-dry-run",
            r"^\s*docker\b(?:\s+[^;&|`$()]*)*--dry-run(?:\s+[^;&|`$()]*)*$"
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // system prune - removes all unused data
        destructive_pattern!(
            "system-prune",
            r"docker\b.*?\bsystem\s+prune",
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
             docker image prune        # Only dangling images",
            SYSTEM_PRUNE_SUGGESTIONS
        ),
        // volume prune - removes all unused volumes
        destructive_pattern!(
            "volume-prune",
            r"docker\b.*?\bvolume\s+prune",
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
             docker volume rm <specific-volume>  # Remove by name",
            VOLUME_PRUNE_SUGGESTIONS
        ),
        // network prune - removes all unused networks
        destructive_pattern!(
            "network-prune",
            r"docker\b.*?\bnetwork\s+prune",
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
             docker network rm <specific-network>",
            NETWORK_PRUNE_SUGGESTIONS
        ),
        // image prune - removes unused images (Medium: only affects unused images)
        destructive_pattern!(
            "image-prune",
            r"docker\b.*?\bimage\s+prune",
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
             Usually safe, but may slow down builds.",
            IMAGE_PRUNE_SUGGESTIONS
        ),
        // container prune - removes stopped containers (Medium: only affects stopped)
        destructive_pattern!(
            "container-prune",
            r"docker\b.*?\bcontainer\s+prune",
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
             Consider keeping recent containers for debugging.",
            CONTAINER_PRUNE_SUGGESTIONS
        ),
        // rm -f (force remove containers)
        destructive_pattern!(
            "rm-force",
            r"docker\b.*?\brm\s+.*(?:-[a-zA-Z0-9]*f|--force)",
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
             docker ps -a | grep <container>",
            RM_FORCE_SUGGESTIONS
        ),
        // rmi -f (force remove images)
        destructive_pattern!(
            "rmi-force",
            r"docker\b.*?\brmi\s+.*(?:-[a-zA-Z0-9]*f|--force)",
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
             docker rmi <image>  # Fails safely if in use",
            RMI_FORCE_SUGGESTIONS
        ),
        // volume rm
        destructive_pattern!(
            "volume-rm",
            r"docker\b.*?\bvolume\s+rm",
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
             tar czf /backup/volume-backup.tar.gz /data",
            VOLUME_RM_SUGGESTIONS
        ),
        // stop/kill all containers pattern: match `docker stop/kill` with a
        // `$(...)` subshell that dynamically selects targets. The regex uses
        // `\$\(` (not `\$\(docker\s+ps`) so context sanitization (which masks
        // subshell contents into `$()`) doesn't break the match.
        destructive_pattern!(
            "stop-all",
            r"docker\b.*?\b(?:stop|kill)\s+\$\(",
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
             docker stop $(docker ps -q -f name=myapp)  # Filter by name (dcg gates \
             any stop over a $(docker ps ...) expansion, so this form still needs approval)\n\n\
             Preview what would be stopped:\n  \
             docker ps --format '{{.Names}}: {{.Status}}'",
            STOP_ALL_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn docker_patterns_match_with_global_flags() {
        // Same class bug as cloud packs: Docker CLI global flags
        // (`--context`, `--host`, `--config`, `--debug`, `--log-level`,
        // `--tls*`) between `docker` and the subcommand break every
        // `docker\s+<sub>` pattern. Multi-context operators (users of
        // remote Docker daemons, testing against staging + prod)
        // regularly use `--context`, so this is mainline.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "docker --context prod volume rm critical-vol",
            "volume",
        );
        assert_blocks(
            &pack,
            "docker --host ssh://prod-host system prune --all",
            "prune",
        );
        assert_blocks(
            &pack,
            "docker --config /tmp/dc --context prod rm -f prod-db",
            "forcibly removes",
        );
        assert_blocks(
            &pack,
            "docker --log-level debug --context prod image prune --all",
            "prune",
        );
    }

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

    #[test]
    fn container_named_as_safe_subcommand_does_not_short_circuit() {
        // If a container is literally named the same as a safe subcommand
        // (e.g. `ps`, `logs`, `build`, `run`), the destructive rule must
        // still win. Previously `docker rm -f ps` matched `docker-ps` safe
        // via the positional arg.
        let pack = create_pack();
        let matched = pack
            .check("docker rm -f ps")
            .expect("container literally named `ps` must still trigger rm-force");
        assert_eq!(matched.name, Some("rm-force"));

        let matched = pack
            .check("docker rm --force logs")
            .expect("container literally named `logs` must still trigger rm-force");
        assert_eq!(matched.name, Some("rm-force"));

        let matched = pack
            .check("docker rmi -f build")
            .expect("image literally named `build` must still trigger rmi-force");
        assert_eq!(matched.name, Some("rmi-force"));
    }

    #[test]
    fn safe_subcommand_inside_container_name_does_not_short_circuit() {
        // Container names often contain subcommand keywords as substrings:
        //   ps-container, logs-archive, build-server, run-worker
        // Without the `(?=\s|$)` anchor, `docker rm -f ps-container` would
        // match the `docker-ps` safe pattern and bypass the `rm-force`
        // destructive rule.
        let pack = create_pack();
        let matched = pack
            .check("docker rm -f ps-container")
            .expect("destructive rm -f must still block when name contains ps");
        assert_eq!(matched.name, Some("rm-force"));

        let matched = pack
            .check("docker rmi -f build-server-img")
            .expect("destructive rmi -f must still block when name contains build");
        assert_eq!(matched.name, Some("rmi-force"));

        let matched = pack
            .check("docker volume rm logs-archive")
            .expect("destructive volume rm must still block when name contains logs");
        assert_eq!(matched.name, Some("volume-rm"));

        // Bare subcommands still short-circuit as safe.
        assert_allows(&pack, "docker ps");
        assert_allows(&pack, "docker logs mycontainer");
        assert_allows(&pack, "docker build -t app .");
    }

    #[test]
    fn nested_docker_ps_command_substitution_does_not_short_circuit() {
        let pack = create_pack();

        assert!(
            !pack.matches_safe("docker stop $(docker ps -q)"),
            "inner `docker ps` must not satisfy the top-level safe whitelist"
        );
        let matched = pack
            .check("docker stop $(docker ps -q)")
            .expect("stopping every running container must block");
        assert_eq!(matched.name, Some("stop-all"));

        let matched = pack
            .check("docker stop $()")
            .expect("sanitized command substitution must still block");
        assert_eq!(matched.name, Some("stop-all"));

        let matched = pack
            .check("docker kill $(docker ps -aq)")
            .expect("killing every container from docker ps must block");
        assert_eq!(matched.name, Some("stop-all"));
    }

    #[test]
    fn docker_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "docker system prune", "prune");
        assert_blocks(&pack, "docker system prune --all", "prune");
        assert_blocks(&pack, "docker volume prune", "prune");
        assert_blocks(&pack, "docker network prune", "prune");
        assert_blocks(&pack, "docker image prune", "prune");
        assert_blocks(&pack, "docker container prune", "prune");
        assert_blocks(&pack, "docker volume rm my-volume", "volume");
    }

    #[test]
    fn docker_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "docker system prune -a", Severity::High);
        assert_blocks_with_severity(&pack, "docker volume prune", Severity::High);
        assert_blocks_with_severity(&pack, "docker volume rm data-vol", Severity::High);
        assert_blocks_with_severity(&pack, "docker rm -f container", Severity::High);
        assert_blocks_with_severity(&pack, "docker rmi -f image", Severity::High);
    }

    #[test]
    fn docker_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "docker ps");
        assert_safe_pattern_matches(&pack, "docker ps -a");
        assert_safe_pattern_matches(&pack, "docker logs mycontainer");
        assert_safe_pattern_matches(&pack, "docker images");
        assert_safe_pattern_matches(&pack, "docker inspect mycontainer");
        assert_safe_pattern_matches(&pack, "docker build -t app .");
        assert_safe_pattern_matches(&pack, "docker pull nginx:latest");
        assert_safe_pattern_matches(&pack, "docker run --rm hello-world");
        assert_safe_pattern_matches(&pack, "docker exec -it container bash");
        assert_safe_pattern_matches(&pack, "docker stats");
    }

    #[test]
    fn docker_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo docker");
    }
}

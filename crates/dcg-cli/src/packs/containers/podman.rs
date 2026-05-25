//! Podman patterns - protections against destructive podman commands.
//!
//! This includes patterns for:
//! - system prune (removes unused data)
//! - rm/rmi with force flags
//! - volume/pod prune
//! - Similar to Docker but for Podman

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Podman pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "containers.podman".to_string(),
        name: "Podman",
        description: "Protects against destructive Podman operations like system prune, \
                      volume prune, and force removal",
        keywords: &["podman", "prune"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    // Two safeguards on each safe subcommand:
    //   1. `(?:\s+--?\S+(?:\s+\S+)?)*` only accepts flag-value pairs between
    //      `podman` and the safe subcommand — so a destructive command like
    //      `podman rm -f ps` (container literally named `ps`) can't match
    //      `podman-ps` via the positional arg.
    //   2. `(?=\s|$)` on the trailing side so a container name starting
    //      with the subcommand keyword (e.g. `ps-container`, `logs-archive`)
    //      can't short-circuit destructive ops either.
    vec![
        // podman ps/images/logs are safe (read-only)
        safe_pattern!(
            "podman-ps",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ps(?=\s|$)"
        ),
        safe_pattern!(
            "podman-images",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+images(?=\s|$)"
        ),
        safe_pattern!(
            "podman-logs",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)"
        ),
        // podman inspect is safe
        safe_pattern!(
            "podman-inspect",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s|$)"
        ),
        // podman build is generally safe
        safe_pattern!(
            "podman-build",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?=\s|$)"
        ),
        // podman pull is safe
        safe_pattern!(
            "podman-pull",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+pull(?=\s|$)"
        ),
        // podman run is allowed
        safe_pattern!(
            "podman-run",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s|$)"
        ),
        // podman exec is generally safe
        safe_pattern!(
            "podman-exec",
            r"podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+exec(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // system prune - removes all unused data
        destructive_pattern!(
            "system-prune",
            r"podman\b.*?\bsystem\s+prune",
            "podman system prune removes ALL unused containers, pods, images. Use 'podman system df' to preview.",
            High,
            "podman system prune is an aggressive cleanup command that removes:\n\n\
             - All stopped containers\n\
             - All pods without running containers\n\
             - All dangling images (untagged)\n\
             - All dangling build cache\n\n\
             With -a flag, removes ALL unused images. With --volumes, removes unused volumes.\n\n\
             Safer alternatives:\n\
             - podman system df: Preview disk usage first\n\
             - podman container prune: Only remove stopped containers\n\
             - podman image prune: Only remove dangling images"
        ),
        // volume prune - removes all unused volumes
        destructive_pattern!(
            "volume-prune",
            r"podman\b.*?\bvolume\s+prune",
            "podman volume prune removes ALL unused volumes and their data permanently.",
            Critical,
            "podman volume prune permanently deletes ALL volumes not currently in use by \
             any container. This is extremely dangerous:\n\n\
             - Database data in volumes is lost forever\n\
             - Application state and uploads are destroyed\n\
             - Volumes from stopped containers are considered 'unused'\n\
             - No recovery mechanism exists\n\n\
             Safer alternatives:\n\
             - podman volume ls: List all volumes first\n\
             - podman volume inspect: Check volume contents\n\
             - podman volume rm <name>: Remove specific volumes"
        ),
        // pod prune - removes stopped pods
        destructive_pattern!(
            "pod-prune",
            r"podman\b.*?\bpod\s+prune",
            "podman pod prune removes ALL stopped pods.",
            Medium,
            "podman pod prune removes all pods that are not currently running. Pods group \
             containers together and pruning them:\n\n\
             - Removes all containers within the stopped pods\n\
             - Pod configuration and networking setup is lost\n\
             - Cannot restart or inspect removed pods\n\n\
             Safer alternatives:\n\
             - podman pod ps -a: List all pods first\n\
             - podman pod rm <pod>: Remove specific pods\n\
             - podman pod start <pod>: Restart instead of removing"
        ),
        // image prune - removes unused images (Medium: only affects unused images)
        destructive_pattern!(
            "image-prune",
            r"podman\b.*?\bimage\s+prune",
            "podman image prune removes unused images. Use 'podman images' to review first.",
            Medium,
            "podman image prune removes dangling images (untagged layers). With -a flag, \
             removes ALL images not used by existing containers.\n\n\
             Consequences:\n\
             - Build cache layers are deleted (slower rebuilds)\n\
             - With -a: Base images must be re-pulled\n\n\
             Safer alternatives:\n\
             - podman images -f dangling=true: Preview what would be removed\n\
             - podman images: Review all images\n\
             - podman rmi <image>: Remove specific images"
        ),
        // container prune - removes stopped containers (Medium: only affects stopped)
        destructive_pattern!(
            "container-prune",
            r"podman\b.*?\bcontainer\s+prune",
            "podman container prune removes ALL stopped containers.",
            Medium,
            "podman container prune removes all stopped containers. Relatively safe but:\n\n\
             - Container logs are lost\n\
             - Container filesystem layers are deleted\n\
             - Cannot restart or inspect removed containers\n\n\
             Safer alternatives:\n\
             - podman ps -a: List all containers first\n\
             - podman rm <container>: Remove specific containers\n\
             - podman start <container>: Restart instead of removing"
        ),
        // rm -f (force remove containers)
        destructive_pattern!(
            "rm-force",
            r"podman\b.*?\brm\s+.*(?:-[a-zA-Z0-9]*f|--force)",
            "podman rm -f forcibly removes containers, potentially losing data.",
            High,
            "podman rm -f forcibly stops and removes containers. This is dangerous because:\n\n\
             - Running processes are killed immediately (SIGKILL)\n\
             - No graceful shutdown - data may be corrupted\n\
             - In-flight requests are dropped\n\
             - Uncommitted data in the container is lost\n\n\
             Safer alternatives:\n\
             - podman stop <container>: Graceful shutdown first\n\
             - podman rm <container>: Then remove\n\
             - podman ps: Check container status first"
        ),
        // rmi -f (force remove images)
        destructive_pattern!(
            "rmi-force",
            r"podman\b.*?\brmi\s+.*(?:-[a-zA-Z0-9]*f|--force)",
            "podman rmi -f forcibly removes images even if in use.",
            High,
            "podman rmi -f forcibly removes images, even if containers reference them. \
             This can cause:\n\n\
             - Containers to fail on restart (missing image)\n\
             - Broken references to deleted layers\n\
             - Loss of build cache\n\n\
             Safer alternatives:\n\
             - podman ps -a --filter ancestor=<image>: Check what uses the image\n\
             - podman rmi <image>: Fails safely if in use\n\
             - podman images: Review images before removal"
        ),
        // volume rm
        destructive_pattern!(
            "volume-rm",
            r"podman\b.*?\bvolume\s+rm",
            "podman volume rm permanently deletes volumes and their data.",
            High,
            "podman volume rm permanently deletes named volumes and all data stored in them. \
             This is irreversible:\n\n\
             - Database files are gone forever\n\
             - User uploads are lost\n\
             - Configuration data is destroyed\n\
             - No trash or undo mechanism\n\n\
             Safer alternatives:\n\
             - podman volume inspect <volume>: Check volume details\n\
             - podman run --rm -v vol:/data alpine ls -la /data: View contents\n\
             - Back up before removal"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn podman_patterns_match_with_global_flags() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "podman --remote --connection prod volume rm critical-vol",
            "volumes",
        );
        assert_blocks(
            &pack,
            "podman --url tcp://prod:8080 system prune --all",
            "prune",
        );
        assert_blocks(
            &pack,
            "podman --log-level debug --connection prod rm -f prod-db",
            "forcibly removes",
        );
    }

    #[test]
    fn test_rm_force() {
        let pack = create_pack();
        assert_blocks(&pack, "podman rm -f container", "forcibly removes");
        assert_blocks(&pack, "podman rm --force container", "forcibly removes");
        assert_blocks(&pack, "podman rm -af", "forcibly removes");
        assert_blocks(&pack, "podman rm -vf container", "forcibly removes");
        assert_blocks(&pack, "podman rm -fv container", "forcibly removes");

        assert_allows(&pack, "podman rm container");
    }

    #[test]
    fn test_rmi_force() {
        let pack = create_pack();
        assert_blocks(&pack, "podman rmi -f image", "forcibly removes");
        assert_blocks(&pack, "podman rmi --force image", "forcibly removes");
        assert_blocks(&pack, "podman rmi -nf image", "forcibly removes");

        assert_allows(&pack, "podman rmi image");
    }

    #[test]
    fn podman_blocks_each_destructive_pattern() {
        let pack = create_pack();
        assert_blocks(&pack, "podman system prune", "prune");
        assert_blocks(&pack, "podman system prune --all", "prune");
        assert_blocks(&pack, "podman volume prune", "prune");
        assert_blocks(&pack, "podman pod prune", "prune");
        assert_blocks(&pack, "podman image prune", "prune");
        assert_blocks(&pack, "podman container prune", "prune");
        assert_blocks(&pack, "podman volume rm my-volume", "volume");
    }

    #[test]
    fn podman_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "podman system prune -a", Severity::High);
        assert_blocks_with_severity(&pack, "podman volume prune", Severity::Critical);
        assert_blocks_with_severity(&pack, "podman pod prune", Severity::Medium);
        assert_blocks_with_severity(&pack, "podman image prune", Severity::Medium);
        assert_blocks_with_severity(&pack, "podman container prune", Severity::Medium);
        assert_blocks_with_severity(&pack, "podman volume rm data-vol", Severity::High);
        assert_blocks_with_severity(&pack, "podman rm -f container", Severity::High);
        assert_blocks_with_severity(&pack, "podman rmi -f image", Severity::High);
    }

    #[test]
    fn podman_all_safe_patterns_match() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "podman ps");
        assert_safe_pattern_matches(&pack, "podman ps -a");
        assert_safe_pattern_matches(&pack, "podman images");
        assert_safe_pattern_matches(&pack, "podman logs mycontainer");
        assert_safe_pattern_matches(&pack, "podman inspect mycontainer");
        assert_safe_pattern_matches(&pack, "podman build -t app .");
        assert_safe_pattern_matches(&pack, "podman pull nginx:latest");
        assert_safe_pattern_matches(&pack, "podman run --rm hello-world");
        assert_safe_pattern_matches(&pack, "podman exec -it container bash");
    }

    #[test]
    fn podman_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "ls -la");
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo podman");
    }
}

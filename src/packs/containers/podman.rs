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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // podman ps/images/logs are safe (read-only)
        safe_pattern!("podman-ps", r"podman\s+ps"),
        safe_pattern!("podman-images", r"podman\s+images"),
        safe_pattern!("podman-logs", r"podman\s+logs"),
        // podman inspect is safe
        safe_pattern!("podman-inspect", r"podman\s+inspect"),
        // podman build is generally safe
        safe_pattern!("podman-build", r"podman\s+build"),
        // podman pull is safe
        safe_pattern!("podman-pull", r"podman\s+pull"),
        // podman run is allowed
        safe_pattern!("podman-run", r"podman\s+run"),
        // podman exec is generally safe
        safe_pattern!("podman-exec", r"podman\s+exec"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // system prune - removes all unused data
        destructive_pattern!(
            "system-prune",
            r"podman\s+system\s+prune",
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
            r"podman\s+volume\s+prune",
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
            r"podman\s+pod\s+prune",
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
            r"podman\s+image\s+prune",
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
            r"podman\s+container\s+prune",
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
            r"podman\s+rm\s+.*-f|podman\s+rm\s+.*--force",
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
            r"podman\s+rmi\s+.*-f|podman\s+rmi\s+.*--force",
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
            r"podman\s+volume\s+rm",
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

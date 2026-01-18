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
            "podman system prune removes ALL unused containers, pods, images. Use 'podman system df' to preview."
        ),
        // volume prune - removes all unused volumes
        destructive_pattern!(
            "volume-prune",
            r"podman\s+volume\s+prune",
            "podman volume prune removes ALL unused volumes and their data permanently."
        ),
        // pod prune - removes stopped pods
        destructive_pattern!(
            "pod-prune",
            r"podman\s+pod\s+prune",
            "podman pod prune removes ALL stopped pods."
        ),
        // image prune - removes unused images (Medium: only affects unused images)
        destructive_pattern!(
            "image-prune",
            r"podman\s+image\s+prune",
            "podman image prune removes unused images. Use 'podman images' to review first.",
            Medium
        ),
        // container prune - removes stopped containers (Medium: only affects stopped)
        destructive_pattern!(
            "container-prune",
            r"podman\s+container\s+prune",
            "podman container prune removes ALL stopped containers.",
            Medium
        ),
        // rm -f (force remove containers)
        destructive_pattern!(
            "rm-force",
            r"podman\s+rm\s+.*-f|podman\s+rm\s+.*--force",
            "podman rm -f forcibly removes containers, potentially losing data."
        ),
        // rmi -f (force remove images)
        destructive_pattern!(
            "rmi-force",
            r"podman\s+rmi\s+.*-f|podman\s+rmi\s+.*--force",
            "podman rmi -f forcibly removes images even if in use."
        ),
        // volume rm
        destructive_pattern!(
            "volume-rm",
            r"podman\s+volume\s+rm",
            "podman volume rm permanently deletes volumes and their data."
        ),
    ]
}

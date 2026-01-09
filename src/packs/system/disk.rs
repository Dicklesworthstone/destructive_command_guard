//! Disk patterns - protections against destructive disk operations.
//!
//! This includes patterns for:
//! - dd to block devices
//! - fdisk/parted operations
//! - mkfs (formatting)
//! - mount/umount operations

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Disk pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "system.disk".to_string(),
        name: "Disk Operations",
        description: "Protects against destructive disk operations like dd to devices, \
                      mkfs, and partition table modifications",
        keywords: &["dd", "fdisk", "mkfs", "parted", "mount", "wipefs", "/dev/"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // dd to regular files is generally safe
        safe_pattern!("dd-file-out", r"dd\s+.*of=[^/\s]+\."),
        // lsblk is safe (read-only)
        safe_pattern!("lsblk", r"\blsblk\b"),
        // fdisk -l (list) is safe
        safe_pattern!("fdisk-list", r"fdisk\s+-l"),
        // parted print is safe
        safe_pattern!("parted-print", r"parted\s+.*print"),
        // blkid is safe (read-only)
        safe_pattern!("blkid", r"\bblkid\b"),
        // df is safe
        safe_pattern!("df", r"\bdf\b"),
        // mount (without arguments, just list)
        safe_pattern!("mount-list", r"\bmount\s*$"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // dd to block devices
        destructive_pattern!(
            "dd-device",
            r"dd\s+.*of=/dev/",
            "dd to a block device will OVERWRITE all data on that device. Extremely dangerous!"
        ),
        // dd with if=/dev/zero or if=/dev/urandom to devices
        destructive_pattern!(
            "dd-wipe",
            r"dd\s+.*if=/dev/(?:zero|urandom|random).*of=/dev/",
            "dd from /dev/zero or /dev/urandom to a device will WIPE all data!"
        ),
        // fdisk (partition editing)
        destructive_pattern!(
            "fdisk-edit",
            r"fdisk\s+/dev/(?!.*-l)",
            "fdisk can modify partition tables and cause data loss."
        ),
        // parted (except print)
        destructive_pattern!(
            "parted-modify",
            r"parted\s+/dev/\S+\s+(?!print)",
            "parted can modify partition tables and cause data loss."
        ),
        // mkfs (format filesystem)
        destructive_pattern!(
            "mkfs",
            r"mkfs(?:\.[a-z0-9]+)?\s+",
            "mkfs formats a partition/device and ERASES all existing data."
        ),
        // wipefs
        destructive_pattern!(
            "wipefs",
            r"wipefs\s+",
            "wipefs removes filesystem signatures. Use with extreme caution."
        ),
        // mount with potentially dangerous options
        destructive_pattern!(
            "mount-bind-root",
            r"mount\s+.*--bind\s+.*\s+/(?:$|[^a-z])",
            "mount --bind to root directory can have system-wide effects."
        ),
        // umount -f (force)
        destructive_pattern!(
            "umount-force",
            r"umount\s+.*-[a-z]*f",
            "umount -f force unmounts which may cause data loss if device is in use."
        ),
        // losetup can be dangerous
        destructive_pattern!(
            "losetup-device",
            r"losetup\s+/dev/loop",
            "losetup modifies loop device associations. Verify before proceeding."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipefs_is_reachable_via_keywords() {
        let pack = create_pack();
        assert!(
            pack.might_match("wipefs --all somefile.img"),
            "wipefs should be included in pack keywords to prevent false negatives"
        );
        let matched = pack
            .check("wipefs --all somefile.img")
            .expect("wipefs should be blocked by disk pack");
        assert_eq!(matched.name, Some("wipefs"));
    }

    #[test]
    fn keyword_absent_skips_pack() {
        let pack = create_pack();
        assert!(!pack.might_match("echo hello"));
        assert!(pack.check("echo hello").is_none());
    }
}

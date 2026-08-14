//! Disk patterns - protections against destructive disk operations.
//!
//! This includes patterns for:
//! - dd to block devices
//! - fdisk/parted operations
//! - mkfs (formatting)
//! - mount/umount operations
//! - mdadm RAID management
//! - btrfs filesystem operations
//! - dmsetup device-mapper operations
//! - nbd-client network block device
//! - LVM destructive commands (pvremove, vgremove, lvremove, etc.)
//! - macOS diskutil erase/partition/APFS-delete operations

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Disk pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "system.disk".to_string(),
        name: "Disk Operations",
        description: "Protects against destructive disk operations like dd to devices, \
                      mkfs, partition table modifications, RAID management, \
                      btrfs/LVM/device-mapper operations, network block devices, \
                      and macOS diskutil erase/partition/APFS deletion",
        keywords: &[
            "dd",
            "diskutil",
            "fdisk",
            "mkfs",
            "mkswap",
            "parted",
            "mount",
            "wipefs",
            "/dev/",
            "mdadm",
            "btrfs",
            "dmsetup",
            "nbd-client",
            "pvremove",
            "vgremove",
            "lvremove",
            "vgreduce",
            "lvreduce",
            "lvresize",
            "pvmove",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // dd to regular files is generally safe
        safe_pattern!("dd-file-out", r#"dd\s+.*of=['"]?[^/\s'"]+\."#),
        // dd to /dev/null|zero|full is safe (discard output). Accept optional
        // quotes so `dd of="/dev/null"` still short-circuits as safe.
        safe_pattern!(
            "dd-discard",
            r#"dd\s+.*of=['"]?/dev/(?:null|zero|full)['"]?(?:\s|$)"#
        ),
        // lsblk is safe (read-only)
        safe_pattern!("lsblk", r"\blsblk\b"),
        // fdisk -l (list) is safe
        safe_pattern!("fdisk-list", r"fdisk\s+-l"),
        // parted print is safe. Keep this tight because safe patterns run
        // before destructive patterns, and GNU Parted accepts multiple
        // commands after the device.
        safe_pattern!(
            "parted-print",
            r#"parted\b(?:\s+--?\S+)*\s+(?:['"]?/dev/\S+['"]?\s+)?print(?:\s+(?:devices|free|list|all|\d+))?\s*$"#
        ),
        // blkid is safe (read-only)
        safe_pattern!("blkid", r"\bblkid\b"),
        // df is safe
        safe_pattern!("df", r"\bdf\b"),
        // mount (without arguments, just list)
        safe_pattern!("mount-list", r"\bmount\s*$"),
        // mkswap --check (read-only inspection of swap area)
        safe_pattern!("mkswap-check", r"mkswap\s+(?:.*\s+)?--check\b"),
        // --- mdadm safe patterns ---
        // mdadm --detail (read-only inspection)
        safe_pattern!("mdadm-detail", r"mdadm\s+--detail\b"),
        // mdadm --examine (read-only superblock inspection)
        safe_pattern!("mdadm-examine", r"mdadm\s+--examine\b"),
        // mdadm --query (read-only query)
        safe_pattern!("mdadm-query", r"mdadm\s+--query\b"),
        // mdadm -Q (short form of --query)
        safe_pattern!("mdadm-query-short", r"mdadm\s+-Q\b"),
        // mdadm --scan (scan for arrays, read-only)
        safe_pattern!("mdadm-scan", r"mdadm\s+--scan\b"),
        // --- btrfs safe patterns ---
        // btrfs subvolume list (read-only)
        safe_pattern!(
            "btrfs-subvolume-list",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+subvolume\s+list(?=\s|$)"
        ),
        // btrfs subvolume show (read-only)
        safe_pattern!(
            "btrfs-subvolume-show",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+subvolume\s+show(?=\s|$)"
        ),
        // btrfs filesystem show (read-only)
        safe_pattern!(
            "btrfs-filesystem-show",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+show(?=\s|$)"
        ),
        // btrfs filesystem df (read-only)
        safe_pattern!(
            "btrfs-filesystem-df",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+df(?=\s|$)"
        ),
        // btrfs filesystem usage (read-only)
        safe_pattern!(
            "btrfs-filesystem-usage",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+usage(?=\s|$)"
        ),
        // btrfs device stats (read-only)
        safe_pattern!(
            "btrfs-device-stats",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+device\s+stats(?=\s|$)"
        ),
        // btrfs property get/list (read-only)
        safe_pattern!(
            "btrfs-property-get",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+property\s+(?:get|list)(?=\s|$)"
        ),
        // btrfs scrub status (read-only)
        safe_pattern!(
            "btrfs-scrub-status",
            r"btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+scrub\s+status(?=\s|$)"
        ),
        // --- dmsetup safe patterns ---
        // dmsetup ls (list devices)
        safe_pattern!(
            "dmsetup-ls",
            r"dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ls(?=\s|$)"
        ),
        // dmsetup status (show status)
        safe_pattern!(
            "dmsetup-status",
            r"dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s|$)"
        ),
        // dmsetup info (show info)
        safe_pattern!(
            "dmsetup-info",
            r"dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+info(?=\s|$)"
        ),
        // dmsetup table (show mapping table)
        safe_pattern!(
            "dmsetup-table",
            r"dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+table(?=\s|$)"
        ),
        // dmsetup deps (show dependencies)
        safe_pattern!(
            "dmsetup-deps",
            r"dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deps(?=\s|$)"
        ),
        // --- nbd-client safe patterns ---
        // nbd-client -l (list exports)
        safe_pattern!("nbd-client-list", r"nbd-client\s+-l\b"),
        // nbd-client -check (check connection)
        safe_pattern!("nbd-client-check", r"nbd-client\s+.*-check\b"),
        // --- macOS diskutil safe patterns (read-only) ---
        // Verbs are matched case-insensitively because diskutil itself accepts
        // any casing. End-bounded with [^;&|]* so a read-only verb cannot mask
        // a chained destructive command later on the same line (conservative:
        // failing to match here just falls through to the destructive check).
        safe_pattern!(
            "diskutil-readonly",
            r"(?i)diskutil\s+(?:list|info|information|activity|listFilesystems|apfs\s+list(?:Snapshots|Users)?)\b[^;&|]*$"
        ),
        // --- LVM safe patterns (read-only) ---
        // lvs, vgs, pvs (list commands)
        safe_pattern!("lvm-list", r"\b(?:lvs|vgs|pvs)\b"),
        // lvdisplay, vgdisplay, pvdisplay (display commands)
        safe_pattern!("lvm-display", r"\b(?:lvdisplay|vgdisplay|pvdisplay)\b"),
        // lvscan, vgscan, pvscan (scan commands)
        safe_pattern!("lvm-scan", r"\b(?:lvscan|vgscan|pvscan)\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // dd to block devices. Accept optional quotes around the device path
        // (`dd of="/dev/sda"` unquotes to `of=/dev/sda` before exec).
        destructive_pattern!(
            "dd-device",
            r#"dd\s+.*of=['"]?/dev/"#,
            "dd to a block device will OVERWRITE all data on that device. Extremely dangerous!"
        ),
        // dd with if=/dev/zero or if=/dev/urandom to devices
        destructive_pattern!(
            "dd-wipe",
            r#"dd\s+.*if=['"]?/dev/(?:zero|urandom|random).*of=['"]?/dev/"#,
            "dd from /dev/zero or /dev/urandom to a device will WIPE all data!"
        ),
        // fdisk (partition editing).
        // `['"]?` allows quoted variants like `fdisk "/dev/sda"` to match.
        destructive_pattern!(
            "fdisk-edit",
            r#"fdisk\s+['"]?/dev/(?!.*-l)"#,
            "fdisk can modify partition tables and cause data loss."
        ),
        // parted partition edits. GNU Parted accepts global options before
        // the device and one or more commands after it, so an initial read-only
        // command like `print` must not hide a later mutating command.
        destructive_pattern!(
            "parted-modify",
            r#"parted\b[^\n;&|]*?['"]?/dev/\S+['"]?(?:\s+--)?\s+(?:(?!\s*(?:align-check|help|h|print|p|quit|q|select|unit|u)\b)|[^\n;&|]*\b(?:print|p)\b\s+(?:(?:devices|free|list|all|\d+)\s+\S+|(?!devices\b|free\b|list\b|all\b|\d+\b)\S+)|[^\n;&|]*\b(?:disk_set|disk_toggle|mklabel|mktable|mkpart|name|rescue|resizepart|rm|set|toggle|type)\b)"#,
            "parted can modify partition tables and cause data loss."
        ),
        // mkfs (format filesystem)
        destructive_pattern!(
            "mkfs",
            r"mkfs(?:\.[a-z0-9]+)?\s+",
            "mkfs formats a partition/device and ERASES all existing data."
        ),
        // mkswap (format as swap area). Same blast radius as mkfs: overwrites
        // any existing data on the target device. Shipped as its own rule
        // because mkswap is a separate binary, not an mkfs.* variant.
        destructive_pattern!(
            "mkswap",
            r"mkswap\s+",
            "mkswap formats a partition as a swap area, ERASING any existing data."
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
            r#"mount\s+.*--bind\s+.*\s+['"]?/(?:$|[^a-z])"#,
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
            r#"losetup\s+['"]?/dev/loop"#,
            "losetup modifies loop device associations. Verify before proceeding."
        ),
        // --- mdadm destructive patterns ---
        // mdadm --stop (stops a running RAID array)
        destructive_pattern!(
            "mdadm-stop",
            r"mdadm\s+(?:.*\s+)?(?:--stop|-S)\b",
            "mdadm --stop shuts down a RAID array. Data may become inaccessible."
        ),
        // mdadm --remove (removes a device from an array)
        destructive_pattern!(
            "mdadm-remove",
            r"mdadm\s+(?:.*\s+)?--remove\b",
            "mdadm --remove removes a drive from a RAID array. May cause data loss if redundancy is lost."
        ),
        // mdadm --fail (marks a device as failed)
        destructive_pattern!(
            "mdadm-fail",
            r"mdadm\s+(?:.*\s+)?(?:--fail|-f)\b",
            "mdadm --fail marks a device as failed. Use only for intentional drive replacement."
        ),
        // mdadm --zero-superblock (wipes RAID superblock)
        destructive_pattern!(
            "mdadm-zero-superblock",
            r"mdadm\s+(?:.*\s+)?--zero-superblock\b",
            "mdadm --zero-superblock PERMANENTLY erases RAID metadata. Array cannot be reassembled."
        ),
        // mdadm --create (creates a new array, can overwrite existing data)
        destructive_pattern!(
            "mdadm-create",
            r"mdadm\s+(?:.*\s+)?(?:--create|-C)\b",
            "mdadm --create initializes a new RAID array, ERASING existing data on member devices."
        ),
        // mdadm --grow with dangerous options
        destructive_pattern!(
            "mdadm-grow",
            r"mdadm\s+(?:.*\s+)?--grow\b",
            "mdadm --grow reshapes a RAID array. Interruption can cause data loss. Backup first."
        ),
        // --- btrfs destructive patterns ---
        // btrfs subvolume delete
        destructive_pattern!(
            "btrfs-subvolume-delete",
            r"btrfs\b.*?\s+subvolume\s+delete\b",
            "btrfs subvolume delete PERMANENTLY removes a subvolume and all its data."
        ),
        // btrfs device remove/delete
        destructive_pattern!(
            "btrfs-device-remove",
            r"btrfs\b.*?\s+device\s+(?:remove|delete)\b",
            "btrfs device remove redistributes data off a device. Interruption causes data loss."
        ),
        // btrfs device add (can be dangerous with wrong device)
        destructive_pattern!(
            "btrfs-device-add",
            r"btrfs\b.*?\s+device\s+add\b",
            "btrfs device add incorporates a device into the filesystem. Verify the device is correct."
        ),
        // btrfs balance start (can be very disruptive)
        destructive_pattern!(
            "btrfs-balance",
            r"btrfs\b.*?\s+balance\s+start\b",
            "btrfs balance redistributes data across devices. Can be slow and disruptive."
        ),
        // btrfs check --repair (dangerous, can corrupt filesystem)
        destructive_pattern!(
            "btrfs-check-repair",
            r"btrfs\b.*?\s+check\s+(?:.*\s+)?--repair\b",
            "btrfs check --repair is DANGEROUS and can cause data loss. Backup first!"
        ),
        // btrfs rescue (emergency operations)
        destructive_pattern!(
            "btrfs-rescue",
            r"btrfs\b.*?\s+rescue\b",
            "btrfs rescue operations modify filesystem metadata. Use only as last resort."
        ),
        // btrfs filesystem resize (can shrink)
        destructive_pattern!(
            "btrfs-filesystem-resize",
            r"btrfs\b.*?\s+filesystem\s+resize\b",
            "btrfs filesystem resize can shrink a filesystem. Data loss if size is too small."
        ),
        // --- dmsetup destructive patterns ---
        // dmsetup remove (removes a device-mapper device)
        destructive_pattern!(
            "dmsetup-remove",
            r"dmsetup\b.*?\s+remove\b",
            "dmsetup remove detaches a device-mapper device. May cause data loss if in use."
        ),
        // dmsetup remove_all (removes ALL device-mapper devices)
        destructive_pattern!(
            "dmsetup-remove-all",
            r"dmsetup\b.*?\s+remove_all\b",
            "dmsetup remove_all removes ALL device-mapper devices. Extremely dangerous!"
        ),
        // dmsetup wipe_table (replaces table with error target)
        destructive_pattern!(
            "dmsetup-wipe-table",
            r"dmsetup\b.*?\s+wipe_table\b",
            "dmsetup wipe_table replaces the device table, causing all I/O to fail."
        ),
        // dmsetup clear (clears the table)
        destructive_pattern!(
            "dmsetup-clear",
            r"dmsetup\b.*?\s+clear\b",
            "dmsetup clear removes the mapping table from a device."
        ),
        // dmsetup load (loads a new table)
        destructive_pattern!(
            "dmsetup-load",
            r"dmsetup\b.*?\s+load\b",
            "dmsetup load changes device mapping. Verify the new table is correct."
        ),
        // dmsetup create (creates a new device)
        destructive_pattern!(
            "dmsetup-create",
            r"dmsetup\b.*?\s+create\b",
            "dmsetup create sets up a new device-mapper device. Verify parameters carefully."
        ),
        // --- nbd-client destructive patterns ---
        // nbd-client -d (disconnect)
        destructive_pattern!(
            "nbd-client-disconnect",
            r"nbd-client\s+(?:.*\s+)?-d\b",
            "nbd-client -d disconnects a network block device. Data loss if not properly unmounted."
        ),
        // nbd-client connect (can overwrite existing data)
        destructive_pattern!(
            "nbd-client-connect",
            r#"nbd-client\s+\S+\s+\d+\s+['"]?/dev/nbd"#,
            "nbd-client connecting a device can expose or overwrite data. Verify server and device."
        ),
        // --- LVM destructive patterns ---
        // pvremove (removes physical volume)
        destructive_pattern!(
            "pvremove",
            r"\bpvremove\b",
            "pvremove ERASES LVM metadata from a physical volume. Data becomes inaccessible."
        ),
        // vgremove (removes volume group)
        destructive_pattern!(
            "vgremove",
            r"\bvgremove\b",
            "vgremove DELETES a volume group and all logical volumes within it."
        ),
        // lvremove (removes logical volume)
        destructive_pattern!(
            "lvremove",
            r"\blvremove\b",
            "lvremove PERMANENTLY deletes a logical volume and ALL its data."
        ),
        // vgreduce (removes PV from VG)
        destructive_pattern!(
            "vgreduce",
            r"\bvgreduce\b",
            "vgreduce removes a physical volume from a volume group. Data may be lost."
        ),
        // lvreduce (shrinks logical volume)
        destructive_pattern!(
            "lvreduce",
            r"\blvreduce\b",
            "lvreduce SHRINKS a logical volume. Data loss if filesystem isn't resized first!"
        ),
        // lvresize with shrink (can lose data)
        destructive_pattern!(
            "lvresize-shrink",
            r"lvresize\s+(?:.*\s+)?(?:-L\s*-|-l\s*-|--size\s+\S*-)",
            "lvresize with negative size SHRINKS the volume. Resize filesystem first or lose data!"
        ),
        // pvmove (moves data between PVs, interruptible = bad)
        destructive_pattern!(
            "pvmove",
            r"\bpvmove\b",
            "pvmove migrates data between physical volumes. Do NOT interrupt or data may be lost."
        ),
        // lvcreate with snapshot removal
        destructive_pattern!(
            "lvconvert-merge",
            r"lvconvert\s+(?:.*\s+)?--merge\b",
            "lvconvert --merge reverts LV to snapshot state, discarding changes since snapshot."
        ),
        // --- macOS diskutil destructive patterns (issue #305) ---
        // diskutil verbs are case-insensitive, so all three rules use (?i).
        // Erase family: destroys all data on the target disk or volume.
        destructive_pattern!(
            "diskutil-erase",
            r"(?i)diskutil\s+(?:eraseDisk|eraseVolume|reformat|zeroDisk|randomDisk|secureErase)\b",
            "diskutil erase operations DESTROY all data on the target disk or volume.",
            Critical,
            "diskutil eraseDisk/eraseVolume/reformat/zeroDisk/randomDisk/secureErase \
             overwrite the target's contents. On APFS this removes every volume in \
             the container. There is no recovery without backups.\n\n\
             Inspect the target first:\n  \
             diskutil list\n  \
             diskutil info <disk>",
            executables = ["diskutil"]
        ),
        // Partition-table rewrites: partitionDisk erases the whole disk;
        // splitPartition/mergePartitions destroy the contents of the
        // partitions they reshape (merge keeps only the first).
        destructive_pattern!(
            "diskutil-partition",
            r"(?i)diskutil\s+(?:partitionDisk|splitPartition|mergePartitions|resetFusion)\b",
            "diskutil partitioning operations rewrite the partition map and erase data.",
            Critical,
            "diskutil partitionDisk erases the entire disk before writing the new \
             partition map; splitPartition and mergePartitions destroy the contents \
             of the partitions they reshape (merge preserves only the first when \
             asked); resetFusion wipes both constituent devices.\n\n\
             Preview the current layout first:\n  \
             diskutil list <disk>",
            executables = ["diskutil"]
        ),
        // APFS container/volume/snapshot deletion.
        destructive_pattern!(
            "diskutil-apfs-delete",
            r"(?i)diskutil\s+(?:apfs|ap)\s+(?:deleteContainer|deleteVolume|eraseVolume|deleteSnapshot)\b",
            "diskutil apfs delete/erase operations permanently remove APFS containers, volumes, or snapshots.",
            Critical,
            "Deleting an APFS container destroys every volume inside it; deleting or \
             erasing a volume destroys that volume's data; deleting a snapshot \
             removes a restore point. None of these are recoverable without \
             backups.\n\n\
             List APFS structure first:\n  \
             diskutil apfs list",
            executables = ["diskutil"]
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

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

    /// Issue #305: macOS diskutil erase, partition, and APFS deletion
    /// operations must be blocked while read-only inspection stays allowed.
    #[test]
    fn diskutil_destructive_operations_are_blocked_issue_305() {
        let pack = create_pack();
        assert!(
            pack.might_match("diskutil eraseDisk APFS PROBE /dev/disk999"),
            "diskutil must be reachable via pack keywords"
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil eraseDisk APFS PROBE /dev/disk999",
            "diskutil-erase",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil eraseVolume free none disk3s2",
            "diskutil-erase",
        );
        assert_blocks_with_pattern(&pack, "diskutil reformat disk3s2", "diskutil-erase");
        assert_blocks_with_pattern(&pack, "diskutil zeroDisk /dev/disk999", "diskutil-erase");
        assert_blocks_with_pattern(
            &pack,
            "diskutil secureErase 0 /dev/disk999",
            "diskutil-erase",
        );
        // Verb casing is not load-bearing: diskutil accepts any casing.
        assert_blocks_with_pattern(
            &pack,
            "diskutil erasedisk APFS X /dev/disk999",
            "diskutil-erase",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil partitionDisk /dev/disk999 GPT APFS PROBE 100%",
            "diskutil-partition",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil splitPartition disk3s2 2 JHFS+ A 50% JHFS+ B 50%",
            "diskutil-partition",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil mergePartitions JHFS+ merged disk3s2 disk3s4",
            "diskutil-partition",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil apfs deleteContainer disk999",
            "diskutil-apfs-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil apfs deleteVolume disk3s7",
            "diskutil-apfs-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil apfs eraseVolume disk3s7",
            "diskutil-apfs-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "diskutil apfs deleteSnapshot disk3s1 -uuid 0FCE82D1",
            "diskutil-apfs-delete",
        );
    }

    /// Issue #305: read-only diskutil commands stay allowed.
    #[test]
    fn diskutil_readonly_operations_stay_allowed_issue_305() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "diskutil list");
        assert_safe_pattern_matches(&pack, "diskutil list /dev/disk0");
        assert_safe_pattern_matches(&pack, "diskutil info /dev/disk0");
        assert_safe_pattern_matches(&pack, "diskutil activity");
        assert_safe_pattern_matches(&pack, "diskutil apfs list");
        assert_safe_pattern_matches(&pack, "diskutil apfs listSnapshots disk3s1");
        assert_allows(&pack, "diskutil list");
        assert_allows(&pack, "diskutil info disk3");
        // A read-only verb must not mask a chained destructive verb.
        let chained = pack
            .check("diskutil list && diskutil eraseDisk APFS X /dev/disk999")
            .expect("chained eraseDisk must still block");
        assert_eq!(chained.name, Some("diskutil-erase"));
    }

    #[test]
    fn dd_quote_bypass_is_closed() {
        // `dd of="/dev/sda"` unquotes to `dd of=/dev/sda` at exec time.
        // The destructive pattern must match both spellings. The earlier-listed
        // `dd-device` rule catches every `dd of=/dev/...` variant (including
        // the more-specific wipe cases), which is the correct, fail-safe
        // behavior.
        let pack = create_pack();
        let matched = pack
            .check("dd if=/dev/zero of=\"/dev/sda\" bs=1M")
            .expect("dd of=\"...\" must still block");
        assert_eq!(matched.name, Some("dd-device"));

        let matched = pack
            .check("dd of='/dev/sdb' if=something.img")
            .expect("dd of='...' must still block");
        assert_eq!(matched.name, Some("dd-device"));

        // /dev/null stays safe under quotes.
        assert!(
            pack.matches_safe("dd if=myfile of=\"/dev/null\""),
            "safe /dev/null discard must accept quoted path"
        );
    }

    #[test]
    fn btrfs_dmsetup_global_flags_do_not_bypass() {
        let pack = create_pack();
        // btrfs accepts --format, --verbose, --quiet before the subcommand.
        let matched = pack
            .check("btrfs --format json subvolume delete /mnt/foo")
            .expect("btrfs --format subvolume delete should still block");
        assert_eq!(matched.name, Some("btrfs-subvolume-delete"));

        let matched = pack
            .check("btrfs --verbose check --repair /dev/sda1")
            .expect("btrfs --verbose check --repair should still block");
        assert_eq!(matched.name, Some("btrfs-check-repair"));

        // dmsetup accepts -v, --noudevsync, --verifyudev before the subcommand.
        let matched = pack
            .check("dmsetup -v remove_all")
            .expect("dmsetup -v remove_all should still block");
        assert_eq!(matched.name, Some("dmsetup-remove-all"));

        let matched = pack
            .check("dmsetup --noudevsync remove my-dev")
            .expect("dmsetup with noudevsync should still block");
        assert_eq!(matched.name, Some("dmsetup-remove"));
    }

    #[test]
    fn parted_print_only_forms_remain_allowed() {
        let pack = create_pack();
        let safe_prints = [
            "parted /dev/sda print",
            "parted /dev/sda print free",
            "parted /dev/sda print all",
            "parted -s /dev/sda print 1",
        ];

        for cmd in safe_prints {
            assert!(
                pack.matches_safe(cmd),
                "read-only parted print form should match safe pattern: {cmd}"
            );
            assert!(
                pack.check(cmd).is_none(),
                "read-only parted print form should be allowed: {cmd}"
            );
        }

        assert_no_match(&pack, "parted /dev/sda unit s print free");
        assert_no_match(&pack, "parted -l");
    }

    #[test]
    fn parted_print_prefix_and_global_flags_do_not_bypass_modifications() {
        let pack = create_pack();
        let destructive = [
            "parted /dev/sda print rm 1",
            "parted /dev/sda p rm 1",
            "parted /dev/sda print mkla gpt",
            "parted /dev/sda print free rm 1",
            "parted /dev/sda print mklabel gpt",
            "parted /dev/sda print mkpart primary ext4 1MiB 1GiB",
            "parted /dev/sda unit s rm 1",
            "parted /dev/sda unit s p mkla gpt",
            "parted -s /dev/sda mklabel gpt",
            "parted --script /dev/sda rm 1",
            "parted -s /dev/sdX -- mklabel msdos mkpart primary fat32 64s 4MiB",
        ];

        for cmd in destructive {
            let matched = pack
                .check(cmd)
                .unwrap_or_else(|| panic!("parted mutation must block: {cmd}"));
            assert_eq!(matched.name, Some("parted-modify"), "wrong rule for {cmd}");
        }
    }

    #[test]
    fn disk_blocks_with_correct_severity() {
        let pack = create_pack();
        assert_blocks_with_severity(&pack, "dd if=/dev/zero of=/dev/sda bs=1M", Severity::High);
        assert_blocks_with_severity(&pack, "fdisk /dev/sda", Severity::High);
        assert_blocks_with_severity(&pack, "mkfs.ext4 /dev/sdb1", Severity::High);
        assert_blocks_with_severity(&pack, "wipefs --all /dev/sdb", Severity::High);
        assert_blocks_with_severity(&pack, "mdadm --stop /dev/md0", Severity::High);
        assert_blocks_with_severity(&pack, "btrfs subvolume delete /mnt/foo", Severity::High);
        assert_blocks_with_severity(&pack, "dmsetup remove my-dev", Severity::High);
        assert_blocks_with_severity(&pack, "pvremove /dev/sda1", Severity::High);
        assert_blocks_with_severity(&pack, "vgremove my-vg", Severity::High);
        assert_blocks_with_severity(&pack, "lvremove my-vg/my-lv", Severity::High);
    }

    #[test]
    fn disk_unrelated_commands_no_match() {
        let pack = create_pack();
        assert_no_match(&pack, "git status");
        assert_no_match(&pack, "echo hello");
        assert_no_match(&pack, "cargo build");
    }

    #[test]
    fn mkswap_blocks_destructive_variants() {
        let pack = create_pack();
        let cases = [
            "mkswap /dev/sdb",
            "mkswap /dev/sda1",
            "sudo mkswap /dev/sdb",
            "mkswap -L swap1 /dev/sdb1",
            "mkswap -U random /dev/nvme0n1p2",
        ];
        for cmd in cases {
            let matched = pack
                .check(cmd)
                .unwrap_or_else(|| panic!("mkswap command must block: {cmd}"));
            assert_eq!(matched.name, Some("mkswap"), "wrong rule for {cmd}");
            assert_eq!(matched.severity, Severity::High);
        }
    }

    #[test]
    fn mkswap_check_and_unrelated_text_allowed() {
        let pack = create_pack();
        // --check is read-only inspection.
        assert!(
            pack.matches_safe("mkswap --check /dev/sdb"),
            "mkswap --check must be safe"
        );
        assert!(
            pack.matches_safe("mkswap -L swap1 --check /dev/sdb1"),
            "mkswap with other flags + --check must be safe"
        );
        // Unrelated text mentioning mkswap (e.g. docs / paths). The pack regex
        // requires `mkswap\s+` so a hyphenated/embedded mention does not match.
        assert_no_match(&pack, "cat mkswap-readme.md");
        assert_no_match(&pack, "ls /usr/share/doc/mkswap");
        // Note: `echo mkswap is dangerous` matches at the raw-pack level
        // because the regex sees `mkswap ` (the space is the second token
        // separator). The evaluator's echo/printf args-data sanitize layer
        // masks that text before pack evaluation, so the full pipeline still
        // allows the command — exercised in
        // scripts/e2e_destructive_equivalents.sh::scenario_system_disk_default.
    }

    #[test]
    fn mkswap_keyword_reaches_pack() {
        let pack = create_pack();
        assert!(
            pack.might_match("mkswap /dev/sdb"),
            "mkswap must be in pack keywords or it will be filtered out before regex eval"
        );
    }
}

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
        // lsblk is safe (read-only), but only when lsblk is what runs.
        //
        // As a bare `\blsblk\b` this matched the word anywhere in the segment,
        // and a safe match short-circuits the whole pack — so any argument
        // carrying the word disarmed all 44 destructive rules:
        // `wipefs -a /dev/sdb -o /tmp/lsblk.bak` and `mkfs.ext4 -L lsblk
        // /dev/sdb1` were both allowed, while the same commands with any other
        // label were denied. Separator-crossing spellings were already handled
        // (`wipefs -a /dev/sdb && lsblk` denies, because segments are judged
        // separately); what was missing is that evidence has to be the command,
        // not its data. Same defect class as #429.
        //
        // Narrowing a safe pattern can only cost a false DENY where some
        // destructive pattern also matches, and none of them match a read-only
        // lsblk invocation — so an unusual spelling this misses (an env prefix
        // it does not anticipate, say) still falls through to allow.
        safe_pattern!(
            "lsblk",
            r"^\s*(?:\w+=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?lsblk\b"
        ),
        // There is deliberately no `fdisk -l` exemption.
        //
        // One used to sit here, unanchored, so `fdisk\s+-l` matched anywhere in
        // a segment and short-circuited every destructive rule in the pack:
        // `mkfs.ext4 /dev/sdb1 2>>"/tmp/fdisk -l.log"` was allowed (#448).
        // Anchoring it at the command position, the way `lsblk`/`blkid`/`df`
        // were, would have been the smaller change. It is dropped instead
        // because `fdisk-edit` already excludes the read-only form twice over:
        // it requires `/dev/` immediately after `fdisk`, so `fdisk -l /dev/sda`
        // never reaches it, and it carries `(?!.*-l)`, so `fdisk /dev/sda -l`
        // does not match either. The exemption only undid a deny the rule does
        // not make. A redundant exemption is a short-circuit waiting to be
        // re-widened, so it goes rather than gets narrowed — the same call
        // `ae0cf8d` made for the mdadm read-only exemptions.
        // parted print is safe. Keep this tight because safe patterns run
        // before destructive patterns, and GNU Parted accepts multiple
        // commands after the device.
        safe_pattern!(
            "parted-print",
            r#"parted\b(?:\s+--?\S+)*\s+(?:['"]?/dev/\S+['"]?\s+)?print(?:\s+(?:devices|free|list|all|\d+))?\s*$"#
        ),
        // blkid is safe (read-only) — anchored for the reason given on `lsblk`.
        // `mdadm --stop /dev/md0 --config /etc/blkid.conf` and
        // `tee /dev/sda < /tmp/blkid.img` were allowed on the bare spelling.
        safe_pattern!(
            "blkid",
            r"^\s*(?:\w+=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?blkid\b"
        ),
        // df is safe (read-only) — anchored for the same reason, and it was the
        // easiest of the three to trip by accident: two letters matched as a
        // word anywhere, so `mkfs.ext4 -L df /dev/sdb1` was allowed.
        // `btrfs filesystem df` keeps its own pattern below.
        safe_pattern!(
            "df",
            r"^\s*(?:\w+=\S*\s+)*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?df\b"
        ),
        // There is deliberately no bare-`mount` exemption.
        //
        // One used to sit here as `\bmount\s*$`, anchored only at the END, and
        // `/` is a word boundary — so any destructive command whose redirect
        // target's last path component was `mount` satisfied it and skipped the
        // whole pack: `dd if=/dev/zero of=/dev/sda 2>>/var/log/mount` and
        // `wipefs -a /dev/sdb 2>/tmp/mount` were allowed (#448).
        //
        // Neither mount rule here can match a bare `mount` anyway:
        // `mount-bind-root` requires `--bind` and a root target, and
        // `umount-force` requires the literal `umount` with `-f`. So this was
        // also a redundant exemption rather than a needed one.
        // There is deliberately no `mkswap --check` exemption.
        //
        // One used to sit here, commented "read-only inspection of swap area".
        // mkswap(8) says otherwise: "-c, --check: Check the device (if it is a
        // block device) for bad blocks *before creating the swap area*." The
        // check is a preliminary to the format, not an alternative to it, so
        // the exemption allowed a command that destroys the partition —
        // `mkswap --check /dev/sdb1` was allowed while `mkswap -c /dev/sdb1`,
        // which does exactly the same thing, was denied (#448). mkswap has no
        // read-only mode to carve out.
        // --- mdadm has no safe patterns, deliberately ---
        //
        // There were five: --detail, --examine, --query, -Q and --scan, each
        // written as `mdadm\s+--detail\b`. Requiring the read-only flag to
        // follow `mdadm` immediately made the exemption depend on argument
        // order rather than on what the command does, so
        // `mdadm --stop /dev/md0 --detail` was denied while
        // `mdadm --detail --stop /dev/md0` was allowed, and
        // `mdadm --scan --zero-superblock /dev/sdb` — which destroys the RAID
        // metadata identifying array members — was allowed too (#448).
        //
        // The obvious repair is a negative lookahead excluding the destructive
        // modes, and that works, but it is a list that has to be kept in step
        // with the destructive patterns below: add a seventh mdadm rule without
        // extending the list and the exemption silently covers it again. That
        // is the same shape of latent defect this issue exists to remove.
        //
        // Deleting them costs nothing instead. Every destructive mdadm rule
        // below requires an explicit mode — --stop/-S, --remove, --fail/-f,
        // --zero-superblock, --create/-C, --grow — and a read-only invocation
        // carries none of them, so `mdadm --detail /dev/md0` and friends are
        // allowed by matching no destructive pattern rather than by matching a
        // safe one. The exemptions only ever bought an early exit, and they are
        // asserted still allowed in
        // `mdadm_genuinely_read_only_invocations_stay_allowed_issue_448`.
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
        // any casing. End-bounded with [^;&|\r\n]* so a read-only verb cannot
        // mask a chained destructive command in a later segment — every shell
        // separator, newline included, ends the whitelisted span (conservative:
        // failing to match here just falls through to the destructive check).
        safe_pattern!(
            "diskutil-readonly",
            r"(?i)diskutil\s+(?:list|info|information|activity|listFilesystems|apfs\s+list(?:Snapshots|Users)?)\b[^;&|\r\n]*$"
        ),
        // There are deliberately no LVM read-only exemptions.
        //
        // Three used to sit here — `\b(?:lvs|vgs|pvs)\b`,
        // `\b(?:lvdisplay|vgdisplay|pvdisplay)\b` and
        // `\b(?:lvscan|vgscan|pvscan)\b` — all unanchored, so argument data
        // supplied the evidence and short-circuited the whole pack (#448).
        // `lvs`/`vgs`/`pvs` are three letters matched as a word anywhere, which
        // makes them as easy to trip as the `df` case that entry calls out:
        //
        //   mkfs.ext4 -L lvs /dev/sdb1                        was allowed
        //   dd if=/dev/zero of=/dev/sda 2>>/var/log/vgs.log   was allowed
        //   wipefs -a /dev/sdb 2>/tmp/pvs                     was allowed
        //
        // Dropped rather than anchored because none was load-bearing: every
        // destructive LVM rule here is word-anchored on a *remove* or *reduce*
        // tool (`\bpvremove\b`, `\bvgremove\b`, `\blvremove\b`, `\bvgreduce\b`,
        // `\blvreduce\b`), so nothing in this pack ever denied a query tool.
        // The pseudo-devices every writer tool legitimately names. `tee
        // /dev/null` is the single most common shape of all, and `/dev/shm`,
        // `/dev/fd/N` and `/dev/pts/N` are ordinary paths rather than block
        // devices. Writing to /dev/zero or /dev/full is discarded, which
        // `dd-discard` above already treats as safe for dd (#444).
        // The exemption has to name the WRITE TARGET, not merely some
        // pseudo-device in the command: `tee /dev/sda < /dev/zero` reads
        // /dev/zero and writes the disk, and an exemption that skipped over
        // the target to find the source would allow exactly the command #444
        // is about. So tee/sponge's operand must be the pseudo-device itself,
        // and cp/mv/install's must be the final argument they write.
        safe_pattern!(
            "device-write-pseudo-tee",
            r#"\b(?:tee|sponge)\b(?:\s+-{1,2}\S+)*\s+['"]?/dev/(?:null|zero|full|random|urandom|std(?:in|out|err)|tty|console|ptmx|fd/|pts/|shm/)\S*['"]?\s*(?:$|[|>])"#
        ),
        safe_pattern!(
            "device-write-pseudo-copy",
            r#"\b(?:cp|mv|install)\b[^|;&]*\s['"]?/dev/(?:null|zero|full|random|urandom|std(?:in|out|err)|tty|console|ptmx|fd/|pts/|shm/)\S*['"]?\s*$"#
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // A writer tool naming a device destroys it exactly as `dd` does, and
        // every neighbouring spelling already denied: `dd of=/dev/sda`,
        // `mkfs.ext4 /dev/sda1`, `wipefs --all /dev/sda` and every redirect
        // form (`cat /dev/zero > /dev/sda`) via core.filesystem. `tee` fell
        // between them — not a redirect, so the redirect rule saw no target,
        // and not a device tool this pack modelled (#444). `curl … | tee
        // /dev/sda` is the idiom an agent reaches for once `dd` is blocked,
        // which is the same substitution pressure that motivated the
        // `find … -delete` rules.
        //
        // The device set is left open the way `dd-device` leaves it open:
        // matching `/dev/` and exempting the pseudo-devices by name below.
        // Enumerating block devices instead would miss whatever this host
        // calls them — /dev/xvda, /dev/nbd0, /dev/ram0 — and a destructive
        // pattern that fails to match is a missed denial, while a safe
        // pattern that fails to match only withdraws an exemption.
        destructive_pattern!(
            "tee-device",
            r#"\b(?:tee|sponge)\b(?:\s+-{1,2}\S+)*\s+['"]?/dev/"#,
            "tee/sponge into a device will OVERWRITE that device, exactly as dd would. Extremely dangerous!"
        ),
        // cp/mv/install write their LAST argument, so the device has to be in
        // destination position: `cp /dev/null foo` reads a device and is
        // ordinary, `cp /dev/zero /dev/sda` writes one and is not.
        destructive_pattern!(
            "copy-to-device",
            r#"\b(?:cp|mv|install)\b[^|;&]*\s['"]?/dev/[^\s'"|;&]+['"]?\s*$"#,
            "Copying or moving onto a device OVERWRITES that device, exactly as dd would. Extremely dangerous!"
        ),
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
    fn writer_tools_naming_a_device_are_blocked_issue_444() {
        // `tee /dev/sda` destroys the device exactly as `dd of=/dev/sda` does,
        // and every neighbouring spelling already denied: the tool forms here,
        // the redirect forms in core.filesystem. `tee` fell between the two.
        let pack = create_pack();
        for command in [
            "tee /dev/sda < /dev/zero",
            "tee -a /dev/sda",
            "some-generator | tee /dev/sda > /dev/null",
            "curl -s https://example/image.img | tee /dev/sda > /dev/null",
            "tee /dev/nvme0n1",
            "sponge /dev/sda",
        ] {
            assert!(
                pack.might_match(command),
                "keyword gating must reach the pack for {command:?}: `/dev/` is the only \
                 keyword such a command carries"
            );
            assert_blocks_with_pattern(&pack, command, "tee-device");
        }
        for command in [
            "cp /dev/zero /dev/sda",
            "install -m 0 somefile /dev/sda",
            "mv somefile /dev/sda",
        ] {
            assert_blocks_with_pattern(&pack, command, "copy-to-device");
        }
    }

    #[test]
    fn writer_tools_naming_a_pseudo_device_stay_allowed_issue_444() {
        // `tee /dev/null` is the most common shape of all, and /dev/shm,
        // /dev/fd and /dev/pts are ordinary paths rather than block devices.
        let pack = create_pack();
        for command in [
            "tee /dev/null",
            "echo 1 | tee /dev/null",
            "cat x | tee /dev/null | wc -l",
            "tee /dev/stdout",
            "tee -a /dev/stderr",
            "cat x | tee /dev/tty",
            "tee /dev/fd/3",
            "cmd | tee /dev/shm/buffer",
            "cp file /dev/shm/x",
            "cp /dev/null placeholder.log",
            "tee out.txt",
            "tee -a /var/log/app.log",
            "tee file1 file2",
            "cp a.txt b.txt",
        ] {
            // Either a safe pattern exempts it, or no destructive pattern
            // matched it in the first place — `cp /dev/null placeholder.log`
            // names a device as its SOURCE, so `copy-to-device` (which
            // requires the device in destination position) never fires.
            assert!(
                pack.matches_safe(command) || pack.check(command).is_none(),
                "{command:?} must not be blocked by the device-writer rules"
            );
        }
    }

    #[test]
    fn device_write_exemption_names_the_target_not_a_source_issue_444() {
        // The exemption must not skip over the write target to find a
        // pseudo-device used as a SOURCE: `tee /dev/sda < /dev/zero` reads
        // /dev/zero and writes the disk, and an exemption keyed on "some
        // /dev/ pseudo-device appears" would allow exactly the reported
        // command. Same for `cp /dev/zero /dev/sda`.
        let pack = create_pack();
        assert!(
            !pack.matches_safe("tee /dev/sda < /dev/zero"),
            "a /dev/zero source must not exempt a write to /dev/sda"
        );
        assert!(
            !pack.matches_safe("cp /dev/zero /dev/sda"),
            "a /dev/zero source must not exempt a copy onto /dev/sda"
        );
        assert!(
            !pack.matches_safe("some-generator | tee /dev/sda > /dev/null"),
            "a /dev/null redirect must not exempt a write to /dev/sda"
        );
    }

    #[test]
    fn read_only_tool_names_in_argument_data_do_not_disarm_the_pack_issue_448() {
        // A safe match short-circuits every destructive pattern in the pack, so
        // a safe pattern matching a bare word anywhere in the segment hands any
        // argument the power to switch the pack off. Each pair below differs
        // only by a token that `lsblk`, `blkid` or `df` used to match as a bare
        // word; against the released 0.14.4 the second member of every pair was
        // allowed while the first was denied.
        let pack = create_pack();
        for (command, rule) in [
            (
                "dd if=/dev/zero of=/dev/sda 2>>/var/log/blkid.log",
                "dd-device",
            ),
            ("mkfs.ext4 -L lsblk /dev/sdb1", "mkfs"),
            ("mkfs.ext4 -L df /dev/sdb1", "mkfs"),
            ("wipefs -a /dev/sdb -o /tmp/lsblk.bak", "wipefs"),
            ("wipefs -a /dev/sdb -o /tmp/df.bak", "wipefs"),
            (
                "mdadm --stop /dev/md0 --config /etc/blkid.conf",
                "mdadm-stop",
            ),
            ("dmsetup remove mydev --table /tmp/lsblk", "dmsetup-remove"),
            ("lvremove -f vg/lv --config /tmp/blkid", "lvremove"),
            ("tee /dev/sda < /tmp/blkid.img", "tee-device"),
            ("diskutil eraseDisk APFS lsblk /dev/disk9", "diskutil-erase"),
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} must not match a safe pattern: the read-only tool \
                 name is argument data, not the command being run"
            );
            assert_blocks_with_pattern(&pack, command, rule);
        }
    }

    #[test]
    fn mdadm_read_only_flags_do_not_exempt_a_destructive_mode_issue_448() {
        // The exemption used to depend on argument order: a read-only flag
        // immediately after `mdadm` matched, whatever else the command asked
        // for. Measured against v0.14.4, every variant below was allowed while
        // the same modes in the other order were denied.
        let pack = create_pack();
        for (command, rule) in [
            ("mdadm --detail --stop /dev/md0", "mdadm-stop"),
            ("mdadm --examine --stop /dev/md0", "mdadm-stop"),
            ("mdadm -Q --stop /dev/md0", "mdadm-stop"),
            (
                "mdadm --scan --zero-superblock /dev/sdb",
                "mdadm-zero-superblock",
            ),
            ("mdadm --query --fail /dev/md0 /dev/sdb", "mdadm-fail"),
            ("mdadm --detail --remove /dev/md0 /dev/sdb", "mdadm-remove"),
            ("mdadm --scan --create /dev/md0 --level=0", "mdadm-create"),
            (
                "mdadm --detail --grow /dev/md0 --raid-devices=3",
                "mdadm-grow",
            ),
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} carries a destructive mdadm mode and must not be \
                 exempted by a read-only flag"
            );
            assert_blocks_with_pattern(&pack, command, rule);
        }
    }

    #[test]
    fn mdadm_genuinely_read_only_invocations_stay_allowed_issue_448() {
        let pack = create_pack();
        for command in [
            "mdadm --detail /dev/md0",
            "mdadm --detail --scan",
            "mdadm --examine /dev/sdb1",
            "mdadm --query /dev/md0",
            "mdadm -Q /dev/md0",
            "mdadm --scan",
            "sudo mdadm --detail --scan",
        ] {
            assert!(
                pack.matches_safe(command) || pack.check(command).is_none(),
                "{command:?} is read-only and must not be blocked"
            );
        }
    }

    /// The exemption bypass #448 reported survived in two more patterns.
    ///
    /// `cab2851` anchored `lsblk`/`blkid`/`df` at the command position, but
    /// `fdisk-list` (`fdisk\s+-l`, unanchored) and `mount-list` (`\bmount\s*$`,
    /// anchored only at the end) still matched argument data — and a safe match
    /// short-circuits every destructive rule in the pack. `/` is a word
    /// boundary, so a redirect target whose last component is `mount` satisfied
    /// `mount-list`.
    ///
    /// These are the shapes that would actually execute. An earlier pass of mine
    /// used `dd … of=/dev/sda mount`, which exempts but also fails on the stray
    /// operand, so it proved nothing.
    #[test]
    fn inert_data_naming_a_read_only_tool_does_not_disarm_the_pack_issue_448() {
        let pack = create_pack();
        for command in [
            // `mount-list`: the redirect target's last component is `mount`.
            "dd if=/dev/zero of=/dev/sda 2>>/var/log/mount",
            "wipefs -a /dev/sdb 2>/tmp/mount",
            // `fdisk-list`: the two tokens inside a quoted filename.
            r#"mkfs.ext4 /dev/sdb1 2>>"/tmp/fdisk -l.log""#,
            // `lvm-list`: three letters, as a filesystem label or a log path.
            "mkfs.ext4 -L lvs /dev/sdb1",
            "mkfs.ext4 -L vgs /dev/sdb1",
            "mkfs.ext4 -L pvs /dev/sdb1",
            "dd if=/dev/zero of=/dev/sda 2>>/var/log/vgs.log",
            "wipefs -a /dev/sdb 2>/tmp/pvs",
            // `lvm-scan` and `lvm-display`: the same shape, longer words.
            "mkfs.ext4 -L lvscan /dev/sdb1",
            "dd if=/dev/zero of=/dev/sda 2>>/var/log/pvscan",
            "mkfs.ext4 -L vgdisplay /dev/sdb1",
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} names a read-only tool only in inert data and must \
                 not be exempted"
            );
            assert!(
                pack.check(command).is_some(),
                "{command:?} is destructive and must still be blocked"
            );
        }
    }

    /// Dropping those two exemptions must not block the read-only commands they
    /// existed for. Neither is needed: `fdisk-edit` requires `/dev/` directly
    /// after `fdisk` and also carries `(?!.*-l)`, and no rule here matches a
    /// bare `mount` — `mount-bind-root` needs `--bind` with a root target and
    /// `umount-force` needs the literal `umount`.
    #[test]
    fn read_only_fdisk_and_mount_stay_allowed_without_their_exemptions_issue_448() {
        let pack = create_pack();
        for command in [
            "fdisk -l",
            "fdisk -l /dev/sda",
            "sudo fdisk -l",
            "fdisk /dev/sda -l",
            "mount",
            "mount /dev/sdb1 /mnt",
            // The LVM query tools: every destructive LVM rule here is anchored
            // on a remove/reduce tool, so none of these was ever denied.
            "lvs",
            "vgs -o vg_name",
            "pvs /dev/sda",
            "lvs -a -o +devices",
            "lvscan",
            "vgscan",
            "lvdisplay",
            "vgdisplay /dev/sda",
            "pvdisplay",
        ] {
            assert!(
                pack.check(command).is_none(),
                "{command:?} is read-only or ordinary and must not be blocked"
            );
        }
    }

    #[test]
    fn mkswap_check_is_not_read_only_issue_448() {
        // mkswap(8): "-c, --check: Check the device (if it is a block device)
        // for bad blocks before creating the swap area." The check precedes the
        // format rather than replacing it, so every spelling formats the
        // partition. The long form used to be exempt while the short form,
        // which does the same thing, was denied.
        let pack = create_pack();
        for command in [
            "mkswap --check /dev/sdb1",
            "mkswap /dev/sdb1 --check",
            "mkswap -c /dev/sdb1",
            "mkswap /dev/sdb1 -c",
            "sudo mkswap --check /dev/nvme0n1p3",
        ] {
            assert!(
                !pack.matches_safe(command),
                "{command:?} creates a swap area and must not match a safe pattern"
            );
            assert_blocks_with_pattern(&pack, command, "mkswap");
        }
    }

    #[test]
    fn read_only_disk_inspection_stays_allowed_issue_448() {
        // The other direction: anchoring must not cost the genuine read-only
        // invocations these patterns exist for, including the sudo, absolute
        // path and env-prefix spellings.
        let pack = create_pack();
        for command in [
            "lsblk",
            "lsblk -f",
            "lsblk --json /dev/sda",
            "sudo lsblk",
            "sudo -n lsblk -o NAME,SIZE",
            "/usr/bin/lsblk",
            "LC_ALL=C lsblk",
            "blkid",
            "blkid /dev/sda1",
            "sudo blkid -o value -s UUID /dev/sda1",
            "df",
            "df -h",
            "df -h /var",
            "sudo df -i",
            "btrfs filesystem df /mnt",
        ] {
            assert!(
                pack.matches_safe(command) || pack.check(command).is_none(),
                "{command:?} is read-only and must not be blocked"
            );
        }
    }

    #[test]
    fn bind_mount_over_root_is_blocked_issue_441() {
        // `mount --bind <src> /` shadows the running root filesystem for every
        // process that resolves a path afterwards. The rule has always matched
        // it; until #441 the registry row carried only `umount`, so the
        // quick-reject dropped the command — it names no other keyword in that
        // row — and the pack never ran. Measured against the release binary
        // before the fix: `mount --bind /mnt /` was allowed, while
        // `mount --bind /mnt/btrfs /` (identical but for an unrelated row
        // keyword in the path) was denied by this same rule.
        let pack = create_pack();
        for command in [
            "mount --bind /mnt /",
            "mount --bind /tmp /",
            "sudo mount --bind /mnt/overlay /",
        ] {
            assert!(
                pack.might_match(command),
                "keyword gating must reach the pack for {command:?}"
            );
            assert_blocks_with_pattern(&pack, command, "mount-bind-root");
        }
    }

    #[test]
    fn ordinary_mounts_stay_allowed_issue_441() {
        // Registering `mount` widens the gate, so the pack now sees every
        // command containing that substring — including `umount`, which is why
        // the row no longer needs a separate entry for it. Widening the gate
        // must not widen any rule: only a bind whose target is root denies.
        let pack = create_pack();
        for command in [
            "mount --bind /proc /mnt/proc",
            "mount --bind /dev /mnt/dev",
            "mount -t ext4 /dev/sdb1 /mnt",
            "mount -o remount,ro /",
            "mount",
            "mountpoint -q /mnt",
            "docker run --mount type=bind,src=/data,dst=/data alpine",
        ] {
            assert!(
                pack.matches_safe(command) || pack.check(command).is_none(),
                "{command:?} must not be blocked by the mount rules"
            );
        }
    }

    #[test]
    fn umount_force_still_reachable_after_mount_keyword_swap_issue_441() {
        // `umount` contains `mount`, and keyword matching is substring-based,
        // so replacing the row's `umount` entry with `mount` kept #323's rule
        // reachable. This asserts the rule, not just the keyword arithmetic.
        let pack = create_pack();
        for command in ["umount -f /mnt/data", "sudo umount -lf /mnt/nfs"] {
            assert!(
                pack.might_match(command),
                "keyword gating must still reach the pack for {command:?}"
            );
            assert_blocks_with_pattern(&pack, command, "umount-force");
        }
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
    fn unrelated_mkswap_text_is_not_a_match() {
        let pack = create_pack();
        // This test used to assert that `mkswap --check /dev/sdb` and
        // `mkswap -L swap1 --check /dev/sdb1` were safe, on the premise that
        // "--check is read-only inspection". mkswap(8) disagrees: "-c,
        // --check: Check the device (if it is a block device) for bad blocks
        // *before creating the swap area*" — the check is a preliminary to the
        // format. The second case gave it away, since `-L swap1` writes a label
        // into the header that mkswap is being asked to create. Both spellings
        // are now blocked, asserted in `mkswap_check_is_not_read_only_issue_448`.
        //
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

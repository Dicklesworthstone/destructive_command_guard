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

use crate::destructive_pattern;
use crate::packs::regex_engine::LazyCompiledRegex;
use crate::packs::{DestructivePattern, Pack, SafePattern};

// Exemptions must identify the executable, never a word in argument data (#448).
// This is an exemption-only grammar: unknown wrappers/quoting withdraw the
// exemption, not a destructive match. The evaluator also normalizes wrappers.
// Do not use `\S*/` here: it accepts redirect targets and assignments as paths.
// Do not consume arbitrary sudo options: `sudo -u lsblk dd ...` runs dd, not lsblk.
macro_rules! disk_safe_pattern {
    ($name:literal, $body:expr) => {
        SafePattern {
            name: $name,
            regex: LazyCompiledRegex::new(concat!(
                r"^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&|<>()\x22'\\$`*?\[\]{}~=]+/)?",
                $body
            )),
        }
    };
}

// Complete literal arguments only. In particular, no output operand may be
// hidden inside an input filename, and no second, unsafe of= may follow the
// discard target. Expansion/shell syntax is left to the evaluator, not trusted
// by a pack-wide regex exemption.
macro_rules! dd_literal_word {
    () => {
        r#"(?:[^\s;&|<>()"'\\$`*?\[\]{}~]+|'[^'\r\n]*'|"[^"\\$`\r\n]*")"#
    };
}

macro_rules! dd_non_output_operand {
    () => {
        concat!(
            r"(?:(?:if|ibs|obs|bs|cbs|skip|iseek|seek|oseek|count|conv|iflag|oflag|status)=",
            dd_literal_word!(),
            r"|[0-9]*[<>]&(?:[0-9]+|-)|[0-9]*<[ \t]*",
            dd_literal_word!(),
            r"|(?:[0-9]*(?:>>?|>\|)|&>>?)[ \t]*(?:",
            r#"/dev/(?:null|zero|full)|'/dev/(?:null|zero|full)'|"/dev/(?:null|zero|full)"|(?!['"]?/dev/)"#,
            dd_literal_word!(),
            r"))"
        )
    };
}

macro_rules! dd_discard_operand {
    () => {
        r#"(?:of=(?:/dev/(?:null|zero|full)|'/dev/(?:null|zero|full)'|"/dev/(?:null|zero|full)")|'of=/dev/(?:null|zero|full)'|"of=/dev/(?:null|zero|full)")"#
    };
}

// Boolean options must not eat the destructive subcommand as a fictitious
// value. Required values must be present, including with the --option=value form.
macro_rules! btrfs_readonly_pattern {
    ($name:literal, $verb:literal) => {
        disk_safe_pattern!(
            $name,
            concat!(
                r"btrfs[ \t]+(?:(?:--(?:verbose|quiet)|-[vq]+|--format(?:=|[ \t]+)(?:text|json)|--log(?:=|[ \t]+)(?:default|info|verbose|debug|quiet))[ \t]+)*",
                $verb,
                r"(?:[ \t]+[^;&|\r\n<>()`$]*)?[ \t]*$"
            )
        )
    };
}

macro_rules! dmsetup_readonly_pattern {
    ($name:literal, $verb:literal) => {
        disk_safe_pattern!(
            $name,
            concat!(
                r"dmsetup[ \t]+(?:(?:-v+|-c|--(?:verbose|noudevsync|verifyudev|readonly|columns|noheadings))[ \t]+)*",
                $verb,
                r"(?:[ \t]+[^;&|\r\n<>()`$]*)?[ \t]*$"
            )
        )
    };
}

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
            // Direct formatters (see the `mkfs` rule). `newfs_*` are spelled
            // out: `_` is a word character, so `newfs` never matches inside
            // `newfs_apfs` under the boundary-aware quick-reject.
            "mke2fs",
            "mkdosfs",
            "mkntfs",
            "mkexfatfs",
            "newfs",
            "newfs_apfs",
            "newfs_hfs",
            "newfs_msdos",
            "newfs_exfat",
            "mkswap",
            "parted",
            "mount",
            "wipefs",
            // The GPT editors need all three spellings here as well as in
            // `PACK_ENTRIES`; a keyword present in only one of the two lists is
            // inert (#441). Boundary-aware matching means `gdisk` does not cover
            // `sgdisk`, and `cgdisk` covers neither (#456).
            "sgdisk",
            "gdisk",
            "cgdisk",
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
            // Whole-device wipe / erase tools. Most already reach the pack via
            // the `/dev/` keyword, but naming them selects the pack even when
            // the target is a mapped name (`cryptsetup luksErase mydev`) or a
            // pool name (`zpool destroy tank`, which carries no `/dev/`).
            "blkdiscard",
            "cryptsetup",
            "hdparm",
            "nvme",
            "badblocks",
            "sg_format",
            "zpool",
            "zfs",
            // `nwipe --autonuke` carries no `/dev/`; `scrub`/`wipe` reach the
            // pack via their required `/dev/` target, so they need no keyword.
            "nwipe",
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
        // There is no dd-file-out exemption: it matched of= inside source
        // filenames and let an ordinary filename hide an actual device output.
        // Regular file outputs do not match dd-device in the first place.
        disk_safe_pattern!(
            "dd-discard",
            concat!(
                r"dd[ \t]+(?:",
                dd_non_output_operand!(),
                r"[ \t]+)*",
                dd_discard_operand!(),
                r"(?:[ \t]+(?:",
                dd_non_output_operand!(),
                r"|",
                dd_discard_operand!(),
                r"))*[ \t]*$"
            )
        ),
        disk_safe_pattern!("lsblk", r"lsblk(?:[ \t]+[^;&|\r\n<>()`$]*)?[ \t]*$"),
        disk_safe_pattern!("blkid", r"blkid(?:[ \t]+[^;&|\r\n<>()`$]*)?[ \t]*$"),
        disk_safe_pattern!("df", r"df(?:[ \t]+[^;&|\r\n<>()`$]*)?[ \t]*$"),
        // Parted accepts multiple commands; only a complete print-only form
        // can exempt it. The executable must also be in command position.
        disk_safe_pattern!(
            "parted-print",
            r#"parted[ \t]+(?:(?:-s|--script|-m|--machine|-j|--json)[ \t]+)*(?:['"]?/dev/[^\s'";&|<>()`$]+['"]?[ \t]+)?print(?:[ \t]+(?:devices|free|list|all|\d+))?[ \t]*$"#
        ),
        btrfs_readonly_pattern!("btrfs-subvolume-list", r"subvolume[ \t]+list"),
        btrfs_readonly_pattern!("btrfs-subvolume-show", r"subvolume[ \t]+show"),
        btrfs_readonly_pattern!("btrfs-filesystem-show", r"filesystem[ \t]+show"),
        btrfs_readonly_pattern!("btrfs-filesystem-df", r"filesystem[ \t]+df"),
        btrfs_readonly_pattern!("btrfs-filesystem-usage", r"filesystem[ \t]+usage"),
        btrfs_readonly_pattern!("btrfs-device-stats", r"device[ \t]+stats"),
        btrfs_readonly_pattern!("btrfs-property-get", r"property[ \t]+(?:get|list)"),
        btrfs_readonly_pattern!("btrfs-scrub-status", r"scrub[ \t]+status"),
        dmsetup_readonly_pattern!("dmsetup-ls", "ls"),
        dmsetup_readonly_pattern!("dmsetup-status", "status"),
        dmsetup_readonly_pattern!("dmsetup-info", "info"),
        dmsetup_readonly_pattern!("dmsetup-table", "table"),
        dmsetup_readonly_pattern!("dmsetup-deps", "deps"),
        disk_safe_pattern!(
            "diskutil-readonly",
            r"(?i:diskutil[ \t]+(?:list|info|information|activity|listFilesystems|apfs[ \t]+list(?:Snapshots|Users)?)(?:[ \t]+[^;&|\r\n<>()`$]*)?[ \t]*$)"
        ),
        // fdisk-list, mount-list, mdadm and LVM read-only exemptions were
        // redundant and removed for #448. The same is true of nbd-client -l
        // and -check: neither matches a destructive mode unless -d is present.
        // mkswap --check is NOT read-only: it checks before formatting.
        // Pseudo-device writer exclusions belong to the target rules below,
        // not here: a safe target must never exempt another destructive write.
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // A harmless destination is a property of that target, not permission
        // to skip the entire pack. Check every tee operand, including after a
        // regular file or /dev/null, but do not mistake an input redirect for
        // an output. Quote capture keeps "/dev/null extra" from being exempted.
        // Pseudo-device names are exact; /dev/shm paths cannot escape via `..`.
        destructive_pattern!(
            "tee-device",
            r#"\b(?:tee|sponge)\b(?:\s+(?:[^\s"'\\;&|<>]|\\[^\r\n]|'[^']*'|"[^"]*")+)*\s+(['"]?)/dev/(?!(?:(?:null|zero|full|random|urandom|std(?:in|out|err)|tty|console|ptmx)|(?:fd|pts)/\d+)\1(?:\s|$|[|<>])|shm/(?!(?:[^\s'"]*/)?\.\.(?:/|\1(?:\s|$)))[^\s'"]*\1(?:\s|$|[|<>]))"#,
            "tee/sponge into a device will OVERWRITE that device, exactly as dd would. Extremely dangerous!"
        ),
        // cp/mv/install write their LAST argument, so the device has to be in
        // destination position: `cp /dev/null foo` reads a device and is
        // ordinary, `cp /dev/zero /dev/sda` writes one and is not.
        destructive_pattern!(
            "copy-to-device",
            r#"\b(?:cp|mv|install)\b[^|;&]*\s(['"]?)/dev/(?!(?:(?:null|zero|full|random|urandom|std(?:in|out|err)|tty|console|ptmx)|(?:fd|pts)/\d+)\1(?:\s|$|[|<>])|shm/(?!(?:[^\s'"]*/)?\.\.(?:/|\1(?:\s|$)))[^\s'"]*\1(?:\s|$|[|<>]))[^\s'"|;&]+\1\s*$"#,
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
        // The GPT-native tools. `fdisk-edit` reaches `sfdisk` by substring and
        // `parted-modify` covers GNU parted, but nothing covered gdisk's
        // family — which is the family an agent reaches for on a UEFI system.
        // `sgdisk --zap-all /dev/sda` erases the GPT *and* the protective MBR,
        // strictly more than the `parted mklabel` the rule above denies (#456).
        //
        // The read-only carve-out lives INSIDE this pattern rather than in a
        // SafePattern, because a pack-wide exemption short-circuits every
        // destructive rule in the pack — the shape that made #448 possible.
        //
        // The option test is written as "carries an option that is not one of
        // the read-only ones" rather than "carries one of the mutating ones".
        // sgdisk's mutating surface is open-ended (-Z -o -d -n -t -c -A -g -G
        // -r -C -m -M -N -j -s -S -u -U -e …) while its read-only surface is a
        // closed handful, so enumerating the mutating side would make every
        // option this list has not heard of a false negative. A bare `sgdisk
        // /dev/sda` carries no option at all and does nothing, so it stays
        // allowed.
        //
        // `-P`/`--pretend` is sgdisk's dry run and is a dry run whatever it is
        // paired with, so it withdraws the denial the way `parted print` and
        // `Remove-Item -WhatIf` do elsewhere. That lookahead refuses to cross a
        // quote, so a `-P` sitting inside a partition name cannot buy an
        // exemption for the mutating options around it; the cost is that a
        // genuine dry run which also quotes an argument still denies, which is
        // the direction this pack errs in on purpose.
        destructive_pattern!(
            "sgdisk-modify",
            r#"sgdisk\b(?![^\n;&|'"]*[ \t]--?(?:P\b|pretend\b))(?=[^\n;&|]*['"]?/dev/)[^\n;&|]*[ \t]-(?!-?(?:p|print|i|info|b|backup|L|list-types|v|verify|V|version|h|help)\b)"#,
            "sgdisk rewrites the GPT; --zap-all/-Z also erases the protective MBR, losing every partition.",
            High,
            "sgdisk applies its options and exits — there is no confirmation step and no \
             undo. `--zap-all`/`-Z` destroys the GPT and the protective MBR together; \
             `--clear`/`-o`, `--delete`/`-d`, `--new`/`-n` and `--typecode`/`-t` each \
             rewrite the partition table in place. On a UEFI disk that is the same blast \
             radius as `parted mklabel`, which is already denied.\n\n\
             What stays allowed:\n\
             - Inspecting the table: `sgdisk --print /dev/sda`, `sgdisk -i 1 /dev/sda`.\n\
             - Saving it: `sgdisk --backup=/tmp/table.bin /dev/sda`.\n\
             - Rehearsing a change: add `-P`/`--pretend` to see what would happen.\n\n\
             Before changing anything, back the table up and look at the device:\n  \
             sgdisk --backup=/tmp/table.bin /dev/sda\n  \
             lsblk /dev/sda",
            executables = ["sgdisk"]
        ),
        // gdisk and cgdisk are interactive and carry no mutating flag to match
        // on, so they get `fdisk-edit`'s treatment: the bare invocation against
        // a device is what is denied, and `-l` (list) is excluded the same way.
        // `\b` keeps this off `sgdisk`, which has its own rule above.
        destructive_pattern!(
            "gdisk-edit",
            r#"\bc?gdisk\s+['"]?/dev/(?!.*-l)"#,
            "gdisk/cgdisk open the GPT for interactive editing; a write from that session destroys the partition table.",
            High,
            "gdisk and cgdisk are editors: they load the partition table and apply what \
             the session writes back. An agent that cannot see the prompts cannot know \
             what it is about to commit.\n\n\
             Read the table instead, which is never blocked:\n  \
             gdisk -l /dev/sda\n  \
             sgdisk --print /dev/sda\n  \
             lsblk /dev/sda",
            executables = ["gdisk", "cgdisk"]
        ),
        // mkfs (format filesystem), and the formatters `mkfs.*` fronts but an
        // agent can run directly: `mke2fs` (ext2/3/4), `mkdosfs`, `mkntfs`,
        // `mkexfatfs`, and macOS `newfs_*`. `mke2fs /dev/sdb1` reached this
        // pack through `/dev/` and matched no rule, so it was allowed.
        destructive_pattern!(
            "mkfs",
            r"(?:mkfs(?:\.[a-z0-9]+)?|mke2fs|mkdosfs|mkntfs|mkexfatfs|newfs(?:_[a-z0-9]+)?)\s+",
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
        // ----- Whole-device wipe / secure-erase tools -----
        //
        // These sit in the same class as `mkfs`/`dd of=/dev/...`/`wipefs`:
        // one command destroys an entire device or its encryption keys with no
        // confirmation and no undo. Each rule targets the destructive
        // subcommand/flag only, so the read-only spellings (`hdparm -I`,
        // `nvme list`, `cryptsetup status`, `zpool status`, `zfs list`,
        // `badblocks` without `-w`, `fstrim`) stay allowed.
        destructive_pattern!(
            "blkdiscard",
            r"\bblkdiscard\b",
            "blkdiscard discards (TRIMs) every block on the device, destroying all data instantly with no undo.",
            Critical
        ),
        destructive_pattern!(
            "cryptsetup-erase",
            r"\bcryptsetup\b(?:\s+--?\S+)*\s+(?:luksErase|luksFormat|erase|luksKillSlot)\b",
            "cryptsetup erase/luksErase/luksFormat destroys the LUKS key material; the encrypted volume becomes permanently unreadable.",
            Critical
        ),
        destructive_pattern!(
            "hdparm-security-erase",
            r"\bhdparm\b[^|;&\r\n]*--security-erase(?:-enhanced)?\b",
            "hdparm --security-erase issues an ATA secure erase of the WHOLE drive at the firmware level. Unrecoverable.",
            Critical
        ),
        destructive_pattern!(
            "nvme-format-sanitize",
            r"\bnvme\s+(?:format|sanitize)\b",
            "nvme format/sanitize erases an NVMe namespace (or the entire controller). All data is destroyed.",
            Critical
        ),
        destructive_pattern!(
            "badblocks-write",
            r"\bbadblocks\b[^|;&\r\n]*\s-[A-Za-z]*w",
            "badblocks -w (write mode) overwrites every block on the device with test patterns, destroying all existing data.",
            Critical
        ),
        destructive_pattern!(
            "sg_format",
            r"\bsg_format\b[^|;&\r\n]*--format\b",
            "sg_format --format performs a SCSI low-level format, erasing all data on the medium.",
            Critical
        ),
        destructive_pattern!(
            "zpool-destroy",
            r"\bzpool\s+destroy\b",
            "zpool destroy removes a ZFS pool and every dataset, snapshot, and byte of data it contains.",
            Critical
        ),
        destructive_pattern!(
            "zfs-destroy",
            r"\bzfs\s+destroy\b",
            "zfs destroy removes a ZFS dataset, volume, or snapshot; with -r it destroys the whole descendant tree.",
            Critical
        ),
        destructive_pattern!(
            "nwipe",
            r"\bnwipe\b",
            "nwipe (the dban successor) overwrites an entire disk with wipe patterns; `--autonuke` targets every disk. All data is destroyed.",
            Critical
        ),
        // `scrub` and `wipe` are common English words, so both rules require a
        // `/dev/` target after the command. That keys on the destructive
        // device-overwrite use and never fires on the READ-ONLY, pool/mount-
        // targeted `zpool scrub tank` / `btrfs scrub /mnt`.
        destructive_pattern!(
            "scrub-device",
            r"\bscrub\b\s+(?:[^|;&\r\n]*\s)?/dev/\S",
            "scrub overwrites a device with data-destruction patterns (DoD/Gutmann/etc.); its contents are gone.",
            Critical
        ),
        destructive_pattern!(
            "wipe-device",
            r"\bwipe\b\s+(?:[^|;&\r\n]*\s)?/dev/\S",
            "wipe securely overwrites the target device, destroying all data on it.",
            Critical
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
    fn gpt_tools_are_covered_like_their_mbr_era_siblings_issue_456() {
        // The control is the row above these in the issue: `parted mklabel`
        // and `fdisk /dev/sda` already deny, so the pack treats this exact
        // class of operation as worth blocking. These are the same operation
        // spelled with the GPT-native tools.
        let pack = create_pack();
        for cmd in [
            "sgdisk --zap-all /dev/sda",
            "sgdisk -Z /dev/sda",
            "sgdisk --clear /dev/sda",
            "sgdisk -o /dev/sda",
            "sgdisk --delete=1 /dev/sda",
            "sgdisk -d 1 /dev/sda",
            "sgdisk --new=1:0:0 /dev/sda",
            "sgdisk -n 1:0:0 /dev/sda",
            "sgdisk -t 1:8300 /dev/sda",
            "sgdisk --typecode=1:8300 /dev/sda",
            "sgdisk -g /dev/sda",
            "sgdisk --randomize-guids /dev/sda",
            // Options this rule has never heard of still deny: the test is
            // "not read-only", not "in a list of known mutations".
            "sgdisk --some-future-option /dev/sda",
            // A read-only option does not launder the mutating one beside it.
            "sgdisk --print --zap-all /dev/sda",
            "sgdisk -p -Z /dev/sda",
            // Device first, option after.
            "sgdisk /dev/sda --zap-all",
        ] {
            let matched = pack
                .check(cmd)
                .unwrap_or_else(|| panic!("sgdisk mutation must block: {cmd}"));
            assert_eq!(matched.name, Some("sgdisk-modify"), "wrong rule for {cmd}");
        }
        for cmd in [
            "gdisk /dev/sda",
            "cgdisk /dev/sda",
            "gdisk \"/dev/nvme0n1\"",
        ] {
            let matched = pack
                .check(cmd)
                .unwrap_or_else(|| panic!("interactive GPT editor must block: {cmd}"));
            assert_eq!(matched.name, Some("gdisk-edit"), "wrong rule for {cmd}");
        }
    }

    #[test]
    fn gpt_tool_read_only_forms_stay_allowed_issue_456() {
        // These allowed before the rules existed because nothing matched. They
        // have to keep allowing for the right reason now, and none of them may
        // reach a SafePattern: a pack-wide exemption would disarm every other
        // rule in this pack for the same command (#448).
        let pack = create_pack();
        for cmd in [
            "sgdisk --print /dev/sda",
            "sgdisk -p /dev/sda",
            "sgdisk --info=1 /dev/sda",
            "sgdisk -i 1 /dev/sda",
            "sgdisk --backup=/tmp/table.bin /dev/sda",
            "sgdisk -b /tmp/table.bin /dev/sda",
            "sgdisk --verify /dev/sda",
            "sgdisk --version",
            "sgdisk --list-types",
            // Bare invocation carries no option and does nothing.
            "sgdisk /dev/sda",
            // `-P` is the dry run, and stays a dry run beside a mutation.
            "sgdisk -P --zap-all /dev/sda",
            "sgdisk --pretend -Z /dev/sda",
            "sgdisk --zap-all -P /dev/sda",
            // gdisk's list mode, both orders.
            "gdisk -l /dev/sda",
            "gdisk /dev/sda -l",
            // Not these tools at all.
            "ls /dev/sda",
            "echo sgdisk --zap-all /dev/sda",
        ] {
            assert_no_match(&pack, cmd);
            assert!(
                !pack.matches_safe(cmd),
                "read-only GPT form must be allowed by not matching, not by a \
                 pack-wide exemption: {cmd}"
            );
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

    #[test]
    fn all_readonly_families_reject_redirect_data_issue_448() {
        let pack = create_pack();
        for command in [
            "dd if=/dev/zero of=/dev/sda",
            "wipefs -a /dev/sdb",
            "mkfs.ext4 /dev/sdb1",
        ] {
            for text in [
                "lsblk",
                "blkid",
                "df",
                "fdisk -l",
                "mount",
                "btrfs subvolume list report",
                "btrfs subvolume show report",
                "btrfs filesystem show report",
                "btrfs filesystem df report",
                "btrfs filesystem usage report",
                "btrfs device stats report",
                "btrfs property get report",
                "btrfs scrub status report",
                "dmsetup ls report",
                "dmsetup info report",
                "dmsetup status report",
                "dmsetup table report",
                "dmsetup deps report",
                "nbd-client -l report",
                "nbd-client -check report",
                "diskutil list report",
                "dd of=backup.img",
                "dd of=/dev/null",
                "tee /dev/null",
                "cp image /dev/null",
            ] {
                for quote in ['\'', '"'] {
                    let candidate = format!("{command} 2>>{quote}/tmp/{text}{quote}");
                    assert!(!pack.matches_safe(&candidate), "exempted: {candidate}");
                    // At the raw-pack layer multiple destructive expressions
                    // can see the filename. Require a denial, never a waiver.
                    assert!(pack.check(&candidate).is_some(), "allowed: {candidate}");
                }
            }
        }
    }

    #[test]
    fn readonly_exemptions_require_the_actual_executable_issue_448() {
        let pack = create_pack();
        for prefix in [
            "2>/tmp/lsblk ",
            "2>/tmp/blkid ",
            "2>/tmp/df ",
            "REPORT=/tmp/lsblk ",
            "REPORT=/tmp/df ",
            "sudo -u lsblk ",
            "sudo -u df ",
        ] {
            let command = format!("{prefix}dd if=/dev/zero of=/dev/sda");
            assert!(!pack.matches_safe(&command), "exempted: {command}");
            assert_blocks_with_pattern(&pack, &command, "dd-device");
        }
        for command in [
            "lsblk-helper dd of=/dev/sda",
            "df-helper dd of=/dev/sda",
            "blkid-helper dd of=/dev/sda",
            "lsblk; dd of=/dev/sda",
            "btrfs subvolume list /mnt; dd of=/dev/sda",
        ] {
            assert!(!pack.matches_safe(command), "exempted: {command}");
        }
    }

    #[test]
    fn readonly_global_flags_do_not_consume_mutations_issue_448() {
        let pack = create_pack();
        for command in [
            "dmsetup -v remove info",
            "dmsetup --noudevsync remove table",
            "dmsetup --verifyudev remove status",
        ] {
            assert!(!pack.matches_safe(command), "exempted: {command}");
            assert_blocks_with_pattern(&pack, command, "dmsetup-remove");
        }
        for command in [
            "dmsetup -v info remove",
            "dmsetup --noudevsync table remove",
            "dmsetup --verifyudev status remove",
            "btrfs --format json subvolume list /mnt",
            "btrfs --format=json filesystem show",
            "btrfs --verbose --log info filesystem usage /mnt",
            "btrfs -q device stats /mnt",
            "nbd-client -l server.example.com",
            "nbd-client -check /dev/nbd0",
        ] {
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn dd_discard_requires_real_output_operands_issue_448() {
        let pack = create_pack();
        // Repeated of= has no portable ordering guarantee. No safe output may
        // cancel a device output in either order; filenames are not operands.
        for command in [
            "dd of=/dev/null of=/dev/sda",
            "dd of=/dev/sda of=/dev/null",
            "dd of=backup.img of=/dev/sda",
            "dd of=/dev/sda of=backup.img",
            "dd if=of=backup.img of=/dev/sda",
            "dd if='of=backup.img' of=/dev/sda",
            "dd if=source.img of='/dev/null' of='/dev/sda'",
            "dd of=/dev/null 2>/dev/sda",
        ] {
            assert!(!pack.matches_safe(command), "exempted: {command}");
            assert_blocks_with_pattern(&pack, command, "dd-device");
        }
        for command in [
            "dd if=/dev/sda of=/dev/null count=1",
            "dd of='/dev/null' if='/tmp/input with spaces'",
            "dd of=\"/dev/null\" if=/dev/sda",
            "dd 'of=/dev/null' if=/dev/sda",
            "dd if='data of=/dev/sda' of=/dev/null",
            "dd if=of=backup.img of=/dev/null",
            "dd of=/dev/null of=/dev/zero",
            "dd of=/dev/null < /dev/sda",
            "dd if=/dev/sda of=/dev/null 2>/tmp/benchmark.log",
            "dd if=/dev/sda of=/dev/null 2>&1",
            "dd if=/dev/sda of=/dev/null > /dev/null",
            "sudo -n /bin/dd if=/dev/sda of=/dev/null",
        ] {
            assert_safe_pattern_matches(&pack, command);
            assert_allows(&pack, command);
        }
    }

    #[test]
    fn pseudo_devices_do_not_hide_other_writer_targets_issue_444() {
        let pack = create_pack();
        for command in [
            "tee /dev/null /dev/sda",
            "tee out.log /dev/sda",
            "tee --append /dev/null /dev/sda",
            "tee 'log with spaces' /dev/sda",
            "tee /dev/null-disk",
            "tee /dev/fd/3-disk",
            "tee /dev/shm/../sda",
            "tee /dev/shm/x/../../sda",
            "tee \"/dev/null /../sda\"",
        ] {
            assert_blocks_with_pattern(&pack, command, "tee-device");
        }
        for command in [
            "cp file /dev/null-disk",
            "cp file /dev/shm/../sda",
            "mv file /dev/shm/x/../../sda",
        ] {
            assert_blocks_with_pattern(&pack, command, "copy-to-device");
        }
        for command in [
            "tee /dev/null /dev/zero",
            "tee /dev/null out.log",
            "tee out.log < /dev/sda",
            "tee 'log /dev/sda'",
            "tee \"/dev/null\"",
            "cp file '/dev/null'",
            "cp file /dev/shm/buffer",
        ] {
            assert_allows(&pack, command);
        }
    }

    /// Whole-device wipe / secure-erase tools that were previously fail-open in
    /// this default-on pack: blkdiscard, cryptsetup erase, ATA/NVMe secure
    /// erase, write-mode badblocks, SCSI low-level format, and ZFS destroy.
    #[test]
    fn whole_device_wipe_tools_block() {
        let pack = create_pack();
        for (command, rule) in [
            ("blkdiscard /dev/sda", "blkdiscard"),
            ("blkdiscard -f /dev/nvme0n1", "blkdiscard"),
            ("cryptsetup luksErase /dev/sda", "cryptsetup-erase"),
            ("cryptsetup erase /dev/sda", "cryptsetup-erase"),
            (
                "cryptsetup --verbose luksKillSlot mydev 0",
                "cryptsetup-erase",
            ),
            ("cryptsetup luksFormat /dev/sdb", "cryptsetup-erase"),
            (
                "hdparm --user-master u --security-erase p /dev/sda",
                "hdparm-security-erase",
            ),
            (
                "hdparm --security-erase-enhanced p /dev/sda",
                "hdparm-security-erase",
            ),
            ("nvme format /dev/nvme0n1", "nvme-format-sanitize"),
            ("nvme sanitize -a 2 /dev/nvme0n1", "nvme-format-sanitize"),
            ("badblocks -w /dev/sda", "badblocks-write"),
            ("badblocks -svw /dev/sda", "badblocks-write"),
            ("sg_format --format /dev/sg0", "sg_format"),
            ("zpool destroy tank", "zpool-destroy"),
            ("zfs destroy -r tank/data", "zfs-destroy"),
            ("zfs destroy tank/data@snap", "zfs-destroy"),
            ("nwipe --autonuke /dev/sda", "nwipe"),
            ("nwipe --autonuke", "nwipe"),
            ("scrub -p dod /dev/sda", "scrub-device"),
            ("scrub /dev/sdb", "scrub-device"),
            ("wipe /dev/sda", "wipe-device"),
            ("wipe -q /dev/nvme0n1", "wipe-device"),
        ] {
            let matched = pack
                .check(command)
                .unwrap_or_else(|| panic!("{command} must be denied"));
            assert_eq!(matched.name, Some(rule), "{command}");
            assert_eq!(matched.severity, Severity::Critical, "{command}");
        }

        // Read-only / non-destructive spellings of the same tools stay allowed.
        for command in [
            "blkid /dev/sda",
            "fstrim /",
            "fstrim -av",
            "hdparm -I /dev/sda",
            "hdparm -t /dev/sda",
            "nvme list",
            "nvme id-ctrl /dev/nvme0n1",
            "cryptsetup status mydev",
            "cryptsetup open /dev/sda mydev",
            "badblocks -sv /dev/sda",
            "badblocks -o bad.txt /dev/sda",
            "zpool status",
            "zpool list -H",
            "zfs list",
            "zfs get all tank",
            // `scrub`/`wipe` on a pool or mountpoint (not a /dev/ node) are the
            // read-only ZFS/btrfs verbs and ordinary file ops — must stay allowed.
            "zpool scrub tank",
            "btrfs scrub start /mnt",
            "wipe notes.txt",
        ] {
            assert_allows(&pack, command);
        }
    }

    /// The formatters `mkfs.*` fronts, run directly, format just the same.
    #[test]
    fn direct_filesystem_formatters_are_mkfs() {
        let pack = create_pack();
        for command in [
            "mke2fs /dev/sdb1",
            "mke2fs -t ext4 /dev/sdb1",
            "mkdosfs -F 32 /dev/sdc1",
            "mkntfs -f /dev/sdc2",
            "mkexfatfs /dev/sdd1",
            "newfs_apfs /dev/disk2s1",
            "newfs_hfs -v Data /dev/disk3s2",
            "newfs_msdos -F 32 /dev/disk4s1",
        ] {
            assert_blocks_with_pattern(&pack, command, "mkfs");
        }
        for command in [
            "dumpe2fs /dev/sdb1",
            "e2fsck -n /dev/sdb1",
            "tune2fs -l /dev/sdb1",
        ] {
            assert_allows(&pack, command);
        }
    }
}

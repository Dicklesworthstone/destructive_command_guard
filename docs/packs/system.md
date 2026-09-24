# System Packs

This document describes packs in the `system` category.

## Packs in this Category

- [Disk Operations](#systemdisk)
- [Permissions](#systempermissions)
- [Services](#systemservices)

---

## Disk Operations

**Pack ID:** `system.disk`

Protects against destructive disk operations like dd to devices, mkfs, partition table modifications, RAID management, btrfs/LVM/device-mapper operations, network block devices, and macOS diskutil erase/partition/APFS deletion

### Keywords

Commands containing these keywords are checked against this pack:

- `dd`
- `diskutil`
- `fdisk`
- `mkfs`
- `mke2fs`
- `mkdosfs`
- `mkntfs`
- `mkexfatfs`
- `newfs`
- `newfs_apfs`
- `newfs_hfs`
- `newfs_msdos`
- `newfs_exfat`
- `mkswap`
- `parted`
- `mount`
- `wipefs`
- `sgdisk`
- `gdisk`
- `cgdisk`
- `/dev/`
- `mdadm`
- `btrfs`
- `dmsetup`
- `nbd-client`
- `pvremove`
- `vgremove`
- `lvremove`
- `vgreduce`
- `lvreduce`
- `lvresize`
- `pvmove`
- `blkdiscard`
- `cryptsetup`
- `hdparm`
- `nvme`
- `badblocks`
- `sg_format`
- `zpool`
- `zfs`
- `nwipe`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `dd-discard` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?dd[ \t]+(?:(?:(?:if\|ibs\|obs\|bs\|cbs\|skip\|iseek\|seek\|oseek\|count\|conv\|iflag\|oflag\|status)=(?:[^\s;&\|<>()"'\\$`*?\[\]{}~]+\|'[^'\r\n]*'\|"[^"\\$`\r\n]*")\|[0-9]*[<>]&(?:[0-9]+\|-)\|[0-9]*<[ \t]*(?:[^\s;&\|<>()"'\\$`*?\[\]{}~]+\|'[^'\r\n]*'\|"[^"\\$`\r\n]*")\|(?:[0-9]*(?:>>?\|>\\|)\|&>>?)[ \t]*(?:/dev/(?:null\|zero\|full)\|'/dev/(?:null\|zero\|full)'\|"/dev/(?:null\|zero\|full)"\|(?!['"]?/dev/)(?:[^\s;&\|<>()"'\\$`*?\[\]{}~]+\|'[^'\r\n]*'\|"[^"\\$`\r\n]*")))[ \t]+)*(?:of=(?:/dev/(?:null\|zero\|full)\|'/dev/(?:null\|zero\|full)'\|"/dev/(?:null\|zero\|full)")\|'of=/dev/(?:null\|zero\|full)'\|"of=/dev/(?:null\|zero\|full)")(?:[ \t]+(?:(?:(?:if\|ibs\|obs\|bs\|cbs\|skip\|iseek\|seek\|oseek\|count\|conv\|iflag\|oflag\|status)=(?:[^\s;&\|<>()"'\\$`*?\[\]{}~]+\|'[^'\r\n]*'\|"[^"\\$`\r\n]*")\|[0-9]*[<>]&(?:[0-9]+\|-)\|[0-9]*<[ \t]*(?:[^\s;&\|<>()"'\\$`*?\[\]{}~]+\|'[^'\r\n]*'\|"[^"\\$`\r\n]*")\|(?:[0-9]*(?:>>?\|>\\|)\|&>>?)[ \t]*(?:/dev/(?:null\|zero\|full)\|'/dev/(?:null\|zero\|full)'\|"/dev/(?:null\|zero\|full)"\|(?!['"]?/dev/)(?:[^\s;&\|<>()"'\\$`*?\[\]{}~]+\|'[^'\r\n]*'\|"[^"\\$`\r\n]*")))\|(?:of=(?:/dev/(?:null\|zero\|full)\|'/dev/(?:null\|zero\|full)'\|"/dev/(?:null\|zero\|full)")\|'of=/dev/(?:null\|zero\|full)'\|"of=/dev/(?:null\|zero\|full)")))*[ \t]*$` |
| `lsblk` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?lsblk(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `blkid` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?blkid(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `df` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?df(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `parted-print` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?parted[ \t]+(?:(?:-s\|--script\|-m\|--machine\|-j\|--json)[ \t]+)*(?:['"]?/dev/[^\s'";&\|<>()`$]+['"]?[ \t]+)?print(?:[ \t]+(?:devices\|free\|list\|all\|\d+))?[ \t]*$` |
| `btrfs-subvolume-list` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*subvolume[ \t]+list(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-subvolume-show` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*subvolume[ \t]+show(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-filesystem-show` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*filesystem[ \t]+show(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-filesystem-df` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*filesystem[ \t]+df(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-filesystem-usage` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*filesystem[ \t]+usage(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-device-stats` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*device[ \t]+stats(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-property-get` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*property[ \t]+(?:get\|list)(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `btrfs-scrub-status` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?btrfs[ \t]+(?:(?:--(?:verbose\|quiet)\|-[vq]+\|--format(?:=\|[ \t]+)(?:text\|json)\|--log(?:=\|[ \t]+)(?:default\|info\|verbose\|debug\|quiet))[ \t]+)*scrub[ \t]+status(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `dmsetup-ls` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?dmsetup[ \t]+(?:(?:-v+\|-c\|--(?:verbose\|noudevsync\|verifyudev\|readonly\|columns\|noheadings))[ \t]+)*ls(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `dmsetup-status` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?dmsetup[ \t]+(?:(?:-v+\|-c\|--(?:verbose\|noudevsync\|verifyudev\|readonly\|columns\|noheadings))[ \t]+)*status(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `dmsetup-info` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?dmsetup[ \t]+(?:(?:-v+\|-c\|--(?:verbose\|noudevsync\|verifyudev\|readonly\|columns\|noheadings))[ \t]+)*info(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `dmsetup-table` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?dmsetup[ \t]+(?:(?:-v+\|-c\|--(?:verbose\|noudevsync\|verifyudev\|readonly\|columns\|noheadings))[ \t]+)*table(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `dmsetup-deps` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?dmsetup[ \t]+(?:(?:-v+\|-c\|--(?:verbose\|noudevsync\|verifyudev\|readonly\|columns\|noheadings))[ \t]+)*deps(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$` |
| `diskutil-readonly` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?(?i:diskutil[ \t]+(?:list\|info\|information\|activity\|listFilesystems\|apfs[ \t]+list(?:Snapshots\|Users)?)(?:[ \t]+[^;&\|\r\n<>()`$]*)?[ \t]*$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `tee-device` | tee/sponge into a device will OVERWRITE that device, exactly as dd would. Extremely dangerous! | high |
| `copy-to-device` | Copying or moving onto a device OVERWRITES that device, exactly as dd would. Extremely dangerous! | high |
| `dd-device` | dd to a block device will OVERWRITE all data on that device. Extremely dangerous! | high |
| `dd-wipe` | dd from /dev/zero or /dev/urandom to a device will WIPE all data! | high |
| `ddrescue-device` | ddrescue --force writes its output onto a device, overwriting all data on it, exactly as dd would. | critical |
| `sfdisk-modify` | sfdisk rewrites the partition table: options act immediately, and a bare invocation reads a new layout from stdin. | high |
| `fdisk-edit` | fdisk can modify partition tables and cause data loss. | high |
| `parted-modify` | parted can modify partition tables and cause data loss. | high |
| `sgdisk-modify` | sgdisk rewrites the GPT; --zap-all/-Z also erases the protective MBR, losing every partition. | high |
| `gdisk-edit` | gdisk/cgdisk open the GPT for interactive editing; a write from that session destroys the partition table. | high |
| `mkfs` | mkfs formats a partition/device and ERASES all existing data. | high |
| `mkswap` | mkswap formats a partition as a swap area, ERASING any existing data. | high |
| `wipefs` | wipefs removes filesystem signatures. Use with extreme caution. | high |
| `mount-bind-root` | mount --bind to root directory can have system-wide effects. | high |
| `umount-force` | umount -f force unmounts which may cause data loss if device is in use. | high |
| `losetup-device` | losetup modifies loop device associations. Verify before proceeding. | high |
| `mdadm-stop` | mdadm --stop shuts down a RAID array. Data may become inaccessible. | high |
| `mdadm-remove` | mdadm --remove removes a drive from a RAID array. May cause data loss if redundancy is lost. | high |
| `mdadm-fail` | mdadm --fail marks a device as failed. Use only for intentional drive replacement. | high |
| `mdadm-zero-superblock` | mdadm --zero-superblock PERMANENTLY erases RAID metadata. Array cannot be reassembled. | high |
| `mdadm-create` | mdadm --create initializes a new RAID array, ERASING existing data on member devices. | high |
| `mdadm-grow` | mdadm --grow reshapes a RAID array. Interruption can cause data loss. Backup first. | high |
| `btrfs-subvolume-delete` | btrfs subvolume delete PERMANENTLY removes a subvolume and all its data. | high |
| `btrfs-device-remove` | btrfs device remove redistributes data off a device. Interruption causes data loss. | high |
| `btrfs-device-add` | btrfs device add incorporates a device into the filesystem. Verify the device is correct. | high |
| `btrfs-balance` | btrfs balance redistributes data across devices. Can be slow and disruptive. | high |
| `btrfs-check-repair` | btrfs check --repair is DANGEROUS and can cause data loss. Backup first! | high |
| `btrfs-rescue` | btrfs rescue operations modify filesystem metadata. Use only as last resort. | high |
| `btrfs-filesystem-resize` | btrfs filesystem resize can shrink a filesystem. Data loss if size is too small. | high |
| `dmsetup-remove` | dmsetup remove detaches a device-mapper device. May cause data loss if in use. | high |
| `dmsetup-remove-all` | dmsetup remove_all removes ALL device-mapper devices. Extremely dangerous! | high |
| `dmsetup-wipe-table` | dmsetup wipe_table replaces the device table, causing all I/O to fail. | high |
| `dmsetup-clear` | dmsetup clear removes the mapping table from a device. | high |
| `dmsetup-load` | dmsetup load changes device mapping. Verify the new table is correct. | high |
| `dmsetup-create` | dmsetup create sets up a new device-mapper device. Verify parameters carefully. | high |
| `nbd-client-disconnect` | nbd-client -d disconnects a network block device. Data loss if not properly unmounted. | high |
| `nbd-client-connect` | nbd-client connecting a device can expose or overwrite data. Verify server and device. | high |
| `pvremove` | pvremove ERASES LVM metadata from a physical volume. Data becomes inaccessible. | high |
| `vgremove` | vgremove DELETES a volume group and all logical volumes within it. | high |
| `lvremove` | lvremove PERMANENTLY deletes a logical volume and ALL its data. | high |
| `vgreduce` | vgreduce removes a physical volume from a volume group. Data may be lost. | high |
| `lvreduce` | lvreduce SHRINKS a logical volume. Data loss if filesystem isn't resized first! | high |
| `lvresize-shrink` | lvresize with negative size SHRINKS the volume. Resize filesystem first or lose data! | high |
| `pvmove` | pvmove migrates data between physical volumes. Do NOT interrupt or data may be lost. | high |
| `lvconvert-merge` | lvconvert --merge reverts LV to snapshot state, discarding changes since snapshot. | high |
| `diskutil-erase` | diskutil erase operations DESTROY all data on the target disk or volume. | critical |
| `diskutil-partition` | diskutil partitioning operations rewrite the partition map and erase data. | critical |
| `diskutil-apfs-delete` | diskutil apfs delete/erase operations permanently remove APFS containers, volumes, or snapshots. | critical |
| `blkdiscard` | blkdiscard discards (TRIMs) every block on the device, destroying all data instantly with no undo. | critical |
| `cryptsetup-erase` | cryptsetup erase/luksErase/luksFormat destroys the LUKS key material; the encrypted volume becomes permanently unreadable. | critical |
| `hdparm-security-erase` | hdparm --security-erase issues an ATA secure erase of the WHOLE drive at the firmware level. Unrecoverable. | critical |
| `nvme-format-sanitize` | nvme format/sanitize erases an NVMe namespace (or the entire controller). All data is destroyed. | critical |
| `badblocks-write` | badblocks -w (write mode) overwrites every block on the device with test patterns, destroying all existing data. | critical |
| `sg_format` | sg_format --format performs a SCSI low-level format, erasing all data on the medium. | critical |
| `zpool-destroy` | zpool destroy removes a ZFS pool and every dataset, snapshot, and byte of data it contains. | critical |
| `zfs-destroy` | zfs destroy removes a ZFS dataset, volume, or snapshot; with -r it destroys the whole descendant tree. | critical |
| `nwipe` | nwipe (the dban successor) overwrites an entire disk with wipe patterns; `--autonuke` targets every disk. All data is destroyed. | critical |
| `scrub-device` | scrub overwrites a device with data-destruction patterns (DoD/Gutmann/etc.); its contents are gone. | critical |
| `wipe-device` | wipe securely overwrites the target device, destroying all data on it. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "system.disk:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "system.disk:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Permissions

**Pack ID:** `system.permissions`

Protects against dangerous permission changes like chmod 777, recursive chmod/chown on system directories

### Keywords

Commands containing these keywords are checked against this pack:

- `chmod`
- `chown`
- `chgrp`
- `setfacl`
- `icacls`
- `cacls`
- `takeown`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `chmod-non-recursive` | `chmod\s+(?!-[rR])(?:\d{3,4}\|[ugoa][+-][rwxXst]+)\s+[^/~$"']` |
| `stat` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?stat\b` |
| `ls-perms` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?ls\b.*-[a-zA-Z]*l` |
| `getfacl` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?getfacl\b` |
| `namei` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?namei\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `chmod-777` | chmod 777 makes files world-writable. This is a security risk. | high |
| `chmod-recursive-root` | chmod -R on system directories can break system permissions. | critical |
| `chown-recursive-root` | chown -R on system directories can break system ownership. | high |
| `chgrp-recursive-root` | chgrp -R on system directories can break system group ownership. | high |
| `icacls-recursive-system` | icacls /t on a Windows system tree rewrites ACLs recursively and can break the system. | critical |
| `takeown-recursive-system` | takeown /r on a Windows system tree seizes ownership recursively and is hard to undo. | high |
| `icacls-grant-everyone` | granting Everyone full/modify/write access makes the target world-writable. | high |
| `chmod-setuid` | Setting setuid bit (chmod u+s) is a security-sensitive operation. | high |
| `chmod-setgid` | Setting setgid bit (chmod g+s) is a security-sensitive operation. | high |
| `chown-to-root` | Changing ownership to root should be done carefully. | high |
| `setfacl-all` | setfacl -R on system directories can modify access control across the filesystem. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "system.permissions:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "system.permissions:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Services

**Pack ID:** `system.services`

Protects against dangerous service operations like stopping critical services and modifying init configuration

### Keywords

Commands containing these keywords are checked against this pack:

- `systemctl`
- `service`
- `init`
- `upstart`
- `shutdown`
- `reboot`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `systemctl-status` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s\|$)` |
| `systemctl-list` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list-(?:units\|unit-files\|sockets\|timers)(?=\s\|$)` |
| `systemctl-show` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s\|$)` |
| `systemctl-is` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+is-(?:active\|enabled\|failed)(?=\s\|$)` |
| `systemctl-reload` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+daemon-reload(?=\s\|$)` |
| `systemctl-cat` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cat(?=\s\|$)` |
| `journalctl` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?journalctl\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `systemctl-stop-critical` | Stopping/disabling critical services can cause system access loss or outage. | high |
| `systemctl-stop` | systemctl stop/disable/mask affects service availability. Verify service name. | high |
| `service-stop-critical` | Stopping critical services can cause system access loss. | high |
| `systemctl-isolate` | systemctl isolate changes the system state significantly. | high |
| `systemctl-power` | systemctl poweroff/reboot/halt will shut down or restart the system. | critical |
| `shutdown` | shutdown will power off or restart the system. | critical |
| `reboot` | reboot will restart the system. | critical |
| `init-level` | init 0 shuts down, init 6 reboots the system. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "system.services:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "system.services:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

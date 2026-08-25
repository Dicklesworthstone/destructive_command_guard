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
- `mkswap`
- `parted`
- `mount`
- `wipefs`
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

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `dd-file-out` | `dd\s+.*of=['"]?[^/\s'"]+\.` |
| `dd-discard` | `dd\s+.*of=['"]?/dev/(?:null\|zero\|full)['"]?(?:\s\|$)` |
| `lsblk` | `\blsblk\b` |
| `fdisk-list` | `fdisk\s+-l` |
| `parted-print` | `parted\b(?:\s+--?\S+)*\s+(?:['"]?/dev/\S+['"]?\s+)?print(?:\s+(?:devices\|free\|list\|all\|\d+))?\s*$` |
| `blkid` | `\bblkid\b` |
| `df` | `\bdf\b` |
| `mount-list` | `\bmount\s*$` |
| `mkswap-check` | `mkswap\s+(?:.*\s+)?--check\b` |
| `mdadm-detail` | `mdadm\s+--detail\b` |
| `mdadm-examine` | `mdadm\s+--examine\b` |
| `mdadm-query` | `mdadm\s+--query\b` |
| `mdadm-query-short` | `mdadm\s+-Q\b` |
| `mdadm-scan` | `mdadm\s+--scan\b` |
| `btrfs-subvolume-list` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+subvolume\s+list(?=\s\|$)` |
| `btrfs-subvolume-show` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+subvolume\s+show(?=\s\|$)` |
| `btrfs-filesystem-show` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+show(?=\s\|$)` |
| `btrfs-filesystem-df` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+df(?=\s\|$)` |
| `btrfs-filesystem-usage` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+usage(?=\s\|$)` |
| `btrfs-device-stats` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+device\s+stats(?=\s\|$)` |
| `btrfs-property-get` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+property\s+(?:get\|list)(?=\s\|$)` |
| `btrfs-scrub-status` | `btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+scrub\s+status(?=\s\|$)` |
| `dmsetup-ls` | `dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ls(?=\s\|$)` |
| `dmsetup-status` | `dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s\|$)` |
| `dmsetup-info` | `dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+info(?=\s\|$)` |
| `dmsetup-table` | `dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+table(?=\s\|$)` |
| `dmsetup-deps` | `dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deps(?=\s\|$)` |
| `nbd-client-list` | `nbd-client\s+-l\b` |
| `nbd-client-check` | `nbd-client\s+.*-check\b` |
| `diskutil-readonly` | `(?i)diskutil\s+(?:list\|info\|information\|activity\|listFilesystems\|apfs\s+list(?:Snapshots\|Users)?)\b[^;&\|\r\n]*$` |
| `lvm-list` | `\b(?:lvs\|vgs\|pvs)\b` |
| `lvm-display` | `\b(?:lvdisplay\|vgdisplay\|pvdisplay)\b` |
| `lvm-scan` | `\b(?:lvscan\|vgscan\|pvscan)\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `dd-device` | dd to a block device will OVERWRITE all data on that device. Extremely dangerous! | high |
| `dd-wipe` | dd from /dev/zero or /dev/urandom to a device will WIPE all data! | high |
| `fdisk-edit` | fdisk can modify partition tables and cause data loss. | high |
| `parted-modify` | parted can modify partition tables and cause data loss. | high |
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

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `chmod-non-recursive` | `chmod\s+(?!-[rR])(?:\d{3,4}\|[ugoa][+-][rwxXst]+)\s+[^/]` |
| `stat` | `\bstat\b` |
| `ls-perms` | `ls\s+.*-[a-zA-Z]*l` |
| `getfacl` | `\bgetfacl\b` |
| `namei` | `\bnamei\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `chmod-777` | chmod 777 makes files world-writable. This is a security risk. | high |
| `chmod-recursive-root` | chmod -R on system directories can break system permissions. | critical |
| `chown-recursive-root` | chown -R on system directories can break system ownership. | high |
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
| `service-status` | `service\s+\S+\s+status(?=\s\|$)` |
| `systemctl-list` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list-(?:units\|unit-files\|sockets\|timers)(?=\s\|$)` |
| `systemctl-show` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s\|$)` |
| `systemctl-is` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+is-(?:active\|enabled\|failed)(?=\s\|$)` |
| `systemctl-reload` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+daemon-reload(?=\s\|$)` |
| `systemctl-cat` | `systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cat(?=\s\|$)` |
| `journalctl` | `\bjournalctl\b` |

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

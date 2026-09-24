# windows

This document describes packs in the `windows` category.

## Packs in this Category

- [Windows Filesystem](#windowsfilesystem)
- [Windows Disk & System](#windowssystem)
- [Windows Misc (registry/accounts/wsl)](#windowsmisc)
- [Windows PowerShell Cmdlets](#windowspowershell)

---

## Windows Filesystem

**Pack ID:** `windows.filesystem`

Protects against recursive/forced filesystem destruction on Windows: cmd `del /s`, `rd /s`, `format <drive>:`, PowerShell `Remove-Item -Recurse (with or without `-Force`; aliases included), `Clear-Content`, `Clear-RecycleBin`, and the .NET recursive-delete APIs `[System.IO.Directory]::Delete($path, $true)` and `<DirectoryInfo>.Delete($true)`.

### Keywords

Commands containing these keywords are checked against this pack:

- `del`
- `DEL`
- `erase`
- `ERASE`
- `rd`
- `RD`
- `rmdir`
- `RMDIR`
- `format`
- `FORMAT`
- `Remove-Item`
- `remove-item`
- `REMOVE-ITEM`
- `rm`
- `RM`
- `ri`
- `RI`
- `Clear-Content`
- `clear-content`
- `CLEAR-CONTENT`
- `clc`
- `CLC`
- `Clear-RecycleBin`
- `clear-recyclebin`
- `CLEAR-RECYCLEBIN`
- `IO.Directory`
- `io.directory`
- `Io.Directory`
- `IO.DIRECTORY`
- `.Delete(`
- `.delete(`
- `.DELETE(`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `whatif-preview` | `(?i)^\s*(?:(?:remove-item\|ri\|clear-content\|clc\|clear-recyclebin)\b(?![^\|&;\r\n]*\s--(?:\s\|$))[^\|&;\r\n]*\s-whatif\b\|rm\b(?=[^\|&;\r\n]*\s-recurse\b)(?![^\|&;\r\n]*\s--(?:\s\|$))[^\|&;\r\n]*\s-whatif\b)[^\|&;\r\n]*$` |
| `del-help` | `(?i)^\s*(?:del\|rd\|rmdir\|format\|erase)(?:\.exe)?\s+/\?\s*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `windows-filesystem-semantic-unverified` | The Windows filesystem command contains unresolved shell syntax in an executable or destructive option position. | critical |
| `del-recursive` | del /s recursively deletes every matching file in a directory tree. | critical |
| `rd-recursive` | rd /s deletes a directory and its entire contents. | critical |
| `remove-item-recurse-force` | Remove-Item -Recurse -Force deletes a tree with no Recycle Bin and no prompt. | critical |
| `remove-item-recurse` | Remove-Item -Recurse permanently deletes a tree with no Recycle Bin. | critical |
| `format-drive` | format <drive>: erases an entire volume. | critical |
| `clear-content` | Clear-Content empties a file's contents in place with no undo. | high |
| `clear-recyclebin` | Clear-RecycleBin permanently purges the Recycle Bin. | medium |
| `dotnet-directory-delete-recursive` | [System.IO.Directory]::Delete with a true recursive flag deletes an entire directory tree. | critical |
| `dotnet-directory-delete` | [System.IO.Directory]::Delete removes a directory outside the Recycle Bin. | high |
| `directoryinfo-delete-recursive` | .Delete($true) on a DirectoryInfo object recursively deletes the directory tree. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "windows.filesystem:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "windows.filesystem:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Windows Disk & System

**Pack ID:** `windows.system`

Protects against catastrophic Windows disk/system operations: `vssadmin delete shadows` / `wmic shadowcopy delete` / `Win32_ShadowCopy` deletion through WMI or CIM (Volume Shadow Copy destruction), `wbadmin delete` (backup recovery points), `diskpart`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `Remove-VirtualDisk`, `Initialize-Disk`, `Reset-PhysicalDisk`, `cipher /w`, and `bcdedit /delete`.

### Keywords

Commands containing these keywords are checked against this pack:

- `vssadmin`
- `VSSADMIN`
- `wmic`
- `WMIC`
- `shadowcopy`
- `ShadowCopy`
- `SHADOWCOPY`
- `Win32_ShadowCopy`
- `win32_shadowcopy`
- `WIN32_SHADOWCOPY`
- `diskpart`
- `DISKPART`
- `Format-Volume`
- `format-volume`
- `FORMAT-VOLUME`
- `Clear-Disk`
- `clear-disk`
- `CLEAR-DISK`
- `Remove-Partition`
- `remove-partition`
- `REMOVE-PARTITION`
- `Remove-VirtualDisk`
- `remove-virtualdisk`
- `REMOVE-VIRTUALDISK`
- `Initialize-Disk`
- `initialize-disk`
- `INITIALIZE-DISK`
- `Reset-PhysicalDisk`
- `reset-physicaldisk`
- `RESET-PHYSICALDISK`
- `cipher`
- `CIPHER`
- `bcdedit`
- `BCDEDIT`
- `wbadmin`
- `WBADMIN`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `vssadmin-list` | `(?i)^\s*vssadmin(?:\.exe)?\s+list\b[^\|&;\r\n]*$` |
| `diskpart-list` | `(?i)^\s*diskpart(?:\.exe)?\s+(?:/s\s+\S+\s+)?list\b[^\|&;\r\n]*$` |
| `storage-whatif` | `(?i)^\s*(?:format-volume\|clear-disk\|remove-partition\|remove-virtualdisk\|initialize-disk\|reset-physicaldisk)\b[^\|&;\r\n'"`$@(){}]*\s-whatif(?:\s[^\|&;\r\n'"`$@(){}]*)?$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `vssadmin-delete-shadows` | vssadmin delete shadows destroys Volume Shadow Copies (System Restore + backups). | critical |
| `wbadmin-delete` | wbadmin delete destroys Windows backup recovery points or the backup catalog. | critical |
| `wmic-shadowcopy-delete` | wmic shadowcopy delete destroys Volume Shadow Copies. | critical |
| `wmi-shadowcopy-delete` | Deleting Win32_ShadowCopy instances destroys Volume Shadow Copies. | critical |
| `diskpart` | diskpart with clean/delete/format/script reconfigures or wipes disks and partitions. | high |
| `format-volume` | Format-Volume erases a volume's filesystem and data. | critical |
| `clear-disk` | Clear-Disk removes all partitions and data from a disk. | critical |
| `remove-partition` | Remove-Partition deletes a partition and its data. | critical |
| `remove-virtualdisk` | Remove-VirtualDisk deletes a Storage Spaces virtual disk and all data on it. | critical |
| `initialize-or-reset-disk` | Initialize-Disk / Reset-PhysicalDisk wipe disk metadata and data. | high |
| `cipher-wipe` | cipher /w overwrites free space, making deleted files unrecoverable. | high |
| `bcdedit-delete` | bcdedit /delete removes a boot configuration entry. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "windows.system:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "windows.system:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Windows Misc (registry/accounts/wsl)

**Pack ID:** `windows.misc`

Protects against destructive Windows cmd operations: `reg delete`, `net user|localgroup /delete`, `sc delete`, `schtasks /delete`, `wsl --unregister` (destroys a WSL distro), and `robocopy /MIR` (mirror delete).

### Keywords

Commands containing these keywords are checked against this pack:

- `reg`
- `REG`
- `net`
- `NET`
- `sc`
- `SC`
- `schtasks`
- `SCHTASKS`
- `wsl`
- `WSL`
- `robocopy`
- `ROBOCOPY`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `reg-query` | `(?i)^\s*reg(?:\.exe)?\s+(?:query\|export\|save)\b[^\|&;\r\n]*$` |
| `sc-query` | `(?i)^\s*sc(?:\.exe)?\s+(?:query\|qc\|queryex\|enumdepend)\b[^\|&;\r\n]*$` |
| `wsl-list` | `(?i)^\s*wsl(?:\.exe)?\s+(?:--list\|-l\|--export\|--status)\b[^\|&;\r\n]*$` |
| `schtasks-query` | `(?i)^\s*schtasks(?:\.exe)?\s+/query\b[^\|&;\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `reg-delete` | reg delete removes registry keys/values, which can break apps or Windows. | high |
| `net-account-delete` | net user/localgroup /delete removes a user account or local group. | high |
| `sc-delete` | sc delete removes a Windows service. | high |
| `schtasks-delete` | schtasks /delete removes scheduled tasks. | medium |
| `wsl-unregister` | wsl --unregister irreversibly destroys a WSL distribution and its filesystem. | high |
| `robocopy-mirror` | robocopy /MIR deletes destination files that are not present in the source. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "windows.misc:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "windows.misc:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Windows PowerShell Cmdlets

**Pack ID:** `windows.powershell`

Protects against destructive PowerShell cmdlets: registry/provider deletes (`Remove-Item HKLM:\`, `Remove-ItemProperty`, `Remove-PSDrive`), account/task removal (`Remove-LocalUser`, `Unregister-ScheduledTask`), `Disable-ComputerRestore`, forced `Stop-Computer`/`Restart-Computer`, and `Remove-VM`/`Remove-AppxPackage`.

### Keywords

Commands containing these keywords are checked against this pack:

- `Remove-Item`
- `remove-item`
- `ri`
- `RI`
- `Remove-ItemProperty`
- `remove-itemproperty`
- `Clear-Item`
- `clear-item`
- `Remove-PSDrive`
- `remove-psdrive`
- `Remove-LocalUser`
- `remove-localuser`
- `Remove-LocalGroup`
- `remove-localgroup`
- `Unregister-ScheduledTask`
- `unregister-scheduledtask`
- `Disable-ComputerRestore`
- `disable-computerrestore`
- `Stop-Computer`
- `stop-computer`
- `Restart-Computer`
- `restart-computer`
- `Remove-VM`
- `remove-vm`
- `Remove-AppxPackage`
- `remove-appxpackage`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `ps-whatif` | `(?i)^\s*[^\|&;\r\n]*\s-whatif\b[^\|&;\r\n]*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `remove-item-provider` | Remove-Item against a registry/cert/WSMan provider path deletes that store entry. | high |
| `remove-itemproperty-or-clear` | Remove-ItemProperty / Clear-Item* deletes registry values or item contents. | high |
| `remove-psdrive` | Remove-PSDrive removes a PowerShell drive mapping. | medium |
| `remove-localuser-or-group` | Remove-LocalUser / Remove-LocalGroup deletes a local account or group. | high |
| `unregister-scheduledtask` | Unregister-ScheduledTask deletes a scheduled task. | medium |
| `disable-computerrestore` | Disable-ComputerRestore turns off System Restore and discards restore points. | high |
| `force-stop-or-restart-computer` | Stop-Computer/Restart-Computer -Force shuts down/reboots without saving work. | medium |
| `remove-vm-or-snapshot` | Remove-VM / Remove-VMSnapshot deletes a virtual machine or its checkpoints. | high |
| `remove-appxpackage` | Remove-AppxPackage uninstalls an app package (potentially for all users). | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "windows.powershell:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "windows.powershell:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

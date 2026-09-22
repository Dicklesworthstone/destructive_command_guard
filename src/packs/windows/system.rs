//! Windows disk & system-destruction pack.
//!
//! Covers the catastrophic Windows disk/system operations that are *not* plain
//! filesystem deletes (those live in `windows.filesystem`):
//!   - **Volume Shadow Copy destruction** — `vssadmin delete shadows`,
//!     `wmic shadowcopy delete`. This is the hallmark of ransomware and a common
//!     accidental data-loss vector: it destroys System Restore points and the
//!     shadow copies many backup tools rely on.
//!   - **Whole-volume / partition destruction** — `diskpart`, `Format-Volume`,
//!     `Clear-Disk`, `Remove-Partition`, `Initialize-Disk`, `Reset-PhysicalDisk`.
//!   - **Free-space wipe / boot config** — `cipher /w` (makes deleted files
//!     unrecoverable), `bcdedit /delete` (boot configuration).
//!
//! Design note: a *dedicated* `windows.system` pack is used rather than
//! extending the existing default-on-everywhere `system.disk` pack (mkfs/dd/
//! fdisk/…). That keeps these Windows-only verbs off the Unix default
//! quick-reject path (they would only ever match Windows-shaped commands) and
//! keeps all Windows packs togther with consistent `cfg(windows)` default
//! enablement. `format <drive>:` (cmd) stays in `windows.filesystem`; this pack
//! owns `Format-Volume` (PowerShell) and the lower-level disk verbs.
//!
//! All patterns are `(?i)` case-insensitive with stable rule ids
//! (e.g. `windows.system:vssadmin-delete-shadows`).

use crate::packs::{DestructivePattern, Pack, PatternSuggestion, SafePattern};
use crate::{destructive_pattern, safe_pattern};

const SHADOW_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "vssadmin list shadows",
        "List shadow copies (read-only) instead of deleting them",
    ),
    PatternSuggestion::new(
        "wbadmin start backup",
        "Take a fresh backup before touching shadow copies — deleting them removes a recovery path",
    ),
];

const DISK_SUGGESTIONS: &[PatternSuggestion] = &[
    PatternSuggestion::new(
        "Get-Disk / Get-Volume",
        "Confirm the exact disk/volume number before any clean/format — it is irreversible",
    ),
    PatternSuggestion::new(
        "diskpart -> list disk",
        "Inspect with `list disk`/`list volume` first; never `clean`/`delete` without confirming the target",
    ),
];

const WIPE_SUGGESTIONS: &[PatternSuggestion] = &[PatternSuggestion::new(
    "robocopy / backup first",
    "Free-space wipe and boot-config edits are irreversible — back up and confirm intent first",
)];

/// Create the Windows disk & system pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "windows.system".to_string(),
        name: "Windows Disk & System",
        description: "Protects against catastrophic Windows disk/system operations: \
                      `vssadmin delete shadows` / `wmic shadowcopy delete` (Volume Shadow Copy \
                      destruction), `wbadmin delete` (backup recovery points), `diskpart`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, \
                      `Initialize-Disk`, `Reset-PhysicalDisk`, `cipher /w`, and `bcdedit /delete`.",
        // Conventional keyword casings retained for readable metadata; the
        // quick-reject itself is ASCII case-insensitive. See packs::windows.
        keywords: &[
            "vssadmin",
            "VSSADMIN",
            "wmic",
            "WMIC",
            "shadowcopy",
            "ShadowCopy",
            "SHADOWCOPY",
            "diskpart",
            "DISKPART",
            "Format-Volume",
            "format-volume",
            "FORMAT-VOLUME",
            "Clear-Disk",
            "clear-disk",
            "CLEAR-DISK",
            "Remove-Partition",
            "remove-partition",
            "REMOVE-PARTITION",
            "Initialize-Disk",
            "initialize-disk",
            "INITIALIZE-DISK",
            "Reset-PhysicalDisk",
            "reset-physicaldisk",
            "RESET-PHYSICALDISK",
            "cipher",
            "CIPHER",
            "bcdedit",
            "BCDEDIT",
            "wbadmin",
            "WBADMIN",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

/// A storage cmdlet previewed with a bare `-WhatIf` switch; see
/// `create_safe_patterns`. Shared with the core.filesystem baseline so the two
/// packs cannot disagree about what a preview is.
pub(crate) const STORAGE_WHATIF_SAFE: &str = r#"(?i)^\s*(?:format-volume|clear-disk|remove-partition|initialize-disk|reset-physicaldisk)\b[^|&;\r\n'"`$@(){}]*\s-whatif(?:\s[^|&;\r\n'"`$@(){}]*)?$"#;

/// The `storage-whatif` safe pattern (see [`STORAGE_WHATIF_SAFE`]).
pub(crate) fn storage_whatif_safe_pattern() -> SafePattern {
    SafePattern {
        regex: crate::packs::regex_engine::LazyCompiledRegex::new(STORAGE_WHATIF_SAFE),
        name: "storage-whatif",
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // Read-only inspection of shadow copies / disks.
        safe_pattern!(
            "vssadmin-list",
            r"(?i)^\s*vssadmin(?:\.exe)?\s+list\b[^|&;\r\n]*$"
        ),
        safe_pattern!(
            "diskpart-list",
            r"(?i)^\s*diskpart(?:\.exe)?\s+(?:/s\s+\S+\s+)?list\b[^|&;\r\n]*$"
        ),
        // `-WhatIf` previews, but only on PowerShell storage cmdlets that
        // honor it. A stray `-WhatIf` must not whitelist cmd.exe tools such as
        // vssadmin, cipher, or bcdedit.
        //
        // Only the bare switch counts. `-WhatIf:$false` (or `:0`) turns the
        // preview OFF and the cmdlet really runs; `\b` used to accept it, so
        // `Remove-Partition ... -WhatIf:$false` was allowed. The whole command
        // may also not contain quotes, backticks, `$`, `@`, parentheses or
        // braces: ` -WhatIf` inside a quoted label or a `$( )` subexpression
        // is not a switch on the cmdlet. Anything doubtful stays denied.
        storage_whatif_safe_pattern(),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // === Volume Shadow Copy destruction (ransomware hallmark) ===
        destructive_pattern!(
            "vssadmin-delete-shadows",
            r"(?i)\bvssadmin(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?delete\s+shadows\b",
            "vssadmin delete shadows destroys Volume Shadow Copies (System Restore + backups).",
            Critical,
            "`vssadmin delete shadows` deletes the Volume Shadow Copies on a volume — the snapshots \
             that back System Restore, Previous Versions, and many backup tools. With `/all /quiet` \
             it removes every shadow copy with no prompt. This is one of the first things ransomware \
             does, and run by accident it silently removes the main local recovery path.\n\n\
             Safer alternatives:\n\
             - vssadmin list shadows: review what exists before deleting anything\n\
             - Take a fresh backup (wbadmin / your backup tool) instead of deleting recovery points",
            SHADOW_SUGGESTIONS
        ),
        // `wbadmin delete catalog|backup|systemstatebackup` removes Windows
        // Server Backup / system-image recovery points: the same inhibit-recovery
        // step as shadow deletion, and just as irreversible.
        destructive_pattern!(
            "wbadmin-delete",
            r"(?i)\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)\b",
            "wbadmin delete destroys Windows backup recovery points or the backup catalog.",
            Critical,
            "`wbadmin delete backup` / `delete systemstatebackup` removes Windows Server Backup and \
             system-image recovery points (with `-keepVersions:0`, all of them), and `wbadmin delete \
             catalog` erases the catalog that makes the remaining backups restorable. Like \
             `vssadmin delete shadows`, it is a standard ransomware step and an irreversible loss \
             of recovery.\n\n\
             Safer alternatives:\n\
             - wbadmin get versions: list the recovery points first\n\
             - Take a fresh backup before pruning old versions",
            SHADOW_SUGGESTIONS
        ),
        destructive_pattern!(
            "wmic-shadowcopy-delete",
            r"(?i)\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b",
            "wmic shadowcopy delete destroys Volume Shadow Copies.",
            Critical,
            "`wmic shadowcopy delete` is an alternate way to destroy Volume Shadow Copies (the same \
             snapshots that back System Restore and backups). Like `vssadmin delete shadows` it is a \
             common ransomware step and an irreversible loss of local recovery.\n\n\
             Safer alternatives:\n\
             - wmic shadowcopy list / vssadmin list shadows: inspect first\n\
             - Back up before removing any recovery points",
            SHADOW_SUGGESTIONS
        ),
        // === Whole-volume / partition destruction ===
        destructive_pattern!(
            "diskpart",
            r"(?i)\bdiskpart(?:\.exe)?\b(?=[^|&\r\n]*(?:/s\b|\bclean\b|\bdelete\b|\bformat\b))",
            "diskpart with clean/delete/format/script reconfigures or wipes disks and partitions.",
            High,
            "`diskpart` is the low-level disk-partitioning tool. Driven by a script (`/s file.txt`) or \
             with `clean`/`delete partition`/`delete volume`/`format`, it wipes partition tables and \
             volumes — a wrong disk number destroys the wrong drive irreversibly. A non-interactive \
             agent has no confirmation prompt.\n\n\
             Safer alternatives:\n\
             - diskpart -> `list disk` / `list volume`: confirm the exact target first\n\
             - Use Get-Disk/Get-Partition to inspect before any clean/delete",
            DISK_SUGGESTIONS
        ),
        destructive_pattern!(
            "format-volume",
            r"(?i)\bformat-volume\b",
            "Format-Volume erases a volume's filesystem and data.",
            Critical,
            "`Format-Volume` re-creates the filesystem on a volume, destroying all data on it. A wrong \
             drive letter or disk number formats the wrong volume. There is no Recycle Bin for a \
             format.\n\n\
             Safer alternatives:\n\
             - Get-Volume / Get-Partition: confirm the exact target first\n\
             - Back up the volume before any format",
            DISK_SUGGESTIONS
        ),
        destructive_pattern!(
            "clear-disk",
            r"(?i)\bclear-disk\b",
            "Clear-Disk removes all partitions and data from a disk.",
            Critical,
            "`Clear-Disk` wipes a whole physical disk — with `-RemoveData -RemoveOEM` it deletes every \
             partition (including recovery/OEM) and all data. A wrong disk number destroys the wrong \
             drive irreversibly.\n\n\
             Safer alternatives:\n\
             - Get-Disk: confirm the disk number and that it is the intended target\n\
             - Back up before clearing; consider removing a single partition instead",
            DISK_SUGGESTIONS
        ),
        destructive_pattern!(
            "remove-partition",
            r"(?i)\bremove-partition\b",
            "Remove-Partition deletes a partition and its data.",
            Critical,
            "`Remove-Partition` deletes a partition and everything on it. Targeting the wrong disk or \
             partition number destroys live data with no undo.\n\n\
             Safer alternatives:\n\
             - Get-Partition: confirm the disk/partition numbers first\n\
             - Back up the partition's data before removing it",
            DISK_SUGGESTIONS
        ),
        destructive_pattern!(
            "initialize-or-reset-disk",
            r"(?i)\b(?:initialize-disk|reset-physicaldisk)\b",
            "Initialize-Disk / Reset-PhysicalDisk wipe disk metadata and data.",
            High,
            "`Initialize-Disk` re-initializes a disk's partition style and `Reset-PhysicalDisk` resets \
             a physical disk — both discard existing partitioning/data on the target. On a disk that \
             already holds data this is destructive and easy to point at the wrong disk.\n\n\
             Safer alternatives:\n\
             - Get-Disk: confirm the disk is empty / the intended target first\n\
             - Back up before initializing or resetting",
            DISK_SUGGESTIONS
        ),
        // === Free-space wipe / boot config ===
        destructive_pattern!(
            "cipher-wipe",
            r"(?i)\bcipher(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/w",
            "cipher /w overwrites free space, making deleted files unrecoverable.",
            High,
            "`cipher /w:<path>` overwrites all free space on the volume, permanently destroying the \
             recoverability of any previously deleted files. It is slow, irreversible, and usually run \
             by mistake when a simple delete was intended.\n\n\
             Safer alternatives:\n\
             - If you only need to remove a file, delete it normally\n\
             - Reserve free-space wiping for decommissioning, after backups are confirmed",
            WIPE_SUGGESTIONS
        ),
        destructive_pattern!(
            "bcdedit-delete",
            r"(?i)\bbcdedit(?:\.exe)?\s+(?:[^|&\r\n]*\s+)?/delete",
            "bcdedit /delete removes a boot configuration entry.",
            High,
            "`bcdedit /delete` (and `/deletevalue`) removes Boot Configuration Data entries. A wrong \
             entry can leave the machine unbootable. Boot config should be changed deliberately, not \
             as part of a cleanup.\n\n\
             Safer alternatives:\n\
             - bcdedit /enum: review the current boot entries first\n\
             - Export with `bcdedit /export` before modifying anything",
            WIPE_SUGGESTIONS
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Severity;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "windows.system");
        assert!(pack.keywords.contains(&"vssadmin"));
        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn keyword_gate_admits_uppercase_cmdlets() {
        let pack = create_pack();
        for cmd in [
            "REMOVE-PARTITION -DiskNumber 0 -PartitionNumber 2",
            "INITIALIZE-DISK -Number 0",
            "RESET-PHYSICALDISK -FriendlyName Disk1",
            "FORMAT-VOLUME -DriveLetter D",
            "CLEAR-DISK -Number 1 -RemoveData",
            "wmic SHADOWCOPY delete",
        ] {
            assert!(pack.might_match(cmd), "keyword gate should admit: {cmd}");
        }
    }

    #[test]
    fn blocks_shadow_copy_destruction() {
        let pack = create_pack();
        let checks = [
            (
                "vssadmin delete shadows /all /quiet",
                "vssadmin-delete-shadows",
            ),
            (
                "vssadmin delete shadows /for=C: /oldest",
                "vssadmin-delete-shadows",
            ),
            ("VSSADMIN DELETE SHADOWS /ALL", "vssadmin-delete-shadows"),
            ("wmic shadowcopy delete", "wmic-shadowcopy-delete"),
            ("wbadmin delete catalog -quiet", "wbadmin-delete"),
            (
                "wbadmin delete systemstatebackup -keepVersions:0",
                "wbadmin-delete",
            ),
            (
                "WBADMIN.EXE DELETE BACKUP -keepVersions:0 -quiet",
                "wbadmin-delete",
            ),
        ];
        for (command, expected) in checks {
            assert_blocks_with_pattern(&pack, command, expected);
            assert_blocks_with_severity(&pack, command, Severity::Critical);
        }
    }

    #[test]
    fn blocks_disk_and_partition_destruction() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "diskpart /s wipe.txt", "diskpart");
        assert_blocks_with_pattern(&pack, "Format-Volume -DriveLetter D", "format-volume");
        assert_blocks_with_pattern(&pack, "Clear-Disk -Number 1 -RemoveData", "clear-disk");
        assert_blocks_with_pattern(
            &pack,
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2",
            "remove-partition",
        );
        assert_blocks_with_pattern(
            &pack,
            "Initialize-Disk -Number 2",
            "initialize-or-reset-disk",
        );
        assert_blocks_with_pattern(
            &pack,
            "Reset-PhysicalDisk -FriendlyName Disk1",
            "initialize-or-reset-disk",
        );
    }

    #[test]
    fn blocks_wipe_and_bootconfig() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "cipher /w:C:\\", "cipher-wipe");
        assert_blocks_with_pattern(&pack, "cipher /w:C:\\ -WhatIf", "cipher-wipe");
        assert_blocks_with_pattern(&pack, "bcdedit /delete {current}", "bcdedit-delete");
        assert_blocks_with_pattern(&pack, "bcdedit /delete {current} -WhatIf", "bcdedit-delete");
        assert_blocks_with_pattern(
            &pack,
            "vssadmin delete shadows /all /quiet -WhatIf",
            "vssadmin-delete-shadows",
        );
    }

    #[test]
    fn allows_read_only_and_whatif() {
        let pack = create_pack();
        let allowed = [
            "vssadmin list shadows",
            "VSSADMIN LIST SHADOWS",
            "diskpart /s list.txt list disk",
            "Format-Volume -DriveLetter D -WhatIf",
            "Clear-Disk -Number 1 -RemoveData -WhatIf",
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2 -WhatIf",
            "Initialize-Disk -Number 2 -WhatIf",
            "Reset-PhysicalDisk -FriendlyName Disk1 -WhatIf",
            "bcdedit /enum",
            "wbadmin get versions",
            "wbadmin start backup -backupTarget:E: -include:C: -quiet",
            // bare diskpart with no destructive verb on the line is not flagged here
            "diskpart",
        ];
        for command in allowed {
            assert_allows(&pack, command);
        }
    }

    /// `-WhatIf:$false` disables the preview, so the cmdlet really runs; the
    /// carve-out used to accept it through `\b`. A ` -WhatIf` that is not a
    /// switch on the cmdlet (inside a quoted argument or a subexpression) and
    /// a longer parameter name must not count either.
    #[test]
    fn whatif_carve_out_accepts_only_the_bare_switch() {
        let pack = create_pack();
        for command in [
            "Format-Volume -DriveLetter D -WhatIf:$false",
            "Format-Volume -DriveLetter D -WhatIf:$False -Confirm:$false",
            "Clear-Disk -Number 1 -RemoveData -WhatIf:$false",
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2 -WhatIf:0",
            "Initialize-Disk -Number 2 -WhatIf:$false",
            "Reset-PhysicalDisk -FriendlyName Disk1 -WhatIf:$false",
            "Format-Volume -DriveLetter D -NewFileSystemLabel ' -WhatIf'",
            "Format-Volume -DriveLetter D -NewFileSystemLabel \" -WhatIf\"",
            "Remove-Partition -DiskNumber $(Get-Disk -WhatIf) -PartitionNumber 2",
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2 -WhatIfx",
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2 `\n-WhatIf",
        ] {
            assert!(pack.check(command).is_some(), "must stay denied: {command}");
        }
        assert_allows(
            &pack,
            "Remove-Partition -DiskNumber 1 -PartitionNumber 2 -WhatIf -Confirm",
        );
    }
}

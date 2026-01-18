//! `Velero` pack - protections for destructive Kubernetes backup operations.
//!
//! Covers destructive CLI operations:
//! - Backup, restore, and schedule deletion
//! - Location deletion
//! - Uninstall

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the `Velero` pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "backup.velero".to_string(),
        name: "Velero",
        description: "Protects against destructive velero operations like deleting backups, schedules, and locations.",
        keywords: &["velero"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!(
            "velero-backup-get",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+backup\s+get\b"
        ),
        safe_pattern!(
            "velero-backup-describe",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+backup\s+describe\b"
        ),
        safe_pattern!(
            "velero-backup-logs",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+backup\s+logs\b"
        ),
        safe_pattern!(
            "velero-backup-create",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+backup\s+create\b"
        ),
        safe_pattern!(
            "velero-schedule-get",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+schedule\s+get\b"
        ),
        safe_pattern!(
            "velero-restore-create",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+restore\s+create\b"
        ),
        safe_pattern!(
            "velero-version",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+version\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "velero-backup-delete",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+backup\s+delete\b",
            "velero backup delete removes a backup and its data.",
            High,
            "Deleting a Velero backup removes both the backup metadata in Kubernetes and the \
             actual backup data from object storage. Once deleted, you cannot restore your \
             cluster or applications to that backup point. This is irreversible.\n\n\
             Safer alternatives:\n\
             - velero backup describe: Review backup contents before deletion\n\
             - velero backup get: List all backups to verify target\n\
             - Consider retaining backups with TTL policies instead of manual deletion"
        ),
        destructive_pattern!(
            "velero-schedule-delete",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+schedule\s+delete\b",
            "velero schedule delete removes scheduled backups.",
            Medium,
            "Deleting a backup schedule stops automatic backup creation. Existing backups \
             created by the schedule are not affected, but no new backups will be created. \
             If forgotten, this can lead to outdated backups and recovery gaps.\n\n\
             Safer alternatives:\n\
             - velero schedule get: Review all schedules first\n\
             - velero schedule describe: Check schedule configuration\n\
             - Pause the schedule instead if temporary"
        ),
        destructive_pattern!(
            "velero-restore-delete",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+restore\s+delete\b",
            "velero restore delete removes restore records.",
            Low,
            "Deleting restore records removes the metadata about past restore operations from \
             Kubernetes. This does not affect the restored resources themselves or the original \
             backups. However, audit trails of restore operations will be lost.\n\n\
             Safer alternatives:\n\
             - velero restore get: List restores before deletion\n\
             - Document restore history externally if needed for compliance"
        ),
        destructive_pattern!(
            "velero-backup-location-delete",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+backup-location\s+delete\b",
            "velero backup-location delete removes a backup storage location.",
            High,
            "Removing a backup storage location disconnects Velero from that storage backend. \
             Backups stored there become inaccessible to Velero (though data remains in storage). \
             You won't be able to restore from those backups until the location is recreated.\n\n\
             Safer alternatives:\n\
             - velero backup-location get: Review all locations\n\
             - Verify no critical backups depend on this location\n\
             - Migrate backups to another location before deletion"
        ),
        destructive_pattern!(
            "velero-snapshot-location-delete",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+snapshot-location\s+delete\b",
            "velero snapshot-location delete removes a snapshot location.",
            High,
            "Deleting a snapshot location removes the configuration for volume snapshots. \
             Existing snapshots may become orphaned and inaccessible through Velero. Volume \
             restores that depend on this location will fail.\n\n\
             Safer alternatives:\n\
             - velero snapshot-location get: Review all snapshot locations\n\
             - Verify no backups use this snapshot location\n\
             - Migrate to a new snapshot location before deletion"
        ),
        destructive_pattern!(
            "velero-uninstall",
            r"velero(?:\s+--?\S+(?:\s+\S+)?)*\s+uninstall\b",
            "velero uninstall removes the Velero deployment and related resources.",
            Critical,
            "Uninstalling Velero removes the deployment, CRDs, and all Velero-managed resources \
             from your cluster. Backup schedules stop immediately. While backup data in object \
             storage is preserved, you cannot restore from backups until Velero is reinstalled \
             and reconfigured.\n\n\
             Safer alternatives:\n\
             - Document current configuration before uninstalling\n\
             - velero backup-location get: Record storage locations\n\
             - velero schedule get: Record all schedules\n\
             - Export Velero resources: kubectl get -o yaml"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn test_pack_creation() {
        let pack = create_pack();
        assert_eq!(pack.id, "backup.velero");
        assert_eq!(pack.name, "Velero");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"velero"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        assert_safe_pattern_matches(&pack, "velero backup get");
        assert_safe_pattern_matches(&pack, "velero backup describe nightly");
        assert_safe_pattern_matches(&pack, "velero backup logs nightly");
        assert_safe_pattern_matches(&pack, "velero backup create nightly");
        assert_safe_pattern_matches(&pack, "velero schedule get");
        assert_safe_pattern_matches(&pack, "velero restore create restore-1");
        assert_safe_pattern_matches(&pack, "velero version");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "velero backup delete nightly",
            "velero-backup-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "velero schedule delete nightly",
            "velero-schedule-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "velero restore delete restore-1",
            "velero-restore-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "velero backup-location delete default",
            "velero-backup-location-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "velero snapshot-location delete default",
            "velero-snapshot-location-delete",
        );
        assert_blocks_with_pattern(&pack, "velero uninstall", "velero-uninstall");
    }
}

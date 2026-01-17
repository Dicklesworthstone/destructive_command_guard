//! Azure Blob Storage pack - protections for destructive Azure storage operations.
//!
//! Covers destructive operations:
//! - Container deletion (az storage container delete)
//! - Blob deletion (az storage blob delete, delete-batch)
//! - Storage account deletion
//! - azcopy remove and sync --delete-destination

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Azure Blob Storage pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "storage.azure_blob".to_string(),
        name: "Azure Blob Storage",
        description: "Protects against destructive Azure Blob Storage operations like container \
                      deletion, blob deletion, and azcopy remove.",
        keywords: &["az storage", "azcopy"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // az storage container operations (read-only)
        safe_pattern!(
            "az-storage-container-list",
            r"\baz\s+storage\s+container\s+list\b"
        ),
        safe_pattern!(
            "az-storage-container-show",
            r"\baz\s+storage\s+container\s+show\b"
        ),
        safe_pattern!(
            "az-storage-container-exists",
            r"\baz\s+storage\s+container\s+exists\b"
        ),
        // az storage blob operations (read-only)
        safe_pattern!("az-storage-blob-list", r"\baz\s+storage\s+blob\s+list\b"),
        safe_pattern!("az-storage-blob-show", r"\baz\s+storage\s+blob\s+show\b"),
        safe_pattern!(
            "az-storage-blob-exists",
            r"\baz\s+storage\s+blob\s+exists\b"
        ),
        safe_pattern!(
            "az-storage-blob-download",
            r"\baz\s+storage\s+blob\s+download\b"
        ),
        safe_pattern!(
            "az-storage-blob-download-batch",
            r"\baz\s+storage\s+blob\s+download-batch\b"
        ),
        safe_pattern!("az-storage-blob-url", r"\baz\s+storage\s+blob\s+url\b"),
        safe_pattern!(
            "az-storage-blob-metadata-show",
            r"\baz\s+storage\s+blob\s+metadata\s+show\b"
        ),
        // az storage account operations (read-only)
        safe_pattern!(
            "az-storage-account-list",
            r"\baz\s+storage\s+account\s+list\b"
        ),
        safe_pattern!(
            "az-storage-account-show",
            r"\baz\s+storage\s+account\s+show\b"
        ),
        safe_pattern!(
            "az-storage-account-keys-list",
            r"\baz\s+storage\s+account\s+keys\s+list\b"
        ),
        // azcopy operations (read-only)
        safe_pattern!("azcopy-list", r"\bazcopy\s+(?:--\S+\s+)*list\b"),
        safe_pattern!("azcopy-copy", r"\bazcopy\s+(?:--\S+\s+)*copy\b"),
        safe_pattern!("azcopy-jobs-list", r"\bazcopy\s+(?:--\S+\s+)*jobs\s+list\b"),
        safe_pattern!("azcopy-jobs-show", r"\bazcopy\s+(?:--\S+\s+)*jobs\s+show\b"),
        safe_pattern!("azcopy-login", r"\bazcopy\s+(?:--\S+\s+)*login\b"),
        safe_pattern!("azcopy-env", r"\bazcopy\s+(?:--\S+\s+)*env\b"),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // Container deletion
        destructive_pattern!(
            "az-storage-container-delete",
            r"\baz\s+storage\s+container\s+delete\b",
            "az storage container delete removes an Azure storage container."
        ),
        // Blob deletion (order matters: delete-batch before delete)
        destructive_pattern!(
            "az-storage-blob-delete-batch",
            r"\baz\s+storage\s+blob\s+delete-batch\b",
            "az storage blob delete-batch removes multiple blobs from Azure storage."
        ),
        destructive_pattern!(
            "az-storage-blob-delete",
            r"\baz\s+storage\s+blob\s+delete(?:\s|$)",
            "az storage blob delete removes a blob from Azure storage."
        ),
        // Storage account deletion
        destructive_pattern!(
            "az-storage-account-delete",
            r"\baz\s+storage\s+account\s+delete\b",
            "az storage account delete removes an entire Azure storage account."
        ),
        // azcopy remove
        destructive_pattern!(
            "azcopy-remove",
            r"\bazcopy\s+(?:--\S+\s+)*remove\b",
            "azcopy remove deletes files from Azure storage."
        ),
        // azcopy sync with delete
        destructive_pattern!(
            "azcopy-sync-delete",
            r"\bazcopy\s+(?:--\S+\s+)*sync\b.*--delete-destination\b",
            "azcopy sync --delete-destination removes destination files not in source."
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
        assert_eq!(pack.id, "storage.azure_blob");
        assert_eq!(pack.name, "Azure Blob Storage");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"az storage"));
        assert!(pack.keywords.contains(&"azcopy"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn allows_safe_commands() {
        let pack = create_pack();
        // Container operations
        assert_safe_pattern_matches(&pack, "az storage container list --account-name myaccount");
        assert_safe_pattern_matches(&pack, "az storage container show -n mycontainer");
        assert_safe_pattern_matches(&pack, "az storage container exists -n mycontainer");
        // Blob operations
        assert_safe_pattern_matches(&pack, "az storage blob list -c mycontainer");
        assert_safe_pattern_matches(&pack, "az storage blob show -c mycontainer -n myblob");
        assert_safe_pattern_matches(&pack, "az storage blob exists -c mycontainer -n myblob");
        assert_safe_pattern_matches(
            &pack,
            "az storage blob download -c mycontainer -n myblob -f local.txt",
        );
        assert_safe_pattern_matches(
            &pack,
            "az storage blob download-batch -d ./local -s mycontainer",
        );
        assert_safe_pattern_matches(&pack, "az storage blob url -c mycontainer -n myblob");
        assert_safe_pattern_matches(
            &pack,
            "az storage blob metadata show -c mycontainer -n myblob",
        );
        // Account operations
        assert_safe_pattern_matches(&pack, "az storage account list");
        assert_safe_pattern_matches(&pack, "az storage account show -n myaccount");
        assert_safe_pattern_matches(&pack, "az storage account keys list -n myaccount");
        // azcopy operations
        assert_safe_pattern_matches(&pack, "azcopy list https://account.blob.core.windows.net/");
        assert_safe_pattern_matches(
            &pack,
            "azcopy copy ./local https://account.blob.core.windows.net/container",
        );
        assert_safe_pattern_matches(&pack, "azcopy jobs list");
        assert_safe_pattern_matches(&pack, "azcopy jobs show jobid");
        assert_safe_pattern_matches(&pack, "azcopy login");
        assert_safe_pattern_matches(&pack, "azcopy env");
    }

    #[test]
    fn blocks_destructive_commands() {
        let pack = create_pack();
        // Container deletion
        assert_blocks_with_pattern(
            &pack,
            "az storage container delete -n mycontainer",
            "az-storage-container-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az storage container delete --name mycontainer --account-name myaccount",
            "az-storage-container-delete",
        );
        // Blob deletion
        assert_blocks_with_pattern(
            &pack,
            "az storage blob delete -c mycontainer -n myblob",
            "az-storage-blob-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az storage blob delete-batch -s mycontainer",
            "az-storage-blob-delete-batch",
        );
        assert_blocks_with_pattern(
            &pack,
            "az storage blob delete-batch --source mycontainer --pattern '*.log'",
            "az-storage-blob-delete-batch",
        );
        // Account deletion
        assert_blocks_with_pattern(
            &pack,
            "az storage account delete -n myaccount",
            "az-storage-account-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "az storage account delete --name myaccount --yes",
            "az-storage-account-delete",
        );
        // azcopy remove
        assert_blocks_with_pattern(
            &pack,
            "azcopy remove https://account.blob.core.windows.net/container/blob",
            "azcopy-remove",
        );
        assert_blocks_with_pattern(
            &pack,
            "azcopy remove --recursive https://account.blob.core.windows.net/container",
            "azcopy-remove",
        );
        // azcopy sync with delete
        assert_blocks_with_pattern(
            &pack,
            "azcopy sync ./local https://account.blob.core.windows.net/container --delete-destination true",
            "azcopy-sync-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "azcopy sync --delete-destination=true ./src https://dest.blob.core.windows.net/",
            "azcopy-sync-delete",
        );
    }
}

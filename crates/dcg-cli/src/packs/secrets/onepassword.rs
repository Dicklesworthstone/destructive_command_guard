//! `1Password` CLI pack - protections for destructive `op` operations.
//!
//! Blocks delete/archive commands that remove secrets, users, groups, or vaults.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the 1Password pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "secrets.onepassword".to_string(),
        name: "1Password CLI",
        description: "Protects against destructive 1Password CLI operations like deleting items, \
                      documents, users, groups, and vaults.",
        keywords: &["op"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
        default_effects: crate::packs::DEFAULT_PACK_EFFECTS,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("op-whoami", r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s|$)"),
        safe_pattern!(
            "op-account-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+account\s+get(?=\s|$)"
        ),
        safe_pattern!("op-read", r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+read(?=\s|$)"),
        safe_pattern!(
            "op-item-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "op-item-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "op-document-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+document\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "op-vault-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "op-vault-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+get(?=\s|$)"
        ),
        safe_pattern!(
            "op-user-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+list(?=\s|$)"
        ),
        safe_pattern!(
            "op-group-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+group\s+list(?=\s|$)"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "op-item-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+delete\b",
            "op item delete removes secret items (including archive operations).",
            High,
            "Deleting a 1Password item permanently removes the secret (passwords, API keys, \
             credentials). Without --archive, this cannot be undone. Applications and users \
             relying on this item will lose access to the stored credentials.\n\n\
             Safer alternatives:\n\
             - op item get: Export item fields before deletion\n\
             - op item delete --archive: Move to archive for recovery\n\
             - Verify no applications reference this item"
        ),
        destructive_pattern!(
            "op-document-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+document\s+delete\b",
            "op document delete removes secure documents (including archive operations).",
            High,
            "Deleting a 1Password document permanently removes the file (certificates, keys, \
             configurations). Unlike items, documents may contain unique binary data that \
             cannot be recreated from memory.\n\n\
             Safer alternatives:\n\
             - op document get: Download document before deletion\n\
             - op document delete --archive: Move to archive for recovery\n\
             - Back up to secure local storage first"
        ),
        destructive_pattern!(
            "op-vault-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+delete\b",
            "op vault delete removes an entire vault.",
            Critical,
            "Deleting a vault removes all items, documents, and permissions within it. This \
             affects all users with vault access and any applications using items from this \
             vault. This action cannot be undone.\n\n\
             Safer alternatives:\n\
             - op item list --vault=X: Inventory vault contents\n\
             - Export items and documents before deletion\n\
             - Move items to a different vault instead"
        ),
        destructive_pattern!(
            "op-user-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+delete\b",
            "op user delete removes a user from 1Password.",
            High,
            "Deleting a user revokes their access to all vaults and items. Any private vaults \
             owned by the user may be transferred or lost. Service accounts and integrations \
             created by this user may also be affected.\n\n\
             Safer alternatives:\n\
             - op user suspend: Suspend instead of delete for recovery\n\
             - op user get: Document user permissions first\n\
             - Transfer vault ownership before deletion"
        ),
        destructive_pattern!(
            "op-group-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+group\s+delete\b",
            "op group delete removes a group.",
            Medium,
            "Deleting a group removes the permission boundary and all vault assignments. \
             Members lose access to vaults shared through this group. This affects team \
             organization and access control policies.\n\n\
             Safer alternatives:\n\
             - op group list: Review group membership first\n\
             - Reassign vault permissions to individual users\n\
             - Create replacement group before deleting old one"
        ),
        destructive_pattern!(
            "op-connect-token-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+connect\s+token\s+delete\b",
            "op connect token delete revokes access tokens.",
            High,
            "Deleting a Connect token immediately revokes API access for integrations using \
             it. CI/CD pipelines, deployment scripts, and applications fetching secrets will \
             fail to authenticate until a new token is configured.\n\n\
             Safer alternatives:\n\
             - op connect token list: Document token usage first\n\
             - Create new token before deleting old one\n\
             - Update integrations with new token prior to deletion"
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
        assert_eq!(pack.id, "secrets.onepassword");
        assert_eq!(pack.name, "1Password CLI");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"op"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_item_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "op item delete \"Database Password\"",
            "op-item-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "op item delete --archive \"Legacy Token\"",
            "op-item-delete",
        );
    }

    #[test]
    fn test_document_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "op document delete \"Prod Cert\"",
            "op-document-delete",
        );
        assert_blocks_with_pattern(
            &pack,
            "op document delete --archive \"Old Cert\"",
            "op-document-delete",
        );
    }

    #[test]
    fn test_vault_group_user_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "op vault delete \"Engineering\"", "op-vault-delete");
        assert_blocks_with_pattern(&pack, "op group delete \"Contractors\"", "op-group-delete");
        assert_blocks_with_pattern(
            &pack,
            "op user delete \"user@example.com\"",
            "op-user-delete",
        );
    }

    #[test]
    fn test_connect_token_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "op connect token delete abc123",
            "op-connect-token-delete",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "op whoami");
        assert_allows(&pack, "op account get");
        assert_allows(&pack, "op read op://vault/item/field");
        assert_allows(&pack, "op item get \"Database Password\"");
        assert_allows(&pack, "op item list");
        assert_allows(&pack, "op document get \"Prod Cert\"");
        assert_allows(&pack, "op vault list");
        assert_allows(&pack, "op vault get Engineering");
        assert_allows(&pack, "op user list");
        assert_allows(&pack, "op group list");
    }
}

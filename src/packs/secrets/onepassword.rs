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
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("op-whoami", r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami\b"),
        safe_pattern!(
            "op-account-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+account\s+get\b"
        ),
        safe_pattern!("op-read", r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+read\b"),
        safe_pattern!("op-item-get", r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+get\b"),
        safe_pattern!(
            "op-item-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+list\b"
        ),
        safe_pattern!(
            "op-document-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+document\s+get\b"
        ),
        safe_pattern!(
            "op-vault-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+list\b"
        ),
        safe_pattern!(
            "op-vault-get",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+get\b"
        ),
        safe_pattern!(
            "op-user-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+list\b"
        ),
        safe_pattern!(
            "op-group-list",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+group\s+list\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "op-item-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+delete\b",
            "op item delete removes secret items (including archive operations)."
        ),
        destructive_pattern!(
            "op-document-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+document\s+delete\b",
            "op document delete removes secure documents (including archive operations)."
        ),
        destructive_pattern!(
            "op-vault-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+delete\b",
            "op vault delete removes an entire vault."
        ),
        destructive_pattern!(
            "op-user-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+delete\b",
            "op user delete removes a user from 1Password."
        ),
        destructive_pattern!(
            "op-group-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+group\s+delete\b",
            "op group delete removes a group."
        ),
        destructive_pattern!(
            "op-connect-token-delete",
            r"op(?:\s+--?\S+(?:\s+\S+)?)*\s+connect\s+token\s+delete\b",
            "op connect token delete revokes access tokens."
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

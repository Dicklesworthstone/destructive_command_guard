//! `HashiCorp` Vault CLI pack - protections for destructive Vault operations.
//!
//! This pack blocks commands that delete secrets, disable auth/secret engines,
//! revoke leases/tokens, or remove policies.

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the Vault secrets pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "secrets.vault".to_string(),
        name: "HashiCorp Vault",
        description: "Protects against destructive Vault CLI operations like deleting secrets, \
                      disabling auth/secret engines, revoking leases/tokens, and deleting policies.",
        keywords: &["vault"],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        safe_pattern!("vault-status", r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+status\b"),
        safe_pattern!(
            "vault-version",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+version\b"
        ),
        safe_pattern!("vault-read", r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+read\b"),
        safe_pattern!(
            "vault-kv-get",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+get\b"
        ),
        safe_pattern!(
            "vault-kv-list",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+list\b"
        ),
        safe_pattern!(
            "vault-secrets-list",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+list\b"
        ),
        safe_pattern!(
            "vault-policy-list",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+list\b"
        ),
        safe_pattern!(
            "vault-token-lookup",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+lookup\b"
        ),
        safe_pattern!(
            "vault-auth-list",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+auth\s+list\b"
        ),
        safe_pattern!(
            "vault-audit-list",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+audit\s+list\b"
        ),
        safe_pattern!(
            "vault-lease-lookup",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+lease\s+lookup\b"
        ),
    ]
}

fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        destructive_pattern!(
            "vault-secrets-disable",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+disable\b",
            "vault secrets disable disables a secrets engine, causing data loss."
        ),
        destructive_pattern!(
            "vault-kv-destroy",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+destroy\b",
            "vault kv destroy permanently deletes secret versions."
        ),
        destructive_pattern!(
            "vault-kv-metadata-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+metadata\s+delete\b",
            "vault kv metadata delete removes all versions and metadata for a secret."
        ),
        destructive_pattern!(
            "vault-kv-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+delete\b",
            "vault kv delete removes the latest secret version."
        ),
        destructive_pattern!(
            "vault-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "vault delete removes secrets at a path."
        ),
        destructive_pattern!(
            "vault-policy-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+delete\b",
            "vault policy delete removes access policies."
        ),
        destructive_pattern!(
            "vault-auth-disable",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+auth\s+disable\b",
            "vault auth disable disables an auth method."
        ),
        destructive_pattern!(
            "vault-token-revoke",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+revoke\b",
            "vault token revoke invalidates tokens and can disrupt access."
        ),
        destructive_pattern!(
            "vault-lease-revoke",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+lease\s+revoke\b",
            "vault lease revoke invalidates leases and can disrupt access."
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
        assert_eq!(pack.id, "secrets.vault");
        assert_eq!(pack.name, "HashiCorp Vault");
        assert!(!pack.description.is_empty());
        assert!(pack.keywords.contains(&"vault"));

        assert_patterns_compile(&pack);
        assert_all_patterns_have_reasons(&pack);
        assert_unique_pattern_names(&pack);
    }

    #[test]
    fn test_secrets_disable_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "vault secrets disable secret/",
            "vault-secrets-disable",
        );
        assert_blocks(
            &pack,
            "vault --namespace admin secrets disable kv/",
            "disables a secrets engine",
        );
    }

    #[test]
    fn test_kv_destroy_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "vault kv destroy -versions=1-3 secret/myapp/config",
            "vault-kv-destroy",
        );
    }

    #[test]
    fn test_kv_metadata_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "vault kv metadata delete secret/myapp/config",
            "vault-kv-metadata-delete",
        );
    }

    #[test]
    fn test_kv_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "vault kv delete secret/myapp/config",
            "vault-kv-delete",
        );
    }

    #[test]
    fn test_generic_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "vault delete secret/myapp/config", "vault-delete");
    }

    #[test]
    fn test_policy_delete_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "vault policy delete myapp-policy",
            "vault-policy-delete",
        );
    }

    #[test]
    fn test_auth_disable_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "vault auth disable github", "vault-auth-disable");
    }

    #[test]
    fn test_token_revoke_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(&pack, "vault token revoke abc123", "vault-token-revoke");
    }

    #[test]
    fn test_lease_revoke_blocked() {
        let pack = create_pack();
        assert_blocks_with_pattern(
            &pack,
            "vault lease revoke -prefix secret/",
            "vault-lease-revoke",
        );
    }

    #[test]
    fn test_safe_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "vault status");
        assert_allows(&pack, "vault version");
        assert_allows(&pack, "vault read secret/myapp/config");
        assert_allows(&pack, "vault kv get secret/myapp/config");
        assert_allows(&pack, "vault kv list secret/");
        assert_allows(&pack, "vault secrets list");
        assert_allows(&pack, "vault policy list");
        assert_allows(&pack, "vault token lookup");
        assert_allows(&pack, "vault auth list");
        assert_allows(&pack, "vault audit list");
        assert_allows(&pack, "vault lease lookup lease_id");
    }

    #[test]
    fn test_safe_with_global_flags() {
        let pack = create_pack();
        assert_allows(&pack, "vault -namespace=admin status");
        assert_allows(&pack, "vault --namespace admin policy list");
    }
}

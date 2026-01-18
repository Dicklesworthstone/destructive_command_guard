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
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
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
            "vault secrets disable disables a secrets engine, causing data loss.",
            Critical,
            "Disabling a secrets engine permanently deletes ALL secrets stored in that \
             engine. Dynamic credentials are revoked immediately. Applications using \
             secrets from this engine will fail authentication. This cannot be undone.\n\n\
             Safer alternatives:\n\
             - vault secrets list: Review enabled engines first\n\
             - Export secrets before disabling\n\
             - Rotate applications to new secrets engine first"
        ),
        destructive_pattern!(
            "vault-kv-destroy",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+destroy\b",
            "vault kv destroy permanently deletes secret versions.",
            Critical,
            "Destroy permanently erases secret data including all specified versions. \
             Unlike delete (which is soft-delete in KV v2), destroy is irreversible. \
             The data cannot be recovered even by Vault administrators.\n\n\
             Safer alternatives:\n\
             - vault kv delete: Soft-delete with undelete option\n\
             - vault kv get: Verify the secret versions first\n\
             - Export secret data before destruction"
        ),
        destructive_pattern!(
            "vault-kv-metadata-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+metadata\s+delete\b",
            "vault kv metadata delete removes all versions and metadata for a secret.",
            Critical,
            "Deleting metadata removes ALL versions of a secret and its metadata \
             permanently. This is more destructive than destroy as it removes the \
             entire secret history. The secret path becomes available for reuse.\n\n\
             Safer alternatives:\n\
             - vault kv metadata get: Review secret metadata first\n\
             - vault kv destroy: Delete specific versions only\n\
             - Export all secret versions before deletion"
        ),
        destructive_pattern!(
            "vault-kv-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+delete\b",
            "vault kv delete removes the latest secret version.",
            High,
            "In KV v2, delete performs a soft-delete of the latest version. The data \
             can be recovered with undelete until the delete_version_after policy \
             expires. In KV v1, delete is permanent and immediate.\n\n\
             Safer alternatives:\n\
             - vault kv get: Verify the secret before deleting\n\
             - vault kv undelete: Recover if mistakenly deleted (v2)\n\
             - Set appropriate delete_version_after policies"
        ),
        destructive_pattern!(
            "vault-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+delete\b",
            "vault delete removes secrets at a path.",
            High,
            "The generic delete command removes data at the specified path. The \
             behavior depends on the secrets engine. For most engines, this is \
             a permanent deletion of the secret data.\n\n\
             Safer alternatives:\n\
             - vault read: Verify the path contents first\n\
             - Use engine-specific commands for safer operations\n\
             - Back up data before deletion"
        ),
        destructive_pattern!(
            "vault-policy-delete",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+delete\b",
            "vault policy delete removes access policies.",
            Critical,
            "Deleting a policy immediately affects all tokens with that policy. Users \
             and applications may lose access to secrets they need. Orphaned tokens \
             retain their policy name but lose the permissions.\n\n\
             Safer alternatives:\n\
             - vault policy read: Review policy before deletion\n\
             - vault token lookup: Check affected tokens\n\
             - Create replacement policy before deleting"
        ),
        destructive_pattern!(
            "vault-auth-disable",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+auth\s+disable\b",
            "vault auth disable disables an auth method.",
            Critical,
            "Disabling an auth method revokes ALL tokens issued by that method and \
             removes all configuration. Users authenticating via this method will \
             immediately lose access. This includes all associated roles and policies.\n\n\
             Safer alternatives:\n\
             - vault auth list: Review auth methods first\n\
             - Migrate users to another auth method\n\
             - Export auth configuration before disabling"
        ),
        destructive_pattern!(
            "vault-token-revoke",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+revoke\b",
            "vault token revoke invalidates tokens and can disrupt access.",
            High,
            "Revoking a token immediately invalidates it and all child tokens. \
             Applications using this token will fail authentication on next request. \
             With -prefix, all tokens under a prefix tree are revoked.\n\n\
             Safer alternatives:\n\
             - vault token lookup: Verify the token before revoking\n\
             - Use token TTLs for automatic expiration\n\
             - Coordinate token rotation before revocation"
        ),
        destructive_pattern!(
            "vault-lease-revoke",
            r"vault(?:\s+--?\S+(?:\s+\S+)?)*\s+lease\s+revoke\b",
            "vault lease revoke invalidates leases and can disrupt access.",
            High,
            "Revoking a lease immediately invalidates dynamic credentials (database \
             passwords, AWS keys, etc.). Applications using these credentials will \
             fail. With -prefix, all leases under a path are revoked.\n\n\
             Safer alternatives:\n\
             - vault lease lookup: Review lease details first\n\
             - Use shorter TTLs for automatic rotation\n\
             - Coordinate credential rotation before revocation"
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

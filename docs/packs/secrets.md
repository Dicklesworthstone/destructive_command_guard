# Secrets Management Packs

This document describes packs in the `secrets` category.

## Packs in this Category

- [HashiCorp Vault](#secretsvault)
- [AWS Secrets Manager](#secretsaws_secrets)
- [1Password CLI](#secretsonepassword)
- [Doppler CLI](#secretsdoppler)
- [Infisical CLI](#secretsinfisical)

---

## HashiCorp Vault

**Pack ID:** `secrets.vault`

Protects against destructive Vault CLI operations like deleting secrets, disabling auth/secret engines, revoking leases/tokens, and deleting policies.

### Keywords

Commands containing these keywords are checked against this pack:

- `vault`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `vault-status` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s\|$)` |
| `vault-version` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s\|$)` |
| `vault-read` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+read(?=\s\|$)` |
| `vault-kv-get` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+get(?=\s\|$)` |
| `vault-kv-list` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+kv\s+list(?=\s\|$)` |
| `vault-secrets-list` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+list(?=\s\|$)` |
| `vault-policy-list` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+list(?=\s\|$)` |
| `vault-token-lookup` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+lookup(?=\s\|$)` |
| `vault-auth-list` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+auth\s+list(?=\s\|$)` |
| `vault-audit-list` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+audit\s+list(?=\s\|$)` |
| `vault-lease-lookup` | `vault(?:\s+--?\S+(?:\s+\S+)?)*\s+lease\s+lookup(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `vault-secrets-disable` | vault secrets disable disables a secrets engine, causing data loss. | critical |
| `vault-kv-destroy` | vault kv destroy permanently deletes secret versions. | critical |
| `vault-kv-metadata-delete` | vault kv metadata delete removes all versions and metadata for a secret. | critical |
| `vault-kv-delete` | vault kv delete removes the latest secret version. | high |
| `vault-delete` | vault delete removes secrets at a path. | high |
| `vault-policy-delete` | vault policy delete removes access policies. | critical |
| `vault-auth-disable` | vault auth disable disables an auth method. | critical |
| `vault-token-revoke` | vault token revoke invalidates tokens and can disrupt access. | high |
| `vault-lease-revoke` | vault lease revoke invalidates leases and can disrupt access. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "secrets.vault:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "secrets.vault:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## AWS Secrets Manager

**Pack ID:** `secrets.aws_secrets`

Protects against destructive AWS Secrets Manager and SSM Parameter Store operations like delete-secret and delete-parameter.

### Keywords

Commands containing these keywords are checked against this pack:

- `aws`
- `secretsmanager`
- `ssm`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `aws-secretsmanager-list` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+list-secrets(?=\s\|$)` |
| `aws-secretsmanager-describe` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+describe-secret(?=\s\|$)` |
| `aws-secretsmanager-get` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-secret-value(?=\s\|$)` |
| `aws-secretsmanager-list-versions` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+list-secret-version-ids(?=\s\|$)` |
| `aws-secretsmanager-get-resource-policy` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-resource-policy(?=\s\|$)` |
| `aws-secretsmanager-get-random-password` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+secretsmanager\s+get-random-password(?=\s\|$)` |
| `aws-ssm-get-parameter` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameter(?=\s\|$)` |
| `aws-ssm-get-parameters` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+get-parameters(?=\s\|$)` |
| `aws-ssm-describe-parameters` | `aws(?:\s+--?\S+(?:\s+\S+)?)*\s+ssm\s+describe-parameters(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `aws-secretsmanager-delete-secret` | aws secretsmanager delete-secret removes secrets and may cause data loss. | critical |
| `aws-secretsmanager-delete-resource-policy` | aws secretsmanager delete-resource-policy removes access controls. | high |
| `aws-secretsmanager-remove-regions` | aws secretsmanager remove-regions-from-replication can reduce availability. | high |
| `aws-secretsmanager-update-secret` | aws secretsmanager update-secret overwrites secret metadata or value. | medium |
| `aws-secretsmanager-put-secret-value` | aws secretsmanager put-secret-value creates a new secret version and can break clients. | medium |
| `aws-ssm-delete-parameter` | aws ssm delete-parameter removes a parameter and can break deployments. | high |
| `aws-ssm-delete-parameters` | aws ssm delete-parameters removes parameters and can break deployments. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "secrets.aws_secrets:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "secrets.aws_secrets:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## 1Password CLI

**Pack ID:** `secrets.onepassword`

Protects against destructive 1Password CLI operations like deleting items, documents, users, groups, and vaults.

### Keywords

Commands containing these keywords are checked against this pack:

- `op`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `op-whoami` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s\|$)` |
| `op-account-get` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+account\s+get(?=\s\|$)` |
| `op-read` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+read(?=\s\|$)` |
| `op-item-get` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+get(?=\s\|$)` |
| `op-item-list` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+item\s+list(?=\s\|$)` |
| `op-document-get` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+document\s+get(?=\s\|$)` |
| `op-vault-list` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+list(?=\s\|$)` |
| `op-vault-get` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+vault\s+get(?=\s\|$)` |
| `op-user-list` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+user\s+list(?=\s\|$)` |
| `op-group-list` | `op(?:\s+--?\S+(?:\s+\S+)?)*\s+group\s+list(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `op-item-delete` | op item delete removes secret items (including archive operations). | high |
| `op-document-delete` | op document delete removes secure documents (including archive operations). | high |
| `op-vault-delete` | op vault delete removes an entire vault. | critical |
| `op-user-delete` | op user delete removes a user from 1Password. | high |
| `op-group-delete` | op group delete removes a group. | medium |
| `op-connect-token-delete` | op connect token delete revokes access tokens. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "secrets.onepassword:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "secrets.onepassword:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Doppler CLI

**Pack ID:** `secrets.doppler`

Protects against destructive Doppler CLI operations like deleting secrets, configs, environments, or projects.

### Keywords

Commands containing these keywords are checked against this pack:

- `doppler`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `doppler-secrets-get` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+get(?=\s\|$)` |
| `doppler-secrets-list` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+list(?=\s\|$)` |
| `doppler-run` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s\|$)` |
| `doppler-configure` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+configure(?=\s\|$)` |
| `doppler-setup` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+setup(?=\s\|$)` |
| `doppler-projects-list` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+list(?=\s\|$)` |
| `doppler-environments-list` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+list(?=\s\|$)` |
| `doppler-configs-list` | `doppler(?:\s+--?\S+(?:\s+\S+)?)*\s+configs\s+list(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `doppler-secrets-delete` | doppler secrets delete removes secrets. | high |
| `doppler-projects-delete` | doppler projects delete removes a project. | critical |
| `doppler-environments-delete` | doppler environments delete removes an environment. | high |
| `doppler-configs-delete` | doppler configs delete removes a config. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "secrets.doppler:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "secrets.doppler:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Infisical CLI

**Pack ID:** `secrets.infisical`

Protects against deleting Infisical secrets, folders, and dynamic-secret leases, plus resetting local Infisical configuration.

### Keywords

Commands containing these keywords are checked against this pack:

- `infisical`

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `infisical-secrets-delete` | infisical secrets delete removes one or more stored secrets. | high |
| `infisical-folders-delete` | infisical secrets folders delete removes a secrets folder. | critical |
| `infisical-dynamic-lease-delete` | infisical dynamic-secrets lease delete revokes a live dynamic-secret lease. | high |
| `infisical-reset` | infisical reset clears local Infisical-generated configuration data. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "secrets.infisical:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "secrets.infisical:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

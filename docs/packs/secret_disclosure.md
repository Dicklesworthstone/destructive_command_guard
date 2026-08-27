# secret_disclosure

This document describes packs in the `secret_disclosure` category.

## Packs in this Category

- [Secret Value Disclosure](#secret_disclosure)

---

## Secret Value Disclosure

**Pack ID:** `secret_disclosure`

Opt-in protection against secret-manager commands that emit credential values to stdout and therefore into an agent transcript.

### Keywords

Commands containing these keywords are checked against this pack:

- `infisical`
- `doppler`
- `vault`
- `aws`
- `secretsmanager`
- `ssm`
- `op`

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `infisical-secrets-list-output` | infisical secrets prints all selected secret values to stdout. | high |
| `infisical-secrets-get-output` | infisical secrets get prints requested secret values to stdout. | high |
| `infisical-export-output` | infisical export emits a complete set of secret values. | high |
| `infisical-dynamic-lease-create-output` | infisical dynamic-secrets lease create emits newly issued credentials. | high |
| `onepassword-read-output` | op read prints a 1Password field value to stdout. | high |
| `onepassword-item-get-output` | op item get can print secret fields to stdout. | high |
| `onepassword-document-get-output` | op document get emits protected document contents. | high |
| `doppler-secrets-output` | doppler secrets get/list/download emits secret values. | high |
| `vault-read-output` | vault read/kv get can print secret values to stdout. | high |
| `aws-secretsmanager-read-output` | aws secretsmanager get-secret-value prints a stored secret value. | high |
| `aws-ssm-decrypted-read-output` | aws ssm get-parameter(s) --with-decryption prints decrypted parameter values. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "secret_disclosure:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "secret_disclosure:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

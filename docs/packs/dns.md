# DNS Packs

This document describes packs in the `dns` category.

## Packs in this Category

- [Cloudflare DNS](#dnscloudflare)
- [AWS Route53](#dnsroute53)
- [Generic DNS Tools](#dnsgeneric)

---

## Cloudflare DNS

**Pack ID:** `dns.cloudflare`

Protects against destructive Cloudflare DNS operations like record deletion, zone deletion, and targeted Terraform destroy.

### Keywords

Commands containing these keywords are checked against this pack:

- `wrangler`
- `cloudflare`
- `api.cloudflare.com`
- `dns-records`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `cloudflare-wrangler-dns-list` | `wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+dns-records\s+list\b` |
| `cloudflare-wrangler-whoami` | `wrangler(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami\b` |
| `cloudflare-api-get` | `(?i)^(?!(?=.*(?:-X\s*\|--request(?:=\|\s+))DELETE\b)(?=.*\bapi\.cloudflare\.com\b[^\s]*?/(?:dns_records\|zones)/[^\s]+))curl\b.*(?:-X\s*\|--request(?:=\|\s+))GET\b.*\bapi\.cloudflare\.com\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `cloudflare-wrangler-dns-delete` | wrangler dns-records delete removes a Cloudflare DNS record. | high |
| `cloudflare-api-delete-dns-record` | curl -X DELETE against /dns_records/{id} deletes a Cloudflare DNS record. | high |
| `cloudflare-api-delete-zone` | curl -X DELETE against /zones/{id} deletes a Cloudflare zone. | critical |
| `cloudflare-terraform-destroy-record` | terraform destroy -target=cloudflare_record deletes specific DNS records. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "dns.cloudflare:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "dns.cloudflare:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## AWS Route53

**Pack ID:** `dns.route53`

Protects against destructive AWS Route53 DNS operations like hosted zone deletion and record set DELETE changes.

### Keywords

Commands containing these keywords are checked against this pack:

- `aws`
- `route53`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `route53-list-hosted-zones` | `\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+list-hosted-zones\b` |
| `route53-list-resource-record-sets` | `\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+list-resource-record-sets\b` |
| `route53-get-hosted-zone` | `\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+get-hosted-zone\b` |
| `route53-test-dns-answer` | `\baws\b(?:\s+--?\S+(?:\s+\S+)?)*\s+route53\s+test-dns-answer\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `route53-delete-hosted-zone` | aws route53 delete-hosted-zone permanently deletes a Route53 hosted zone. | critical |
| `route53-change-resource-record-sets-delete` | aws route53 change-resource-record-sets with DELETE removes DNS records. | high |
| `route53-delete-health-check` | aws route53 delete-health-check permanently deletes a Route53 health check. | high |
| `route53-delete-query-logging-config` | aws route53 delete-query-logging-config removes a Route53 query logging configuration. | medium |
| `route53-delete-traffic-policy` | aws route53 delete-traffic-policy permanently deletes a Route53 traffic policy. | high |
| `route53-delete-reusable-delegation-set` | aws route53 delete-reusable-delegation-set permanently deletes a reusable delegation set. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "dns.route53:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "dns.route53:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Generic DNS Tools

**Pack ID:** `dns.generic`

Protects against destructive or risky DNS tooling usage (nsupdate deletes, zone transfers).

### Keywords

Commands containing these keywords are checked against this pack:

- `nsupdate`
- `dig`
- `host`
- `nslookup`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `dns-dig-safe` | `\bdig\b(?!.*(?i:\b(?:axfr\|ixfr)\b))` |
| `dns-host-safe` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?host\b` |
| `dns-nslookup-safe` | `^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&\|<>()\x22'\\$`*?\[\]{}~]*[ \t]+)*(?:sudo[ \t]+(?:-n[ \t]+)?)?(?:[^\s;&\|<>()\x22'\\$`*?\[\]{}~=]+/)?nslookup\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `stdin-unverified` | nsupdate receives indirect input that dcg cannot statically verify. | high |
| `dns-nsupdate-delete` | nsupdate delete commands remove DNS records. | high |
| `dns-nsupdate-local` | nsupdate -l applies local updates which can modify DNS records. | medium |
| `dns-dig-zone-transfer` | dig AXFR/IXFR zone transfers can exfiltrate full zone data. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "dns.generic:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "dns.generic:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

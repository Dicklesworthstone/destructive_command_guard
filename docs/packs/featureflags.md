# Feature Flags Packs

This document describes packs in the `featureflags` category.

## Packs in this Category

- [Flipt](#featureflagsflipt)
- [LaunchDarkly](#featureflagslaunchdarkly)
- [Split.io](#featureflagssplit)
- [Unleash](#featureflagsunleash)

---

## Flipt

**Pack ID:** `featureflags.flipt`

Protects against destructive Flipt CLI and API operations.

### Keywords

Commands containing these keywords are checked against this pack:

- `flipt`
- `/api/v1/`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `flipt-flag-list` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+list(?=\s\|$)` |
| `flipt-flag-get` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+get(?=\s\|$)` |
| `flipt-flag-create` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+create(?=\s\|$)` |
| `flipt-flag-update` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+flag\s+update(?=\s\|$)` |
| `flipt-segment-list` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+list(?=\s\|$)` |
| `flipt-segment-get` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+get(?=\s\|$)` |
| `flipt-segment-create` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+segment\s+create(?=\s\|$)` |
| `flipt-namespace-list` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+list(?=\s\|$)` |
| `flipt-namespace-get` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+get(?=\s\|$)` |
| `flipt-namespace-create` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+create(?=\s\|$)` |
| `flipt-rule-list` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+list(?=\s\|$)` |
| `flipt-rule-get` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+get(?=\s\|$)` |
| `flipt-rule-create` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+rule\s+create(?=\s\|$)` |
| `flipt-evaluate` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+evaluate(?=\s\|$)` |
| `flipt-help` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help\|-h\|help)(?=\s\|$)` |
| `flipt-version` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version\|version)(?=\s\|$)` |
| `flipt-server` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:server\|serve)(?=\s\|$)` |
| `flipt-config` | `flipt(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `flipt-flag-delete` | flipt flag delete permanently removes a feature flag. This cannot be undone. | critical |
| `flipt-segment-delete` | flipt segment delete removes a segment and its constraints. | high |
| `flipt-namespace-delete` | flipt namespace delete removes a namespace and all its flags, segments, and rules. | critical |
| `flipt-rule-delete` | flipt rule delete removes a targeting rule from a flag. | high |
| `flipt-constraint-delete` | flipt constraint delete removes a constraint from a segment. | medium |
| `flipt-variant-delete` | flipt variant delete removes a variant from a flag. | high |
| `flipt-distribution-delete` | flipt distribution delete removes a distribution from a rule. | medium |
| `flipt-api-delete` | DELETE request to Flipt API can remove flags, segments, or rules. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "featureflags.flipt:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "featureflags.flipt:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## LaunchDarkly

**Pack ID:** `featureflags.launchdarkly`

Protects against destructive LaunchDarkly CLI and API operations.

### Keywords

Commands containing these keywords are checked against this pack:

- `ldcli`
- `launchdarkly`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `ldcli-flags-list` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+list(?=\s\|$)` |
| `ldcli-flags-get` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+get(?=\s\|$)` |
| `ldcli-flags-create` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+create(?=\s\|$)` |
| `ldcli-flags-update` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+flags\s+update(?=\s\|$)` |
| `ldcli-projects-list` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+list(?=\s\|$)` |
| `ldcli-projects-get` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+get(?=\s\|$)` |
| `ldcli-projects-create` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+create(?=\s\|$)` |
| `ldcli-environments-list` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+list(?=\s\|$)` |
| `ldcli-environments-get` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+get(?=\s\|$)` |
| `ldcli-environments-create` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+create(?=\s\|$)` |
| `ldcli-segments-list` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+list(?=\s\|$)` |
| `ldcli-segments-get` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+get(?=\s\|$)` |
| `ldcli-segments-create` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+create(?=\s\|$)` |
| `ldcli-metrics-list` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+metrics\s+list(?=\s\|$)` |
| `ldcli-metrics-get` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+metrics\s+get(?=\s\|$)` |
| `ldcli-help` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help\|-h\|help)(?=\s\|$)` |
| `ldcli-version` | `ldcli(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version\|version)(?=\s\|$)` |
| `launchdarkly-api-get` | `(?i)^(?!(?=.*(?:-X\s*\|--request(?:=\|\s+))DELETE\b)(?=.*app\.launchdarkly\.com/api/))curl\s+.*(?:-X\s*\|--request(?:=\|\s+))GET\b.*app\.launchdarkly\.com/api` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `ldcli-flags-delete` | ldcli flags delete permanently removes a feature flag. This cannot be undone. | critical |
| `ldcli-flags-archive` | ldcli flags archive soft-deletes a feature flag. While recoverable, this affects all environments. | high |
| `ldcli-projects-delete` | ldcli projects delete removes an entire project and all its flags, environments, and settings. | critical |
| `ldcli-environments-delete` | ldcli environments delete removes an environment and all its flag configurations. | critical |
| `ldcli-segments-delete` | ldcli segments delete removes a user segment and its targeting rules. | high |
| `ldcli-metrics-delete` | ldcli metrics delete removes a metric and its experiment data. | high |
| `launchdarkly-api-delete-environments` | DELETE request to LaunchDarkly API removes environments. | critical |
| `launchdarkly-api-delete-flags` | DELETE request to LaunchDarkly API removes feature flags. | critical |
| `launchdarkly-api-delete-segments` | DELETE request to LaunchDarkly API removes segments. | high |
| `launchdarkly-api-delete-projects` | DELETE request to LaunchDarkly API removes projects. | critical |
| `launchdarkly-api-delete-generic` | DELETE request to LaunchDarkly API can remove resources. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "featureflags.launchdarkly:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "featureflags.launchdarkly:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Split.io

**Pack ID:** `featureflags.split`

Protects against destructive Split.io CLI and API operations.

### Keywords

Commands containing these keywords are checked against this pack:

- `split`
- `api.split.io`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `split-splits-list` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+list(?=\s\|$)` |
| `split-splits-get` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+get(?=\s\|$)` |
| `split-splits-create` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+create(?=\s\|$)` |
| `split-splits-update` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+splits\s+update(?=\s\|$)` |
| `split-environments-list` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+list(?=\s\|$)` |
| `split-environments-get` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+get(?=\s\|$)` |
| `split-environments-create` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+environments\s+create(?=\s\|$)` |
| `split-segments-list` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+list(?=\s\|$)` |
| `split-segments-get` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+get(?=\s\|$)` |
| `split-segments-create` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+segments\s+create(?=\s\|$)` |
| `split-traffic-types-list` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+traffic-types\s+list(?=\s\|$)` |
| `split-traffic-types-get` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+traffic-types\s+get(?=\s\|$)` |
| `split-workspaces-list` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+workspaces\s+list(?=\s\|$)` |
| `split-workspaces-get` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+workspaces\s+get(?=\s\|$)` |
| `split-help` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help\|-h\|help)(?=\s\|$)` |
| `split-version` | `split(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version\|version)(?=\s\|$)` |
| `split-api-get` | `(?i)^(?!(?=.*(?:-X\s*\|--request(?:=\|\s+))DELETE\b)(?=.*api\.split\.io))curl\s+.*(?:-X\s*\|--request(?:=\|\s+))GET\b.*api\.split\.io` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `split-splits-delete` | split splits delete permanently removes a split definition. This cannot be undone. | critical |
| `split-splits-kill` | split splits kill terminates a split, stopping all traffic to treatments. | high |
| `split-environments-delete` | split environments delete removes an environment and all its configurations. | critical |
| `split-segments-delete` | split segments delete removes a segment and its targeting rules. | high |
| `split-traffic-types-delete` | split traffic-types delete removes a traffic type. This affects all splits using it. | critical |
| `split-workspaces-delete` | split workspaces delete removes a workspace and all its resources. | critical |
| `split-api-delete-splits` | DELETE request to Split.io API removes split definitions. | critical |
| `split-api-delete-environments` | DELETE request to Split.io API removes environments. | critical |
| `split-api-delete-segments` | DELETE request to Split.io API removes segments. | high |
| `split-api-delete-generic` | DELETE request to Split.io API can remove resources. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "featureflags.split:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "featureflags.split:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Unleash

**Pack ID:** `featureflags.unleash`

Protects against destructive Unleash CLI and API operations.

### Keywords

Commands containing these keywords are checked against this pack:

- `unleash`
- `/api/admin/`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `unleash-features-list` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+list(?=\s\|$)` |
| `unleash-features-get` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+get(?=\s\|$)` |
| `unleash-features-create` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+create(?=\s\|$)` |
| `unleash-features-update` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+update(?=\s\|$)` |
| `unleash-features-enable` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+enable(?=\s\|$)` |
| `unleash-features-disable` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+features?\s+disable\b` |
| `unleash-projects-list` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+list(?=\s\|$)` |
| `unleash-projects-get` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+get(?=\s\|$)` |
| `unleash-projects-create` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+projects?\s+create(?=\s\|$)` |
| `unleash-environments-list` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+environments?\s+list(?=\s\|$)` |
| `unleash-environments-get` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+environments?\s+get(?=\s\|$)` |
| `unleash-strategies-list` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+strategies?\s+list(?=\s\|$)` |
| `unleash-strategies-get` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+strategies?\s+get(?=\s\|$)` |
| `unleash-help` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--help\|-h\|help)(?=\s\|$)` |
| `unleash-version` | `unleash(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:--version\|version)(?=\s\|$)` |
| `unleash-api-get` | `(?i)^(?!(?=.*(?:-X\s*\|--request(?:=\|\s+))DELETE\b)(?=.*/api/admin/))curl\s+.*(?:-X\s*\|--request(?:=\|\s+))GET\b.*/api/admin/` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `unleash-features-delete` | unleash features delete permanently removes a feature toggle. This cannot be undone. | critical |
| `unleash-features-archive` | unleash features archive soft-deletes a feature toggle. | high |
| `unleash-projects-delete` | unleash projects delete removes a project and all its feature toggles. | critical |
| `unleash-environments-delete` | unleash environments delete removes an environment. | critical |
| `unleash-strategies-delete` | unleash strategies delete removes a custom strategy. | high |
| `unleash-api-keys-delete` | unleash api-keys delete removes an API key. | high |
| `unleash-api-delete-features` | DELETE request to Unleash API removes feature toggles. | critical |
| `unleash-api-delete-projects` | DELETE request to Unleash API removes projects. | critical |
| `unleash-api-delete-generic` | DELETE request to Unleash API can remove resources. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "featureflags.unleash:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "featureflags.unleash:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

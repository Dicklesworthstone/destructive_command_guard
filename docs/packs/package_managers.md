# Package Manager Packs

This document describes packs in the `package_managers` category.

## Packs in this Category

- [Package Managers](#package_managers)

---

## Package Managers

**Pack ID:** `package_managers`

Protects against dangerous package manager operations like publishing packages and removing critical system packages

### Keywords

Commands containing these keywords are checked against this pack:

- `npm`
- `yarn`
- `pnpm`
- `pip`
- `apt`
- `yum`
- `dnf`
- `cargo`
- `gem`
- `brew`
- `poetry`
- `mvn`
- `mvnw`
- `gradle`
- `gradlew`
- `publish`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `npm-install` | `\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:install\|i\|ci)(?=\s\|$)` |
| `yarn-add` | `\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:add\|install)(?=\s\|$)` |
| `pnpm-install` | `\bpnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:add\|install\|i)(?=\s\|$)` |
| `npm-list` | `\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list\|ls\|info\|view)(?=\s\|$)` |
| `yarn-list` | `\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list\|info\|why)(?=\s\|$)` |
| `npm-audit` | `\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?=\s\|$)` |
| `yarn-audit` | `\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?=\s\|$)` |
| `pip-list` | `\bpip\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list\|show\|freeze)(?=\s\|$)` |
| `poetry-show` | `\bpoetry\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s\|$)` |
| `poetry-env-list` | `\bpoetry\b(?:\s+--?\S+(?:\s+\S+)?)*\s+env\s+list(?=\s\|$)` |
| `cargo-safe` | `\bcargo\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:build\|test\|check\|clippy\|fmt\|doc\|bench)\b` |
| `apt-list` | `\bapt\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list\|show\|search)(?=\s\|$)` |
| `apt-get-list` | `\bapt-get\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:update\|upgrade)(?!\s+.*-y)` |
| `npm-dry-run` | `\bnpm\b[^;\|&\n]*--dry-run(?:=true)?(?:\s\|$)` |
| `yarn-dry-run` | `\byarn\b[^;\|&\n]*--dry-run(?:=true)?(?:\s\|$)` |
| `pnpm-dry-run` | `\bpnpm\b[^;\|&\n]*--dry-run(?:=true)?(?:\s\|$)` |
| `cargo-dry-run` | `\bcargo\b[^;\|&\n]*--dry-run(?:=true)?(?:\s\|$)` |
| `poetry-dry-run` | `\bpoetry\b[^;\|&\n]*--dry-run(?:=true)?(?:\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `npm-publish` | npm publish releases a package publicly. Use --dry-run first. | high |
| `yarn-publish` | yarn publish releases a package publicly. Verify package.json first. | high |
| `pnpm-publish` | pnpm publish releases a package publicly. | high |
| `npm-unpublish` | npm unpublish removes a published package. This can break dependent projects. | high |
| `pip-uninstall` | pip uninstall removes installed packages. Verify dependencies before removing. | high |
| `pip-url` | pip install from URL can install unvetted code. Verify the source first. | high |
| `pip-system` | pip install to system directories requires careful review. | high |
| `apt-remove` | apt remove/purge removes packages. Verify no critical packages are affected. | high |
| `yum-remove` | yum/dnf remove removes packages. Verify no critical packages are affected. | high |
| `cargo-publish` | cargo publish releases a crate to crates.io. Use --dry-run first. | high |
| `cargo-yank` | cargo yank marks a version as unavailable. This can break dependent projects. | high |
| `gem-push` | gem push releases a gem to rubygems.org. Verify before publishing. | high |
| `brew-uninstall` | brew uninstall removes packages. Verify no dependent packages are affected. | high |
| `poetry-publish` | poetry publish releases a package. Use --dry-run first. | high |
| `poetry-remove` | poetry remove uninstalls a dependency. Verify no critical packages are affected. | high |
| `maven-deploy` | mvn deploy publishes artifacts to a remote repository. Verify target repository. | high |
| `maven-release-perform` | mvn release:perform publishes a release. Verify version and repository. | high |
| `gradle-publish` | gradle publish uploads artifacts. Use --dry-run first when possible. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "package_managers:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "package_managers:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

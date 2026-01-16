# Pack Maintenance and CLI Evolution Strategy

CLI tools evolve: new commands appear, flags change, and destructive operations
shift over time. This document defines how packs stay current.

## 1) CLI Version Tracking

Maintain `docs/cli-versions.yaml` with:
- tool name
- tested versions
- last verified date
- changelog URL

Update the file as part of each quarterly audit.

## 2) Quarterly Version Audit

Every quarter:
1. Check new releases for each tracked CLI.
2. Review changelogs for destructive operations or syntax changes.
3. Update pack patterns as needed.
4. Update `tested_versions` and `last_verified`.
5. Run the full test suite.

## 3) Breaking Change Protocol

When a CLI introduces breaking changes:
1. Open an urgent patch bead.
2. Update patterns for new syntax.
3. Keep backward compatibility for N-1 version when feasible.
4. Document the change in release notes.

## 4) Deprecation Strategy

When removing patterns:
1. Mark deprecated in code comments.
2. Log a warning when deprecated patterns match.
3. Keep for two releases.
4. Remove and document in changelog.

## 5) User-Reported Updates

Handle reports as follows:
- **False negatives**: add patterns + tests.
- **False positives**: add safe patterns + edge cases.
- **New pack requests**: create new pack tasks with the standard template.

## 6) Automation

### CLI Version Checker

`scripts/check_cli_versions.sh` scans changelogs and flags new releases.
It is intended for scheduled CI usage and should open an issue when a new
version is detected (implementation TODO).

The weekly CI runner is defined in `.github/workflows/cli-version-audit.yml`.

### Multi-Version CI Testing

Add CI matrices for high-risk tools (Vault, rclone, gh) to verify patterns
against multiple versions. Initial plan (example):

```yaml
matrix:
  vault_version: ["1.15.0", "1.16.0", "latest"]
  rclone_version: ["1.65.0", "1.66.0", "latest"]
```

## 7) Privacy and Safety

History and version checking must never log command contents. Use hashes
and metadata only.

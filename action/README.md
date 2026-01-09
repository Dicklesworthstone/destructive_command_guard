# Destructive Command Guard - GitHub Action

A GitHub Action that scans your repository for destructive commands in executable contexts (shell scripts, Dockerfiles, GitHub Actions workflows, CI configs, etc.).

## Quick Start

Add to your workflow:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write  # Required for PR comments
    steps:
      - uses: actions/checkout@v4
      - uses: Dicklesworthstone/destructive_command_guard/action@v0
        with:
          fail-on: error
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `paths` | Paths to scan (space-separated) | `.` |
| `git-diff` | Git ref range for diff scanning (e.g., `origin/main...HEAD`) | |
| `fail-on` | Severity threshold: `error`, `warning`, or `none` | `error` |
| `format` | Output format: `json`, `pretty`, `compact`, `markdown` | `json` |
| `max-findings` | Maximum findings to report (0 = unlimited) | `100` |
| `truncate` | Maximum command preview length | `200` |
| `comment-on-pr` | Post results as PR comment | `false` |
| `dcg-version` | DCG version to use | `latest` |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Exit code (0 = clean, non-zero = findings) |
| `files-scanned` | Number of files scanned |
| `findings-total` | Total findings count |
| `errors` | Error-severity findings count |
| `warnings` | Warning-severity findings count |
| `results-file` | Path to JSON results file |

## Examples

### PR Diff Scanning

Scan only changed files in a pull request:

```yaml
- uses: Dicklesworthstone/destructive_command_guard/action@v0
  with:
    git-diff: ${{ github.event.pull_request.base.sha }}...HEAD
    comment-on-pr: true
```

### Full Repository Scan

Scan the entire repository:

```yaml
- uses: Dicklesworthstone/destructive_command_guard/action@v0
  with:
    paths: .
    fail-on: warning
```

### Scan Specific Directories

```yaml
- uses: Dicklesworthstone/destructive_command_guard/action@v0
  with:
    paths: scripts/ .github/workflows/
```

### Use Results in Subsequent Steps

```yaml
- uses: Dicklesworthstone/destructive_command_guard/action@v0
  id: scan
  with:
    fail-on: none  # Don't fail, just report

- name: Check results
  if: steps.scan.outputs.findings-total > 0
  run: |
    echo "Found ${{ steps.scan.outputs.findings-total }} issues"
    cat ${{ steps.scan.outputs.results-file }}
```

### Pin to Specific Version

```yaml
- uses: Dicklesworthstone/destructive_command_guard/action@v0
  with:
    dcg-version: v0.2.0
```

## What Gets Scanned

The action scans for destructive commands in:

- Shell scripts (`.sh`, `.bash`, `.zsh`)
- Dockerfiles
- GitHub Actions workflows (`.yml`, `.yaml`)
- GitLab CI configs (`.gitlab-ci.yml`)
- Makefiles
- Package.json scripts
- Docker Compose files
- Terraform provisioners (`.tf`)

## License

MIT

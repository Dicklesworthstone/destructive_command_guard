# dcg (Destructive Command Guard)

<div align="center">
  <img src="illustration.webp" alt="Destructive Command Guard - Protecting your code from accidental destruction">
</div>

<div align="center">

[![CI](https://github.com/Dicklesworthstone/destructive_command_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Dicklesworthstone/destructive_command_guard/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/Dicklesworthstone/destructive_command_guard?label=coverage)](https://codecov.io/gh/Dicklesworthstone/destructive_command_guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

A high-performance hook for AI coding agents that blocks destructive commands before they execute, protecting your work from accidental deletion.

**Supported:** [Claude Code](https://claude.ai/code) and [Gemini CLI](https://github.com/google-gemini/gemini-cli)

<div align="center">
<h3>Quick Install</h3>

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

<p><em>Works on Linux, macOS, and Windows (WSL). Auto-detects your platform and downloads the right binary.</em></p>
</div>

---

## TL;DR

**The Problem**: AI coding agents (Claude, GPT, etc.) occasionally run catastrophic commands like `git reset --hard`, `rm -rf ./src`, or `DROP TABLE users`—destroying hours of uncommitted work in seconds.

**The Solution**: dcg is a high-performance hook that intercepts destructive commands *before* they execute, blocking them with clear explanations and safer alternatives.

### Why Use dcg?

| Feature | What It Does |
|---------|--------------|
| **Zero-Config Protection** | Blocks dangerous git/filesystem commands out of the box |
| **49+ Security Packs** | Databases, Kubernetes, Docker, AWS/GCP/Azure, Terraform, and more |
| **Sub-Millisecond Latency** | SIMD-accelerated filtering—you won't notice it's there |
| **Heredoc/Inline Script Scanning** | Catches `python -c "os.remove(...)"` and embedded shell scripts |
| **Smart Context Detection** | Won't block `grep "rm -rf"` (data) but will block `rm -rf /` (execution) |
| **Scan Mode for CI** | Pre-commit hooks and CI integration to catch dangerous commands in code review |
| **Fail-Open Design** | Never blocks your workflow due to timeouts or parse errors |
| **Explain Mode** | `dcg explain "command"` shows exactly why something is blocked |

### Quick Example

```bash
# AI agent tries to run:
$ git reset --hard HEAD~5

# dcg intercepts and blocks:
════════════════════════════════════════════════════════════════
BLOCKED  dcg
────────────────────────────────────────────────────────────────
Reason:  git reset --hard destroys uncommitted changes

Command: git reset --hard HEAD~5

Tip: Consider using 'git stash' first to save your changes.
════════════════════════════════════════════════════════════════
```

### Enable More Protection

```toml
# ~/.config/dcg/config.toml
[packs]
enabled = [
    "database.postgresql",    # Blocks DROP TABLE, TRUNCATE
    "kubernetes.kubectl",     # Blocks kubectl delete namespace
    "cloud.aws",              # Blocks aws ec2 terminate-instances
    "containers.docker",      # Blocks docker system prune
]
```

---

## Origins & Authors

This project began as a Python script by Jeffrey Emanuel, who recognized that AI coding agents, while incredibly useful, occasionally run catastrophic commands that destroy hours of uncommitted work. The original implementation was a simple but effective hook that intercepted dangerous git and filesystem commands before execution.

- **[Jeffrey Emanuel](https://github.com/Dicklesworthstone)** - Original concept and Python implementation ([source](https://github.com/Dicklesworthstone/misc_coding_agent_tips_and_scripts/blob/main/DESTRUCTIVE_GIT_COMMAND_CLAUDE_HOOKS_SETUP.md)); substantially expanded the Rust version with the modular pack system (49+ security packs), heredoc/inline-script scanning, the three-tier architecture, context classification, allowlists, scan mode, and the dual regex engine
- **[Darin Gordon](https://github.com/Dowwie)** - Initial Rust port with performance optimizations

The initial Rust port by Darin maintained pattern compatibility with the original Python implementation while adding sub-millisecond execution through SIMD-accelerated filtering and lazy-compiled regex patterns. Jeffrey subsequently expanded the Rust codebase dramatically to add the features described above.

## Why This Exists

AI coding agents are powerful but fallible. They can accidentally run destructive commands that wipe out hours of uncommitted work, drop database tables, or delete critical files. Common scenarios include:

- **"Let me clean up the build artifacts"** → `rm -rf ./src` (typo)
- **"I'll reset to the last commit"** → `git reset --hard` (destroys uncommitted changes)
- **"Let me fix the merge conflict"** → `git checkout -- .` (discards all modifications)
- **"I'll clean up untracked files"** → `git clean -fd` (permanently deletes untracked files)

This hook intercepts dangerous commands *before* execution and blocks them with a clear explanation, giving you a chance to stash your changes first, or to consciously proceed by running the command manually.

## What It Blocks

**Git commands that destroy uncommitted work:**
- `git reset --hard` / `git reset --merge` - destroys uncommitted changes
- `git checkout -- <file>` - discards file modifications
- `git restore <file>` (without `--staged`) - discards uncommitted changes
- `git clean -f` - permanently deletes untracked files

**Git commands that can destroy remote history:**
- `git push --force` / `git push -f` - overwrites remote commits
- `git branch -D` - force-deletes branches without merge check

**Git commands that destroy stashed work:**
- `git stash drop` / `git stash clear` - permanently deletes stashes

**Filesystem commands:**
- `rm -rf` on any path outside `/tmp`, `/var/tmp`, or `$TMPDIR`

**Heredoc and inline-script scanning (AST-based):**
- Blocks destructive operations embedded inside heredocs, here-strings, and inline scripts
  (e.g., `python -c`, `bash -c`, `node -e`)
- Supported languages: bash, python, javascript, typescript, ruby, perl, go
- Fail-open on parse errors/timeouts to avoid breaking workflows

## What It Allows

**Safe git operations pass through silently:**
- `git status`, `git log`, `git diff`, `git add`, `git commit`, `git push`, `git pull`, `git fetch`
- `git branch -d` (safe delete with merge check)
- `git stash`, `git stash pop`, `git stash list`

**Explicitly safe patterns:**
- `git checkout -b <branch>` - creating new branches
- `git checkout --orphan <branch>` - creating orphan branches
- `git restore --staged <file>` - unstaging (safe, doesn't touch working tree)
- `git clean -n` / `git clean --dry-run` - preview mode
- `rm -rf /tmp/*`, `rm -rf /var/tmp/*`, `rm -rf $TMPDIR/*` - temp directory cleanup

## Modular Pack System

dcg uses a modular "pack" system to organize destructive command patterns by category. Packs can be enabled or disabled in the configuration file.

- Full pack ID index: `docs/packs/README.md`
- Canonical descriptions + pattern counts: `dcg packs --verbose`

### Core Packs (enabled by default)
- `core.filesystem` - Protects against dangerous rm -rf commands outside temp directories
- `core.git` - Protects against destructive git commands that can lose uncommitted work, rewrite history, or destroy stashes

**Common packs enabled by default:**
- `database.postgresql` - Protects against destructive PostgreSQL operations
- `containers.docker` - Protects against destructive Docker operations like system prune

### Storage Packs
- `storage.s3` - Protects against destructive S3 operations like bucket removal, recursive deletes, and sync --delete.
- `storage.gcs` - Protects against destructive GCS operations like bucket removal, object deletion, and recursive deletes.
- `storage.minio` - Protects against destructive MinIO Client (mc) operations like bucket removal, object deletion, and admin operations.
- `storage.azure_blob` - Protects against destructive Azure Blob Storage operations like container deletion, blob deletion, and azcopy remove.

### Remote Packs
- `remote.rsync` - Protects against destructive rsync operations like --delete and its variants.
- `remote.scp` - Protects against destructive SCP operations like overwrites to system paths.
- `remote.ssh` - Protects against destructive SSH operations like remote command execution and key management.

### Database Packs
- `database.postgresql` - Protects against destructive PostgreSQL operations like DROP DATABASE, TRUNCATE, and dropdb.
- `database.mysql` - MySQL/MariaDB guard.
- `database.mongodb` - Protects against destructive MongoDB operations like dropDatabase, dropCollection, and remove without criteria.
- `database.redis` - Protects against destructive Redis operations like FLUSHALL, FLUSHDB, and mass key deletion.
- `database.sqlite` - Protects against destructive SQLite operations like DROP TABLE, DELETE without WHERE, and accidental data loss.

### Container Packs
- `containers.docker` - Protects against destructive Docker operations like system prune, volume prune, and force removal.
- `containers.compose` - Protects against destructive Docker Compose operations like down -v which removes volumes.
- `containers.podman` - Protects against destructive Podman operations like system prune, volume prune, and force removal.

### Kubernetes Packs
- `kubernetes.kubectl` - Protects against destructive kubectl operations like delete namespace, drain, and mass deletion.
- `kubernetes.helm` - Protects against destructive Helm operations like uninstall and rollback without dry-run.
- `kubernetes.kustomize` - Protects against destructive Kustomize operations when combined with kubectl delete or applied without review.

### Cloud Provider Packs
- `cloud.aws` - Protects against destructive AWS CLI operations like terminate-instances, delete-db-instance, and s3 rm --recursive.
- `cloud.azure` - Protects against destructive Azure CLI operations like vm delete, storage account delete, and resource group delete.
- `cloud.gcp` - Protects against destructive gcloud operations like instances delete, sql instances delete, and gsutil rm -r.

### CDN Packs
- `cdn.cloudflare_workers` - Protects against destructive Cloudflare Workers, KV, R2, and D1 operations via the Wrangler CLI.
- `cdn.cloudfront` - Protects against destructive AWS CloudFront operations like deleting distributions, cache policies, and functions.
- `cdn.fastly` - Protects against destructive Fastly CLI operations like service, domain, backend, and VCL deletion.

### API Gateway Packs
- `apigateway.apigee` - Protects against destructive Google Apigee CLI and apigeecli operations.
- `apigateway.aws` - Protects against destructive AWS API Gateway CLI operations for both REST APIs and HTTP APIs.
- `apigateway.kong` - Protects against destructive Kong Gateway CLI, deck CLI, and Admin API operations.

### Infrastructure Packs
- `infrastructure.ansible` - Protects against destructive Ansible operations like dangerous shell commands and unchecked playbook runs.
- `infrastructure.pulumi` - Protects against destructive Pulumi operations like destroy and up with -y (auto-approve).
- `infrastructure.terraform` - Protects against destructive Terraform operations like destroy, taint, and apply with -auto-approve.

### System Packs
- `system.disk` - Protects against destructive disk operations like dd to devices, mkfs, and partition table modifications.
- `system.permissions` - Protects against dangerous permission changes like chmod 777, recursive chmod/chown on system directories.
- `system.services` - Protects against dangerous service operations like stopping critical services and modifying init configuration.

### CI/CD Packs
- `cicd.circleci` - Protects against destructive CircleCI operations like deleting contexts, removing secrets, deleting orbs/namespaces, or removing pipelines.
- `cicd.github_actions` - Protects against destructive GitHub Actions operations like deleting secrets/variables or using gh api DELETE against /actions endpoints.
- `cicd.gitlab_ci` - Protects against destructive GitLab CI/CD operations like deleting variables, removing artifacts, and unregistering runners.
- `cicd.jenkins` - Protects against destructive Jenkins CLI/API operations like deleting jobs, nodes, credentials, or build history.

### Secrets Management Packs
- `secrets.aws_secrets` - Protects against destructive AWS Secrets Manager and SSM Parameter Store operations like delete-secret and delete-parameter.
- `secrets.doppler` - Protects against destructive Doppler CLI operations like deleting secrets, configs, environments, or projects.
- `secrets.onepassword` - Protects against destructive 1Password CLI operations like deleting items, documents, users, groups, and vaults.
- `secrets.vault` - Protects against destructive Vault CLI operations like deleting secrets, disabling auth/secret engines, revoking leases/tokens, and deleting policies.

### Platform Packs
- `platform.github` - Protects against destructive GitHub CLI operations like deleting repositories, gists, releases, or SSH keys.
- `platform.gitlab` - Protects against destructive GitLab platform operations like deleting projects, releases, protected branches, and webhooks.

### DNS Packs
- `dns.cloudflare` - Protects against destructive Cloudflare DNS operations like record deletion, zone deletion, and targeted Terraform destroy.
- `dns.generic` - Protects against destructive or risky DNS tooling usage (nsupdate deletes, zone transfers).
- `dns.route53` - Protects against destructive AWS Route53 DNS operations like hosted zone deletion and record set DELETE changes.

### Email Packs
- `email.mailgun` - Protects against destructive Mailgun API operations like domain deletion, route deletion, and mailing list removal.
- `email.postmark` - Protects against destructive Postmark API operations like server deletion, template deletion, and sender signature removal.
- `email.sendgrid` - Protects against destructive SendGrid API operations like template deletion, API key deletion, and domain authentication removal.
- `email.ses` - Protects against destructive AWS Simple Email Service operations like identity deletion, template deletion, and configuration set removal.

### Feature Flag Packs
- `featureflags.flipt` - Protects against destructive Flipt CLI and API operations.
- `featureflags.launchdarkly` - Protects against destructive LaunchDarkly CLI and API operations.
- `featureflags.split` - Protects against destructive Split.io CLI and API operations.
- `featureflags.unleash` - Protects against destructive Unleash CLI and API operations.

### Load Balancer Packs
- `loadbalancer.elb` - Protects against destructive AWS Elastic Load Balancing (ELB/ALB/NLB) operations like deleting load balancers, target groups, or deregistering targets from live traffic.
- `loadbalancer.haproxy` - Protects against destructive HAProxy load balancer operations like stopping the service or disabling backends via runtime API.
- `loadbalancer.nginx` - Protects against destructive nginx load balancer operations like stopping the service or deleting config files.
- `loadbalancer.traefik` - Protects against destructive Traefik load balancer operations like stopping containers, deleting config, or API deletions.

### Messaging Packs
- `messaging.kafka` - Protects against destructive Kafka CLI operations like deleting topics, removing consumer groups, resetting offsets, and deleting records.
- `messaging.nats` - Protects against destructive NATS/JetStream operations like deleting streams, consumers, key-value entries, objects, and accounts.
- `messaging.rabbitmq` - Protects against destructive RabbitMQ operations like deleting queues/exchanges, purging queues, deleting vhosts, and resetting cluster state.
- `messaging.sqs_sns` - Protects against destructive AWS SQS and SNS operations like deleting queues, purging messages, deleting topics, and removing subscriptions.

### Monitoring Packs
- `monitoring.datadog` - Protects against destructive Datadog CLI/API operations like deleting monitors and dashboards.
- `monitoring.newrelic` - Protects against destructive New Relic CLI/API operations like deleting entities or alerting resources.
- `monitoring.pagerduty` - Protects against destructive PagerDuty CLI/API operations like deleting services and schedules (which can break incident routing).
- `monitoring.prometheus` - Protects against destructive Prometheus/Grafana operations like deleting time series data or dashboards/datasources.
- `monitoring.splunk` - Protects against destructive Splunk CLI/API operations like index removal and REST API DELETE calls.

### Payment Packs
- `payment.braintree` - Protects against destructive Braintree/PayPal payment operations like deleting customers or cancelling subscriptions via API/SDK calls.
- `payment.square` - Protects against destructive Square CLI/API operations like deleting catalog objects or customers (which can break payment flows).
- `payment.stripe` - Protects against destructive Stripe CLI/API operations like deleting webhook endpoints and customers, or rotating API keys without coordination.

### Search Engine Packs
- `search.algolia` - Protects against destructive Algolia operations like deleting indices, clearing objects, removing rules/synonyms, and deleting API keys.
- `search.elasticsearch` - Protects against destructive Elasticsearch REST API operations like index deletion, delete-by-query, index close, and cluster setting changes.
- `search.meilisearch` - Protects against destructive Meilisearch REST API operations like index deletion, document deletion, delete-batch, and API key removal.
- `search.opensearch` - Protects against destructive OpenSearch REST API operations and AWS CLI domain deletions.

### Backup Packs
- `backup.borg` - Protects against destructive borg operations like delete, prune, compact, and recreate.
- `backup.rclone` - Protects against destructive rclone operations like sync, delete, purge, dedupe, and move.
- `backup.restic` - Protects against destructive restic operations like forgetting snapshots, pruning data, removing keys, and cache cleanup.
- `backup.velero` - Protects against destructive velero operations like deleting backups, schedules, and locations.

### Other Packs
- `package_managers` - Protects against dangerous package manager operations like publishing packages and removing critical system packages.
- `strict_git` - Stricter git protections: blocks all force pushes, rebases, and history rewriting operations.

Enable packs in `~/.config/dcg/config.toml`:

```toml
[packs]
enabled = [
    # Databases
    "database.postgresql",
    "database.redis",

    # Containers and orchestration
    "containers.docker",
    "kubernetes",  # Enables all kubernetes sub-packs

    # Cloud providers
    "cloud.aws",
    "cloud.gcp",

    # Secrets management
    "secrets.aws_secrets",
    "secrets.vault",

    # CI/CD
    "cicd.jenkins",
    "cicd.gitlab_ci",

    # Messaging
    "messaging.kafka",
    "messaging.sqs_sns",

    # Search engines
    "search.elasticsearch",

    # Backup
    "backup.restic",

    # Platform
    "platform.github",

    # Monitoring
    "monitoring.splunk",
]
```

Heredoc scanning configuration:

```toml
[heredoc]
# Enable scanning for heredocs and inline scripts (python -c, bash -c, etc.).
enabled = true

# Extraction timeout budget (milliseconds).
timeout_ms = 50

# Resource limits for extracted bodies.
max_body_bytes = 1048576
max_body_lines = 10000
max_heredocs = 10

# Optional language filter (scan only these languages). Omit for "all".
# languages = ["python", "bash", "javascript", "typescript", "ruby", "perl", "go"]

# Graceful degradation (hook defaults are fail-open).
fallback_on_parse_error = true
fallback_on_timeout = true
```

CLI overrides for heredoc scanning:

- `--heredoc-scan` / `--no-heredoc-scan`
- `--heredoc-timeout <ms>`
- `--heredoc-languages <lang1,lang2,...>`

Heredoc documentation:

- `docs/adr-001-heredoc-scanning.md` (architecture and rationale)
- `docs/patterns.md` (pattern authoring + inventory)
- `docs/security.md` (threat model and incident response)

#### Heredoc Three-Tier Architecture

Heredoc and inline script scanning uses a three-tier pipeline designed for performance and accuracy:

```
Command Input
     │
     ▼
┌─────────────────┐
│ Tier 1: Trigger │ ─── No match ──► ALLOW (fast path, <100μs)
│   (RegexSet)    │
└────────┬────────┘
         │ Match
         ▼
┌─────────────────┐
│ Tier 2: Extract │ ─── Error/Timeout ──► ALLOW + fallback check
│   (<1ms)        │
└────────┬────────┘
         │ Success
         ▼
┌─────────────────┐
│ Tier 3: AST     │ ─── No match ──► ALLOW
│   (<5ms)        │ ─── Match ──► BLOCK
└─────────────────┘
```

**Tier 1: Trigger Detection** (<100μs)

Ultra-fast regex screening to detect heredoc indicators. Uses a compiled `RegexSet` for O(n) matching against all trigger patterns simultaneously:

```rust
static HEREDOC_TRIGGERS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"<<-?\s*(?:['\x22][^'\x22]*['\x22]|[\w.-]+)",  // Heredocs
        r"<<<",                                          // Here-strings
        r"\bpython[0-9.]*\b.*\s+-[A-Za-z]*[ce]",        // python -c/-e
        r"\bruby[0-9.]*\b.*\s+-[A-Za-z]*e",             // ruby -e
        r"\bnode(js)?[0-9.]*\b.*\s+-[A-Za-z]*[ep]",     // node -e/-p
        r"\b(sh|bash|zsh)\b.*\s+-[A-Za-z]*c",           // bash -c
        // ... more patterns
    ])
});
```

Commands without any trigger patterns skip directly to ALLOW—no further processing needed.

**Tier 2: Content Extraction** (<1ms)

For commands that trigger, extract the actual content to be evaluated:

- **Heredocs**: `cat <<EOF ... EOF` → extracts body between delimiters
- **Here-strings**: `cat <<< "content"` → extracts quoted content
- **Inline scripts**: `python -c "code"` → extracts the code argument

Extraction is bounded by configurable limits:
- Maximum body size (default: 1MB)
- Maximum lines (default: 10,000)
- Maximum heredocs per command (default: 10)
- Timeout (default: 50ms)

```rust
pub struct ExtractionLimits {
    pub max_body_bytes: usize,
    pub max_body_lines: usize,
    pub max_heredocs: usize,
    pub timeout_ms: u64,
}
```

**Tier 3: AST Pattern Matching** (<5ms)

Extracted content is parsed using language-specific AST grammars (via tree-sitter/ast-grep) and matched against structural patterns:

```rust
// Example: detect subprocess.run with shell=True and rm -rf
let pattern = r#"
    call_expression {
        function: attribute { object: "subprocess" attr: "run" }
        arguments: argument_list {
            contains string { contains "rm -rf" }
            contains keyword_argument { keyword: "shell" value: "True" }
        }
    }
"#;
```

**Recursive Shell Analysis**:

When extracted content is itself a shell script (e.g., `bash -c "git reset --hard"`), Tier 3 recursively extracts inner commands and re-evaluates them through the full pipeline:

```rust
if content.language == ScriptLanguage::Bash {
    let inner_commands = extract_shell_commands(&content.content);
    for inner in inner_commands {
        // Re-evaluate inner command against all packs
        if let Some(result) = evaluate_command(&inner, ...) {
            if result.decision == Deny {
                return result; // Block the outer command
            }
        }
    }
}
```

If you encounter commands that should be blocked, please file an issue.

### Environment Variables

Environment variables override config files (highest priority):

- `DCG_PACKS="containers.docker,kubernetes"`: enable packs (comma-separated)
- `DCG_DISABLE="kubernetes.helm"`: disable packs/sub-packs (comma-separated)
- `DCG_VERBOSE=1`: verbose output
- `DCG_COLOR=auto|always|never`: color mode
- `DCG_BYPASS=1`: bypass dcg entirely (escape hatch; use sparingly)
- `DCG_CONFIG=/path/to/config.toml`: use explicit config file
- `DCG_HEREDOC_ENABLED=true|false`: enable/disable heredoc scanning
- `DCG_HEREDOC_TIMEOUT=50`: heredoc extraction timeout (milliseconds)
- `DCG_HEREDOC_LANGUAGES=python,bash`: filter heredoc languages
- `DCG_POLICY_DEFAULT_MODE=deny|warn|log`: global default decision mode

### Configuration Hierarchy

dcg supports layered configuration from multiple sources, with higher-priority sources overriding lower ones:

```
1. Environment Variables (DCG_* prefix)           [HIGHEST PRIORITY]
2. Explicit Config File (DCG_CONFIG env var)
3. Project Config (.dcg.toml in repo root)
4. User Config (~/.config/dcg/config.toml)
5. System Config (/etc/dcg/config.toml)
6. Compiled Defaults                              [LOWEST PRIORITY]
```

**Configuration File Locations**:

| Level | Path | Use Case |
|-------|------|----------|
| System | `/etc/dcg/config.toml` | Organization-wide defaults |
| User | `~/.config/dcg/config.toml` | Personal preferences |
| Project | `.dcg.toml` (repo root) | Project-specific settings |
| Explicit | `DCG_CONFIG=/path/to/file` | Testing or override |

**Merging Behavior**:

Configuration layers are merged additively, with higher-priority sources overriding specific fields:

```rust
// Only fields explicitly set in higher-priority configs override
// Missing fields retain values from lower-priority sources
fn merge_layer(&mut self, other: ConfigLayer) {
    if let Some(verbose) = other.general.verbose {
        self.general.verbose = verbose;  // Override if present
    }
    // Unset fields retain previous values
}
```

This means you can set organization defaults in `/etc/dcg/config.toml`, personal preferences in `~/.config/dcg/config.toml`, and project-specific overrides in `.dcg.toml`—each layer only needs to specify the settings that differ from defaults.

**Project-Specific Pack Configuration**:

The `[projects]` section allows different pack configurations for different repositories:

```toml
[projects."/home/user/work/production-api"]
packs = { enabled = ["database.postgresql", "cloud.aws"], disabled = [] }

[projects."/home/user/personal/experiments"]
packs = { enabled = [], disabled = ["core.git"] }  # More permissive for experiments
```

### Fail-Open Philosophy

dcg is designed with a **fail-open** philosophy: when the tool cannot safely analyze a command (due to timeouts, parse errors, or resource limits), it allows the command to proceed rather than blocking it and breaking the user's workflow.

**Why Fail-Open?**

1. **Workflow Continuity**: A blocked legitimate command is more disruptive than a missed dangerous one
2. **Performance Guarantees**: The hook must never become a bottleneck
3. **Graceful Degradation**: Partial analysis is better than no analysis

**Fail-Open Scenarios**:

| Scenario | Behavior | Rationale |
|----------|----------|-----------|
| Parse error in heredoc | ALLOW + warn | Malformed input shouldn't block work |
| Extraction timeout | ALLOW + warn | Slow inputs shouldn't hang terminal |
| Size limit exceeded | ALLOW + fallback check | Large inputs get reduced analysis |
| Regex engine timeout | ALLOW + warn | Pathological patterns shouldn't block |
| AST matching error | Skip that heredoc | Continue evaluating other content |
| Deadline exceeded | ALLOW immediately | Hard cap prevents runaway processing |

**Configurable Strictness**:

For high-security environments, fail-open can be disabled:

```toml
[heredoc]
fallback_on_parse_error = false  # Block on parse errors
fallback_on_timeout = false      # Block on timeouts
```

With strict mode enabled, dcg will block commands when analysis fails, providing detailed error messages explaining why.

**Fallback Pattern Checking**:

Even when full analysis is skipped, dcg performs a lightweight fallback check for critical destructive patterns:

```rust
static FALLBACK_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"shutil\.rmtree",
        r"os\.remove",
        r"fs\.rmSync",
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f",
        r"\bgit\s+reset\s+--hard\b",
        // ... other critical patterns
    ])
});
```

This ensures that even oversized or malformed inputs are checked for the most dangerous operations before being allowed.

**Absolute Timeout**:

To prevent any single command from blocking indefinitely, dcg enforces an absolute maximum processing time of **200ms**. Any command exceeding this threshold is immediately allowed with a warning logged.

## Installation

### Quick Install (Recommended)

The easiest way to install is using the install script, which downloads a prebuilt binary for your platform:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

Easy mode automatically:
- Updates your PATH in shell rc files
- Removes the legacy Python predecessor (if present)
- Configures Claude Code hooks (creates config if needed)
- Configures Gemini CLI hooks (if Gemini CLI is installed)

**Other options:**

```bash
# Interactive mode (prompts for each step)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash

# Install specific version
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --version v0.1.0

# Install to /usr/local/bin (system-wide, requires sudo)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | sudo bash -s -- --system

# Build from source instead of downloading binary
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh?$(date +%s)" | bash -s -- --from-source
```

> **Note:** If you have [gum](https://github.com/charmbracelet/gum) installed, the installer will use it for fancy terminal formatting.

The install script:
- Automatically detects your OS and architecture
- Downloads the appropriate prebuilt binary
- Verifies SHA256 checksums for security
- Falls back to building from source if no prebuilt is available
- Detects and removes legacy Python predecessor (`git_safety_guard.py`)
- Configures Claude Code hooks (creates config directory if needed)
- Configures Gemini CLI hooks (if already installed)
- Offers to update your PATH

### From source (requires Rust nightly)

This project uses Rust Edition 2024 features and requires the nightly toolchain. The repository includes a `rust-toolchain.toml` that automatically selects the correct toolchain.

```bash
# Install Rust nightly if you don't have it
rustup install nightly

# Install directly from GitHub
cargo +nightly install --git https://github.com/Dicklesworthstone/destructive_command_guard
```

### Manual build

```bash
git clone https://github.com/Dicklesworthstone/destructive_command_guard
cd destructive_command_guard
# rust-toolchain.toml automatically selects nightly
cargo build --release
cp target/release/dcg ~/.local/bin/
```

## Updating

Run the built-in updater to re-run the installer for your platform:

```bash
dcg update
```

Optional flags mirror the installer scripts (examples):

```bash
dcg update --version v0.2.7
dcg update --system
dcg update --verify
```

You can always re-run `install.sh` / `install.ps1` directly if preferred.

### Prebuilt Binaries

Prebuilt binaries are available for:
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)
- macOS Intel (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)
- Windows (`x86_64-pc-windows-msvc`)

Download from [GitHub Releases](https://github.com/Dicklesworthstone/destructive_command_guard/releases) and verify the SHA256 checksum.

## Claude Code Configuration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "dcg"
          }
        ]
      }
    ]
  }
}
```

**Important:** Restart Claude Code after adding the hook configuration.

## Gemini CLI Configuration

Add to `~/.gemini/settings.json`:

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command",
        "hooks": [
          {
            "name": "dcg",
            "type": "command",
            "command": "dcg",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
```

**Important:** Restart Gemini CLI after adding the hook configuration.

> **Note:** OpenAI Codex CLI uses a different architecture (sandbox modes and approval policies) and does not support pre-execution hooks like dcg.

## CLI Usage

While primarily designed as a hook, the binary supports direct invocation for testing, debugging, and understanding why commands are blocked or allowed.

```bash
# Show version with build metadata
dcg --version

# Show help with blocked command categories
dcg --help

# Test a command manually (pipe JSON to stdin)
echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg
```

### Explain Mode

When you need to understand exactly why a command was blocked (or allowed), the `dcg explain` command provides a detailed trace of the decision-making process:

```bash
# Explain why a command is blocked
dcg explain "git reset --hard HEAD"

# Explain a safe command
dcg explain "git status"

# Explain with verbose timing information
dcg explain --verbose "rm -rf /tmp/build"

# Output as JSON for programmatic use
dcg explain --format json "kubectl delete namespace production"
```

JSON output is versioned via `schema_version` (currently 2). v2 adds
`matched_span`, `matched_text_preview`, and `explanation` in the `match`
object when a pattern is detected.

**Example Output**:

```
Command: git reset --hard HEAD
Normalized: git reset --hard HEAD

Decision: BLOCKED
  Pack: core.git
  Rule: reset-hard
  Reason: git reset --hard destroys uncommitted changes

Evaluation Trace:
  [  0.8μs] Quick reject: passed (contains 'git')
  [  2.1μs] Normalize: no changes
  [  5.3μs] Safe patterns: no match (checked 34 patterns)
  [ 12.7μs] Destructive patterns: MATCH at pattern 'reset-hard'
  [ 12.9μs] Total time: 12.9μs

Suggestion: Consider using 'git stash' first to save your changes.
```

The explain mode shows:
- **Normalized command**: How dcg sees the command after path normalization
- **Decision**: Whether the command would be blocked or allowed
- **Matching rule**: Which pack and pattern triggered the decision
- **Evaluation trace**: Step-by-step timing of each evaluation stage
- **Suggestion**: Actionable guidance for safer alternatives

This is invaluable for debugging false positives, understanding pack coverage, and verifying that custom allowlist entries work as expected.

### Allow-Once (Temporary Exceptions)

Sometimes you need to run a blocked command temporarily without permanently modifying your allowlist. The allow-once system provides short codes:

```bash
# When a command is blocked, dcg outputs a short code
# BLOCKED: git reset --hard HEAD
# Allow-once code: ab12
# To allow this: dcg allow-once ab12

# Use the short code to create a temporary exception
dcg allow-once ab12

# Or, use --single-use to make the exception one-shot
dcg allow-once ab12 --single-use
```

**How Allow-Once Works**:

1. When dcg blocks a command, it generates a short code (currently 4 hex chars; collisions are handled via `--pick` / `--hash`)
2. The code is tied to the exact command that was blocked
3. Running `dcg allow-once <code>` creates a temporary exception
4. The exception is stored in `~/.config/dcg/pending_exceptions.jsonl`
5. Exceptions expire after 24 hours (or after first use if `--single-use` is used)
6. While active, the exception allows the same command in the same directory scope

This workflow is useful for:
- One-time administrative operations that are intentionally destructive
- Migration scripts that need to reset state
- Emergency fixes where permanent allowlist changes aren't appropriate

**Security Considerations**:
- Short codes are derived from SHA256 (or optional HMAC-SHA256 when `DCG_ALLOW_ONCE_SECRET` is set)
- Codes are never logged or transmitted
- The pending exceptions file is readable only by the current user
- Expired codes are automatically cleaned up

The `--version` output includes build metadata for debugging:

```
dcg 0.1.0
  Built: 2026-01-07T22:13:10.413872881Z
  Rustc: 1.94.0-nightly
  Target: x86_64-unknown-linux-gnu
```

This metadata is embedded at compile time via [vergen](https://github.com/rustyhorde/vergen), making it easy to identify exactly which build is running when troubleshooting.

## Repository Scanning

While the hook protects **interactive** command execution, teams also need protection against destructive commands that get **committed into repositories**. The `dcg scan` command extracts executable command contexts from files and evaluates them using the same pattern engine.

### What Scan Is (and Is Not)

**What it is:**
- An extractor-based scanner that understands executable contexts
- Uses the same evaluator as hook mode for consistency
- Supports CI integration and pre-commit hooks

**What it is NOT:**
- A naive grep that matches strings everywhere
- A replacement for code review
- A static analysis tool for arbitrary languages

The key difference from grep: `dcg scan` understands that `"rm -rf /"` in a comment is data, not code. It uses extractors that understand file structure (shell scripts, Dockerfiles, GitHub Actions, Makefiles) to find only actually-executed commands.

### Supported File Formats

dcg scan includes specialized extractors for each file format, understanding which parts contain executable commands:

| File Type | Detection | Executable Contexts |
|-----------|-----------|---------------------|
| **Shell Scripts** | `*.sh`, `*.bash`, `*.zsh` | All non-comment, non-assignment lines |
| **Dockerfile** | `Dockerfile`, `*.dockerfile` | `RUN` instructions (shell and exec forms) |
| **GitHub Actions** | `.github/workflows/*.yml` | `run:` fields in steps |
| **GitLab CI** | `.gitlab-ci.yml` | `script:`, `before_script:`, `after_script:` |
| **Makefile** | `Makefile` | Tab-indented recipe lines |
| **Terraform** | `*.tf` | `provisioner` blocks (`local-exec`, `remote-exec`) |
| **Docker Compose** | `docker-compose.yml`, `compose.yml` | `command:` and `entrypoint:` fields |

**Context-Aware Extraction**:

Each extractor understands its format's semantics:

```yaml
# GitHub Actions - only 'run:' is extracted
- name: Build
  run: |                    # ← Extracted
    npm install
    npm run build
  env:
    NODE_ENV: production    # ← Skipped (not executable)
```

```dockerfile
# Dockerfile - only RUN instructions
FROM node:18
COPY . /app                 # ← Skipped
RUN npm install             # ← Extracted
RUN ["node", "server.js"]   # ← Extracted (exec form)
ENV PORT=3000               # ← Skipped
```

```makefile
# Makefile - tab-indented lines under targets
build:
	npm install             # ← Extracted (recipe line)
	npm run build           # ← Extracted
SOURCES = $(wildcard *.js)  # ← Skipped (variable assignment)
```

**Non-Executable Context Filtering**:

Extractors intelligently skip data-only sections:

- **Shell**: Assignment-only lines (`export VAR=value`)
- **YAML**: `environment:`, `labels:`, `volumes:`, `variables:` blocks
- **Terraform**: Everything outside `provisioner` blocks
- **All formats**: Comments (format-appropriate: `#`, `//`, etc.)

### Quick Start

```bash
# Install the pre-commit hook
dcg scan install-pre-commit

# Or manually run on staged files
dcg scan --staged

# Scan specific paths
dcg scan --paths scripts/ .github/workflows/
```

### Recommended Rollout Plan

**Start conservative to avoid developer friction:**

```bash
# Week 1-2: Warn-first with narrow scope
dcg scan --staged --fail-on error  # Only fail on catastrophic rules
```

Create `.dcg/hooks.toml` with conservative defaults:

```toml
[scan]
fail_on = "error"          # Only fail on high-confidence catastrophic rules
format = "pretty"          # Human-readable output
redact = "quoted"          # Hide sensitive strings
truncate = 120             # Shorten long commands

[scan.paths]
include = [
    ".github/workflows/**",  # Start with CI configs
    "Dockerfile",            # Container builds
    "Makefile",              # Build scripts
]
exclude = [
    "target/**",
    "node_modules/**",
    "vendor/**",
]
```

**Gradual expansion:**

1. **Week 1-2**: Start with workflows/Dockerfiles only, `--fail-on error`
2. **Week 3-4**: Add Makefiles and shell scripts in `scripts/`
3. **Month 2**: Add `--fail-on warning` after reviewing findings
4. **Ongoing**: Add new extractors as team confidence grows

### Pre-Commit Integration

#### One-Command Install

```bash
dcg scan install-pre-commit
```

This creates a `.git/hooks/pre-commit` that runs `dcg scan --staged`.

#### Manual Setup

If you prefer manual control or use a hook manager:

```bash
#!/bin/bash
# .git/hooks/pre-commit (or equivalent for your hook manager)

set -e

# Run dcg scan on staged files
dcg scan --staged --fail-on error

# Add other hooks below...
```

#### Uninstall

```bash
dcg scan uninstall-pre-commit
```

This only removes hooks installed by dcg (detected via sentinel comment).

### Interpreting Findings

The output includes:

```
scripts/deploy.sh:42:5: [ERROR] core.git:reset-hard
  Command: git reset --hard HEAD
  Reason: git reset --hard destroys uncommitted changes
  Suggestion: Consider using 'git stash' first to save changes.
```

- **File:Line:Col**: Location in the source file
- **Severity**: `ERROR` (catastrophic) or `WARNING` (concerning)
- **Rule ID**: Stable identifier like `core.git:reset-hard`
- **Command**: The extracted command (may be redacted/truncated)
- **Reason**: Why this command is flagged
- **Suggestion**: How to make it safer

### Fixing Findings

#### Option 1: Change the Code (Preferred)

Replace the dangerous command with a safer alternative:

```bash
# Instead of:
git reset --hard

# Use:
git stash push -m "before reset"
git reset --hard
```

#### Option 2: Understand with Explain

Get detailed analysis:

```bash
dcg explain "git reset --hard HEAD"
```

#### Option 3: Allowlist (When Intentional)

If the command is genuinely needed:

```bash
# Project-level allowlist (committed, code-reviewed)
dcg allowlist add core.git:reset-hard --reason "Required for CI cleanup" --project

# Or for a specific command
dcg allowlist add-command "rm -rf ./build" --reason "Build cleanup" --project
```

The finding output includes a copy-paste allowlist command for convenience.
Heredoc rules use stable IDs like `heredoc.python.shutil_rmtree`.

### Privacy and Redaction

Scan supports redaction of potentially sensitive content in output. Use `--redact quoted` to hide quoted strings that may contain secrets:

```
# Original command:
curl -H "Authorization: Bearer $TOKEN" https://api.example.com

# With --redact quoted:
curl -H "..." https://api.example.com
```

Options:
- `--redact none`: Show full commands (default)
- `--redact quoted`: Hide quoted strings (recommended for CI logs)
- `--redact aggressive`: Hide more potential secrets

### Configuration Reference

`.dcg/hooks.toml` (project-level, committed):

```toml
[scan]
# Exit non-zero when findings meet this threshold
fail_on = "error"      # Options: none, warning, error

# Output format
format = "pretty"      # Options: pretty, json, markdown

# Maximum file size to scan (bytes)
max_file_size = 1000000

# Stop after this many findings
max_findings = 50

# Redaction level for sensitive content
redact = "quoted"      # Options: none, quoted, aggressive

# Truncate long commands (chars; 0 = no truncation)
truncate = 120

[scan.paths]
# Only scan files matching these patterns
include = [
    "scripts/**",
    ".github/workflows/**",
    "Dockerfile*",
    "Makefile",
]

# Skip files matching these patterns
exclude = [
    "target/**",
    "node_modules/**",
    "*.md",
]
```

CLI flags override config file values.

### CI Integration

#### GitHub Actions

```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install dcg
        run: |
          curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh" | bash
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Scan changed files
        run: |
          dcg scan --git-diff origin/${{ github.base_ref }}..HEAD \
            --format markdown \
            --fail-on error
```

#### GitLab CI

```yaml
scan:
  stage: test
  script:
    - curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/master/install.sh" | bash
    - ~/.local/bin/dcg scan --git-diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME..HEAD --fail-on error
  rules:
    - if: $CI_MERGE_REQUEST_ID
```

### Bypass for Emergencies

If you need to bypass the pre-commit hook temporarily:

```bash
git commit --no-verify -m "Emergency fix"
```

This is logged and visible in git history. For permanent exceptions, use allowlists instead.

## How It Works

1. Claude Code invokes the hook before executing any Bash command
2. The hook receives the command as JSON on stdin
3. Commands are normalized (e.g., `/usr/bin/git` becomes `git`)
4. Safe patterns are checked first (whitelist approach)
5. Destructive patterns are checked second (blacklist approach)
6. If destructive: outputs JSON denial with explanation
7. If safe: exits silently (no output = allow)

The hook is designed for minimal latency with sub-millisecond execution on typical commands.

### Output Behavior

The hook uses two separate output channels:

- **stdout (JSON)**: The Claude Code hook protocol response. On denial, outputs JSON with `permissionDecision: "deny"`. On allow, outputs nothing.
- **stderr (colorful text)**: A human-readable warning when commands are blocked. Colors are automatically disabled when stderr is not a TTY (e.g., when piped to a file).

This dual-output design ensures the hook protocol works correctly while still providing immediate visual feedback to users watching the terminal.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                                                                  │
│  User: "delete the build artifacts"                             │
│  Agent: executes `rm -rf ./build`                               │
│                                                                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ PreToolUse hook (stdin: JSON)
┌─────────────────────────────────────────────────────────────────┐
│                     dcg                             │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │    Parse     │───▶│  Normalize   │───▶│ Quick Reject │       │
│  │    JSON      │    │   Command    │    │   Filter     │       │
│  └──────────────┘    └──────────────┘    └──────┬───────┘       │
│                                                  │               │
│                      ┌───────────────────────────┘               │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Pattern Matching                        │   │
│  │                                                           │   │
│  │   1. Check SAFE_PATTERNS (whitelist) ──▶ Allow if match  │   │
│  │   2. Check DESTRUCTIVE_PATTERNS ──────▶ Deny if match    │   │
│  │   3. No match ────────────────────────▶ Allow (default)  │   │
│  │                                                           │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼ stdout: JSON (deny) or empty (allow)
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                                                                  │
│  If denied: Shows block message, does NOT execute command       │
│  If allowed: Proceeds with command execution                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Context Classification System

Not every occurrence of a dangerous pattern is actually dangerous. The string `git reset --hard` appearing in a comment, a heredoc body, or a quoted string is fundamentally different from the same string appearing as an executed command. dcg uses a sophisticated context classification system to reduce false positives without compromising safety.

**SpanKind Classification**

Every token in a command is classified into one of these categories:

| SpanKind | Description | Treatment |
|----------|-------------|-----------|
| `Executed` | Command words and unquoted arguments | **MUST check** - highest priority |
| `InlineCode` | Content inside `-c`/`-e` flags (bash -c, python -c) | **MUST check** - code will be executed |
| `Argument` | Quoted arguments to known-safe commands | Lower priority, context-dependent |
| `Data` | Single-quoted strings (shell cannot interpolate) | **Can skip** - treated as literal data |
| `HeredocBody` | Content inside heredocs | Escalated to Tier 2/3 heredoc scanning |
| `Comment` | Shell comments (`# ...`) | **Skip** - never executed |
| `Unknown` | Cannot determine context | Conservative treatment as `Executed` |

**Why Context Matters**

Consider these commands:

```bash
# Safe: the dangerous pattern is in a comment
echo "Reminder: never run git reset --hard"   # git reset --hard destroys changes

# Safe: the dangerous pattern is data being searched for
grep "git reset --hard" documentation.md

# Safe: the dangerous pattern is in a heredoc being written to a file
cat <<EOF > safety_guide.md
Warning: git reset --hard destroys uncommitted changes
EOF

# DANGEROUS: the pattern will be executed
git reset --hard HEAD

# DANGEROUS: the pattern is passed to bash -c for execution
bash -c "git reset --hard"
```

Without context classification, the first three examples would trigger false positives. The context classifier analyzes the AST (abstract syntax tree) structure to understand where patterns appear and only flags genuinely dangerous occurrences.

**Implementation Details**

The context classifier uses a multi-pass approach:

1. **Lexical Analysis**: Identify quoted strings, comments, and heredoc markers
2. **Structural Analysis**: Build a tree of command structure, identifying pipes, subshells, and command substitutions
3. **Flag Analysis**: Detect `-c`, `-e`, and similar flags that introduce inline code contexts
4. **Span Annotation**: Tag each character range with its SpanKind

This approach achieves a significant reduction in false positives while maintaining the zero-false-negatives philosophy for actual command execution.

### Processing Pipeline

**Stage 1: JSON Parsing**
- Reads the hook input from stdin
- Validates the structure matches Claude Code's `PreToolUse` format
- Extracts the command string from `tool_input.command`
- Non-Bash tools are immediately allowed (no output)

**Stage 2: Command Normalization**
- Strips absolute paths from `git` and `rm` binaries
- `/usr/bin/git status` → `git status`
- `/bin/rm -rf /tmp/foo` → `rm -rf /tmp/foo`
- Uses regex with lookahead to preserve arguments containing paths

**Stage 3: Quick Rejection Filter**
- O(n) substring search for "git" or "rm" in the command
- Commands without these substrings bypass regex matching entirely
- Handles 99%+ of non-destructive commands (ls, cat, cargo, npm, etc.)

**Stage 4: Pattern Matching**
- Safe patterns checked first (short-circuit on match → allow)
- Destructive patterns checked second (match → deny with reason)
- No match on either → default allow

## Design Principles

### 1. Whitelist-First Architecture

Safe patterns are checked *before* destructive patterns. This design ensures that explicitly safe commands (like `git checkout -b`) are never accidentally blocked, even if they partially match a destructive pattern (like `git checkout`).

```
git checkout -b feature    →  Matches SAFE "checkout-new-branch"  →  ALLOW
git checkout -- file.txt   →  No safe match, matches DESTRUCTIVE  →  DENY
```

### 2. Fail-Safe Defaults

The hook uses a **default-allow** policy for unrecognized commands. This ensures:
- The hook never breaks legitimate workflows
- Only *known* dangerous patterns are blocked
- New git commands are allowed until explicitly categorized

### 3. Zero False Negatives Philosophy

The pattern set prioritizes **never allowing dangerous commands** over avoiding false positives. A few extra prompts for manual confirmation are acceptable; lost work is not.

### 4. Defense in Depth

This hook is one layer of protection. It complements (not replaces):
- Regular commits and pushes
- Git stash before risky operations
- Proper backup strategies
- Code review processes

### 5. Minimal Latency

Every Bash command passes through this hook. Performance is critical:
- Lazy-initialized static regex patterns (compiled once, reused)
- Quick rejection filter eliminates 99%+ of commands before regex
- No heap allocations on the hot path for safe commands
- Sub-millisecond execution for typical commands

## Pattern Matching System

### Safe Patterns (Whitelist)

The safe pattern list contains 34 patterns covering:

| Category | Patterns | Purpose |
|----------|----------|---------|
| Branch creation | `checkout -b`, `checkout --orphan` | Creating branches is safe |
| Staged-only | `restore --staged`, `restore -S` | Unstaging doesn't touch working tree |
| Dry run | `clean -n`, `clean --dry-run` | Preview mode, no actual deletion |
| Temp cleanup | `rm -rf /tmp/*`, `rm -rf /var/tmp/*` | Ephemeral directories are safe |
| Variable expansion | `rm -rf $TMPDIR/*`, `rm -rf ${TMPDIR}/*` | Shell variable forms |
| Quoted paths | `rm -rf "$TMPDIR/*"` | Quoted variable forms |
| Separate flags | `rm -r -f /tmp/*`, `rm -r -f $TMPDIR/*` | Flag ordering variants |
| Long flags | `rm --recursive --force /tmp/*`, `$TMPDIR/*` | GNU-style long options |

### Destructive Patterns (Blacklist)

The destructive pattern list contains 16 patterns covering:

| Category | Pattern | Reason |
|----------|---------|--------|
| Work destruction | `reset --hard`, `reset --merge` | Destroys uncommitted changes |
| File reversion | `checkout -- <path>` | Discards file modifications |
| Worktree restore | `restore` (without --staged) | Discards uncommitted changes |
| Untracked deletion | `clean -f` | Permanently removes untracked files |
| History rewrite | `push --force`, `push -f` | Can destroy remote commits |
| Unsafe branch delete | `branch -D` | Force-deletes without merge check |
| Stash destruction | `stash drop`, `stash clear` | Permanently deletes stashed work |
| Filesystem nuke | `rm -rf` (non-temp paths) | Recursive deletion outside temp |

### Pattern Syntax

Patterns use [fancy-regex](https://github.com/fancy-regex/fancy-regex) for advanced features:

```rust
// Negative lookahead: block restore UNLESS --staged is present
r"git\s+restore\s+(?!--staged\b)(?!-S\b)"

// Negative lookahead: don't match --force-with-lease
r"git\s+push\s+.*--force(?![-a-z])"

// Character class: match any flag ordering
r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*"
```

## Edge Cases Handled

### Path Normalization

Commands may use absolute paths to binaries:

```bash
/usr/bin/git reset --hard          # Blocked ✓
/usr/local/bin/git checkout -- .   # Blocked ✓
/bin/rm -rf /home/user             # Blocked ✓
```

The normalizer uses regex to strip paths while preserving arguments:

```bash
git add /usr/bin/something         # "/usr/bin/something" is an argument, preserved
```

### Flag Ordering Variants

The `rm` command accepts flags in many forms:

```bash
rm -rf /path          # Combined flags
rm -fr /path          # Reversed order
rm -r -f /path        # Separate flags
rm -f -r /path        # Separate, reversed
rm --recursive --force /path    # Long flags
rm --force --recursive /path    # Long flags, reversed
rm -rf --no-preserve-root /     # Additional flags
```

All variants are handled by flexible regex patterns.

### Shell Variable Expansion

Temp directory variables come in multiple forms:

```bash
rm -rf $TMPDIR/build           # Unquoted, simple
rm -rf ${TMPDIR}/build         # Unquoted, braced
rm -rf "$TMPDIR/build"         # Quoted, simple
rm -rf "${TMPDIR}/build"       # Quoted, braced
rm -rf "${TMPDIR:-/tmp}/build" # With default value
```

### Git Flag Combinations

Git commands can have flags in various positions:

```bash
git push --force                  # Blocked ✓
git push origin main --force      # Blocked ✓
git push --force origin main      # Blocked ✓
git push -f                       # Blocked ✓
git push --force-with-lease       # Allowed ✓ (safe alternative)
```

### Staged vs Worktree Restore

The restore command has nuanced safety:

```bash
git restore --staged file.txt           # Allowed ✓ (unstaging only)
git restore -S file.txt                 # Allowed ✓ (short flag)
git restore file.txt                    # Blocked (discards changes)
git restore --worktree file.txt         # Blocked (explicit worktree)
git restore --staged --worktree file    # Blocked (includes worktree)
git restore -S -W file.txt              # Blocked (includes worktree)
```

## Performance Optimizations

### Dual Regex Engine Architecture

dcg uses a sophisticated dual-engine regex system that automatically selects the optimal engine for each pattern. This enables both guaranteed performance and advanced pattern matching features.

**The Two Engines**:

| Engine | Crate | Time Complexity | Features | Use Case |
|--------|-------|-----------------|----------|----------|
| **Linear** | `regex` | O(n) guaranteed | Basic regex, character classes, alternation | ~85% of patterns |
| **Backtracking** | `fancy_regex` | O(2^n) worst case | Lookahead, lookbehind, backreferences | ~15% of patterns |

**Automatic Engine Selection**:

When a pattern is compiled, dcg analyzes it to determine which engine to use:

```rust
pub enum CompiledRegex {
    Linear(regex::Regex),           // O(n) guaranteed, no lookahead
    Backtracking(fancy_regex::Regex), // Supports lookahead/lookbehind
}

impl CompiledRegex {
    pub fn new(pattern: &str) -> Result<Self, Error> {
        // Try linear engine first (faster, predictable)
        if let Ok(re) = regex::Regex::new(pattern) {
            return Ok(CompiledRegex::Linear(re));
        }
        // Fall back to backtracking for advanced features
        Ok(CompiledRegex::Backtracking(fancy_regex::Regex::new(pattern)?))
    }
}
```

**Why This Matters**:

1. **Performance predictability**: The linear engine guarantees O(n) matching time, critical for a hook that runs on every command
2. **Feature completeness**: Some patterns require negative lookahead (e.g., "match `--force` but not `--force-with-lease`")
3. **Automatic optimization**: Pattern authors don't need to think about engine selection—dcg chooses optimally

**Examples of Engine Selection**:

```rust
// Linear engine (simple pattern)
r"git\s+reset\s+--hard"              // No advanced features needed

// Backtracking engine (negative lookahead)
r"git\s+push\s+.*--force(?![-a-z])"  // Must NOT be followed by "-with-lease"

// Linear engine (character classes)
r"rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f"     // Complex but no lookahead
```

### Performance Budget System

dcg operates under strict latency constraints—every Bash command passes through the hook, so even small delays compound into noticeable sluggishness. The performance budget system enforces these constraints with fail-open semantics.

**Latency Tiers**:

| Tier | Stage | Target | Warning | Panic |
|------|-------|--------|---------|-------|
| 0 | Quick Reject | < 1μs | > 10μs | > 50μs |
| 1 | Normalization | < 5μs | > 25μs | > 100μs |
| 2 | Safe Pattern Check | < 50μs | > 200μs | > 500μs |
| 3 | Destructive Pattern Check | < 50μs | > 200μs | > 500μs |
| 4 | Heredoc Extraction | < 1ms | > 5ms | > 20ms |
| 5 | Heredoc Evaluation | < 2ms | > 10ms | > 30ms |
| 6 | Full Pipeline | < 5ms | > 15ms | > 50ms |

**Fail-Open Behavior**:

If any stage exceeds its panic threshold, dcg logs a warning and **allows the command**:

```
[WARN] Performance budget exceeded: Tier 2 (safe patterns) took 1.2ms (panic threshold: 500μs)
[WARN] Failing open to avoid blocking workflow
```

This design ensures that:
1. A pathological input cannot hang the user's terminal
2. Performance regressions are visible in logs
3. The tool never becomes a productivity bottleneck

**Budget Enforcement**:

```rust
fn check_budget(tier: Tier, elapsed: Duration) -> BudgetResult {
    let budget = TIER_BUDGETS[tier];
    if elapsed > budget.panic {
        log::warn!("Tier {} exceeded panic threshold", tier);
        return BudgetResult::FailOpen;
    }
    if elapsed > budget.warning {
        log::warn!("Tier {} exceeded warning threshold", tier);
    }
    BudgetResult::Continue
}
```

**Monitoring Performance**:

Use `dcg explain --verbose` to see per-stage timing:

```
Evaluation Trace:
  [  0.3μs] Tier 0: Quick reject (PASS - below 1μs target)
  [  1.2μs] Tier 1: Normalize (PASS - below 5μs target)
  [  8.7μs] Tier 2: Safe patterns (PASS - below 50μs target)
  [ 15.2μs] Tier 3: Destructive patterns (PASS - below 50μs target)
  [ 15.4μs] Total: 15.4μs (PASS - below 5ms target)
```

### Keyword-Based Pack Pre-filtering

Before expensive regex matching, dcg uses a multi-level keyword filtering system to quickly skip irrelevant packs. This is critical for performance—with 49+ packs available, checking every pattern against every command would be prohibitively slow.

**How Keyword Filtering Works**:

Each pack declares a set of keywords that must appear in a command for that pack to be relevant:

```rust
Pack {
    id: "database.postgresql".to_string(),
    keywords: &["psql", "dropdb", "createdb", "DROP", "TRUNCATE", "DELETE"],
    // ...
}
```

**Two-Level Filtering**:

1. **Global Quick Reject**: Before any pack evaluation, dcg checks if the command contains *any* keyword from *any* enabled pack. If not, the entire pack evaluation is skipped.

2. **Per-Pack Quick Reject**: For each enabled pack, dcg checks if the command contains any of that pack's keywords before running expensive regex patterns.

**Aho-Corasick Automaton**:

For packs with multiple keywords, dcg builds an [Aho-Corasick automaton](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) that matches all keywords in a single O(n) pass:

```rust
// Built lazily on first pack access
pub keyword_matcher: Option<aho_corasick::AhoCorasick>,

pub fn might_match(&self, cmd: &str) -> bool {
    if self.keywords.is_empty() {
        return true; // No keywords = always check patterns
    }

    // O(n) matching regardless of keyword count
    if let Some(ref ac) = self.keyword_matcher {
        return ac.is_match(cmd);
    }

    // Fallback: sequential memchr search
    self.keywords.iter()
        .any(|kw| memmem::find(cmd.as_bytes(), kw.as_bytes()).is_some())
}
```

**Context-Aware Keyword Matching**:

Keywords are only matched within executable spans (not in comments, quoted strings, or data):

```rust
pub fn pack_aware_quick_reject(cmd: &str, enabled_keywords: &[&str]) -> bool {
    // First: fast substring check
    let any_substring = enabled_keywords.iter()
        .any(|kw| memmem::find(cmd.as_bytes(), kw.as_bytes()).is_some());

    if !any_substring {
        return true; // Safe to skip all pack evaluation
    }

    // Second: verify keyword appears in executable context
    let spans = classify_command(cmd);
    for span in spans.executable_spans() {
        if span_matches_any_keyword(span.text(cmd), enabled_keywords) {
            return false; // Must evaluate packs
        }
    }

    true // Keywords only in non-executable contexts, safe to skip
}
```

This approach ensures that a command like `echo "psql" | grep DROP` doesn't trigger PostgreSQL pack evaluation just because keywords appear in the data being processed.

### 1. Lazy Static Initialization

Regex patterns are compiled once on first use via `LazyLock`:

```rust
static SAFE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern!("checkout-new-branch", r"git\s+checkout\s+-b\s+"),
        // ... 33 more patterns
    ]
});
```

Subsequent invocations reuse the compiled patterns with zero compilation overhead.

### 2. SIMD-Accelerated Quick Rejection

Before any regex matching, a SIMD-accelerated substring search filters out irrelevant commands. The [memchr](https://github.com/BurntSushi/memchr) crate uses CPU vector instructions (SSE2, AVX2, NEON) when available:

```rust
use memchr::memmem;

static GIT_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("git"));
static RM_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new("rm"));

fn quick_reject(cmd: &str) -> bool {
    let bytes = cmd.as_bytes();
    GIT_FINDER.find(bytes).is_none() && RM_FINDER.find(bytes).is_none()
}
```

For commands like `ls -la`, `cargo build`, or `npm install`, this check short-circuits the entire matching pipeline. The `memmem::Finder` is pre-compiled once and reused, avoiding repeated setup costs.

### 3. Early Exit on Safe Match

Safe patterns are checked first. On match, the function returns immediately without checking destructive patterns:

```rust
for pattern in SAFE_PATTERNS.iter() {
    if pattern.regex.is_match(&normalized).unwrap_or(false) {
        return;  // Allow immediately
    }
}
```

### 4. Compile-Time Pattern Validation

The `pattern!` and `destructive!` macros include the pattern name in panic messages, making invalid patterns fail at first execution with clear diagnostics:

```rust
macro_rules! pattern {
    ($name:literal, $re:literal) => {
        Pattern {
            regex: Regex::new($re).expect(concat!("pattern '", $name, "' should compile")),
            name: $name,
        }
    };
}
```

### 5. Zero-Copy JSON Parsing

The `serde_json` parser operates on the input buffer without unnecessary copies. The command string is extracted directly from the parsed JSON value.

### 6. Zero-Allocation Path Normalization

Command normalization uses `Cow<str>` (copy-on-write) to avoid heap allocations in the common case:

```rust
fn normalize_command(cmd: &str) -> Cow<'_, str> {
    // Fast path: if command doesn't start with '/', no normalization needed
    if !cmd.starts_with('/') {
        return Cow::Borrowed(cmd);  // Zero allocation
    }
    PATH_NORMALIZER.replace(cmd, "$1")  // Allocation only when path is stripped
}
```

Most commands don't use absolute paths to `git` or `rm`, so this fast path avoids allocation entirely for 99%+ of inputs.

### 7. Release Profile Optimization

The release build uses aggressive optimization settings:

```toml
[profile.release]
opt-level = "z"     # Optimize for size (lean binary)
lto = true          # Link-time optimization across crates
codegen-units = 1   # Single codegen unit for better optimization
panic = "abort"     # Smaller binary, no unwinding overhead
strip = true        # Remove debug symbols
```

## Example Block Message

When a destructive command is intercepted, the hook outputs a colorful warning to stderr (shown below without ANSI codes):

```
════════════════════════════════════════════════════════════════════════
BLOCKED  dcg
────────────────────────────────────────────────────────────────────────
Reason:  git reset --hard destroys uncommitted changes. Use 'git stash' first.

Command:  git reset --hard HEAD~1

Tip: If you need to run this command, execute it manually in a terminal.
     Consider using 'git stash' first to save your changes.
════════════════════════════════════════════════════════════════════════
```

### Suggestion System

dcg doesn't just block commands—it provides actionable guidance to help users make safer choices. The suggestion system generates context-aware recommendations based on the specific command that was blocked.

**Suggestion Categories**:

| Category | Purpose | Example |
|----------|---------|---------|
| `PreviewFirst` | Run a dry-run/preview command first | "Run `git clean -n` first to preview deletions" |
| `SaferAlternative` | Use a safer command that achieves similar goals | "Use `--force-with-lease` instead of `--force`" |
| `WorkflowFix` | Fix the workflow to avoid the dangerous operation | "Commit your changes before resetting" |
| `Documentation` | Link to relevant documentation | "See `man git-reset` for reset options" |
| `AllowSafely` | How to allowlist if the operation is intentional | "Add to allowlist: `dcg allowlist add core.git:reset-hard`" |

**Contextual Suggestions by Command Type**:

| Command Type | Suggestion |
|-------------|------------|
| `git reset`, `git checkout --` | "Consider using 'git stash' first to save your changes." |
| `git clean` | "Use 'git clean -n' first to preview what would be deleted." |
| `git push --force` | "Consider using '--force-with-lease' for safer force pushing." |
| `rm -rf` | "Verify the path carefully before running rm -rf manually." |
| `kubectl delete` | "Use `kubectl delete --dry-run=client` to preview deletions." |
| `docker system prune` | "Run with `--dry-run` first to see what would be removed." |
| `DROP TABLE` | "Consider `TRUNCATE` if you only need to remove data, not the schema." |

**Custom Suggestions in Packs**:

Each destructive pattern can specify its own suggestion tailored to the specific operation:

```rust
destructive_pattern!(
    "restic-forget",
    r"restic(?:\s+--?\S+(?:\s+\S+)?)*\s+forget\b",
    "restic forget removes snapshots and can permanently delete backup data.",
    suggestion: "Run 'restic snapshots' first to review what would be affected."
)
```

This approach ensures that suggestions are always relevant to the specific context, not generic warnings.

Simultaneously, the hook outputs JSON to stdout for the Claude Code protocol:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "BLOCKED by dcg\n\nReason: ..."
  }
}
```

## Security Considerations

### What This Protects Against

- **Accidental data loss**: AI agents running `git checkout --` or `git reset --hard` on files with uncommitted changes
- **Remote history destruction**: Force pushes that overwrite shared branch history
- **Stash loss**: Dropping or clearing stashes containing important work-in-progress
- **Filesystem accidents**: Recursive deletion outside designated temp directories

### Inherent Limitations

While dcg provides comprehensive protection across many tools and platforms, some attack vectors are inherently difficult or impossible to protect against:
- **Malicious actors**: A determined attacker can bypass this hook
- **Non-Bash commands**: Direct file writes via Python/JavaScript, API calls, etc. are not intercepted
- **Committed but unpushed work**: The hook doesn't prevent loss of local-only commits
- **Bugs in allowed commands**: A `git commit` that accidentally includes wrong files
- **Commands in scripts**: If an agent runs `./deploy.sh`, we don't inspect what's inside the script

### Threat Model

This hook assumes the AI agent is **well-intentioned but fallible**. It's designed to catch honest mistakes, not adversarial attacks. The hook runs with the same permissions as the Claude Code process.

## Troubleshooting

### Hook not blocking commands

1. **Check hook registration**: Verify `~/.claude/settings.json` contains the hook configuration
2. **Restart Claude Code**: Configuration changes require a restart
3. **Check binary location**: Ensure `dcg` is in your PATH
4. **Test manually**: Run `echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg`

### Hook blocking safe commands

1. **Check for false positives**: Some edge cases may not be covered by safe patterns
2. **File an issue**: Report the command that was incorrectly blocked
3. **Temporary bypass**: Have the user run the command manually in a separate terminal
4. **Add to allowlist**: Use the allowlist feature below for persistent overrides

### Resolving False Positives with Allowlists

If dcg blocks a command that is safe in your specific context, you can add it to an allowlist. Allowlists support three layers (checked in order):

1. **Project** (`.dcg/allowlist.toml`): Applies only to the current project
2. **User** (`~/.config/dcg/allowlist.toml`): Applies to all your projects
3. **System** (`/etc/dcg/allowlist.toml`): Applies system-wide

**Adding a rule to the allowlist:**

```bash
# Allow a specific rule by ID (recommended)
dcg allowlist add core.git:reset-hard -r "Used for CI cleanup"

# Allow at project level (default if in a git repo)
dcg allowlist add core.git:reset-hard -r "CI cleanup" --project

# Add to user-level allowlist instead
dcg allowlist add core.git:reset-hard -r "Personal workflow" --user

# Allow with expiration (ISO 8601 format)
dcg allowlist add core.git:clean-force -r "Migration" --expires "2026-02-01T00:00:00Z"

# Allow a specific command (exact match) using add-command
dcg allowlist add-command "rm -rf ./build" -r "Build cleanup"
```

**Listing allowlist entries:**

```bash
# List all entries from all layers
dcg allowlist list

# List project allowlist only
dcg allowlist list --project

# List user allowlist only
dcg allowlist list --user

# Output as JSON
dcg allowlist list --format json
```

**Removing entries:**

```bash
# Remove a rule by ID
dcg allowlist remove core.git:reset-hard

# Remove from project allowlist specifically
dcg allowlist remove core.git:reset-hard --project
```

**Validating allowlist files:**

```bash
# Check for issues (expired entries, invalid patterns)
dcg allowlist validate

# Strict mode: treat warnings as errors
dcg allowlist validate --strict
```

**Example allowlist.toml:**

```toml
[[allow]]
rule = "core.git:reset-hard"
reason = "Used for CI pipeline cleanup"
added_at = "2026-01-08T12:00:00Z"

[[allow]]
exact_command = "rm -rf ./build"
reason = "Safe build directory cleanup"
added_at = "2026-01-08T12:00:00Z"
expires_at = "2026-02-08T12:00:00Z"  # Optional expiration

[[allow]]
pattern = "rm -rf .*/build"
reason = "Build directories across projects"
risk_acknowledged = true  # Required for pattern-based entries
added_at = "2026-01-08T12:00:00Z"
```

### Performance issues

1. **Check pattern count**: Excessive custom patterns can slow matching
2. **Profile with `--release`**: Debug builds are significantly slower
3. **Check stdin buffering**: Slow JSON input can delay processing

## Running Tests

### Unit Tests

```bash
cargo test
```

The test suite includes 80+ tests covering:

- **normalize_command_tests**: Path stripping for git and rm binaries
- **quick_reject_tests**: Fast-path filtering for non-git/rm commands
- **safe_pattern_tests**: Whitelist accuracy for all safe pattern variants
- **destructive_pattern_tests**: Blacklist coverage for all dangerous commands
- **input_parsing_tests**: JSON parsing robustness and edge cases
- **deny_output_tests**: Output format validation
- **integration_tests**: End-to-end pipeline verification

### Test with Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
```

### End-to-End Testing

The repository includes a comprehensive E2E test script with 120 test cases:

```bash
# Run full E2E test suite
./scripts/e2e_test.sh

# With verbose output
./scripts/e2e_test.sh --verbose

# With specific binary path
./scripts/e2e_test.sh --binary ./target/release/dcg
```

The E2E suite covers:
- All destructive git commands (reset, checkout, restore, clean, push, branch, stash)
- All safe git commands (status, log, diff, add, commit, push, branch -d)
- Filesystem commands (rm -rf with various paths and flag orderings)
- Absolute path handling (`/usr/bin/git`, `/bin/rm`)
- Non-Bash tools (Read, Write, Edit, Grep, Glob)
- Malformed JSON input (empty, missing fields, invalid syntax)
- Edge cases (sudo prefixes, quoted paths, variable expansion)

## Continuous Integration

The project uses GitHub Actions for CI/CD:

### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and pull request:

- **Formatting check**: `cargo fmt --check`
- **Clippy lints**: `cargo clippy --all-targets -- -D warnings` (pedantic + nursery enabled)
- **Compilation check**: `cargo check --all-targets`
- **Unit tests**: `cargo nextest run` with JUnit XML reports
- **Coverage**: `cargo llvm-cov` with LCOV output

### Release Workflow (`.github/workflows/dist.yml`)

Triggered on version tags (`v*`):

- Builds optimized binaries for 5 platforms:
  - Linux x86_64 (`x86_64-unknown-linux-gnu`)
  - Linux ARM64 (`aarch64-unknown-linux-gnu`)
  - macOS Intel (`x86_64-apple-darwin`)
  - macOS Apple Silicon (`aarch64-apple-darwin`)
  - Windows (`x86_64-pc-windows-msvc`)
- Creates `.tar.xz` archives (Unix) or `.zip` (Windows)
- Generates SHA256 checksums for verification
- Publishes to GitHub Releases with auto-generated release notes

To create a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## FAQ

**Q: Why block `git branch -D` but allow `git branch -d`?**

The lowercase `-d` only deletes branches that have been fully merged. The uppercase `-D` force-deletes regardless of merge status, potentially losing commits that exist only on that branch.

**Q: Why is `git push --force-with-lease` allowed?**

Force-with-lease is a safer alternative that refuses to push if the remote has commits you haven't seen. It prevents accidentally overwriting someone else's work.

**Q: Why block all `rm -rf` outside temp directories?**

Recursive forced deletion is one of the most dangerous filesystem operations. Even with good intentions, a typo or wrong variable expansion can delete critical files. Temp directories are designed to be ephemeral.

**Q: Can I add custom patterns?**

Currently, patterns are compiled into the binary. For custom patterns, fork the repository and modify `SAFE_PATTERNS` or `DESTRUCTIVE_PATTERNS` in `src/main.rs`.

**Q: What if I really need to run a blocked command?**

The block message instructs the AI to ask you for explicit permission. You can then run the command manually in a separate terminal, ensuring you've made a conscious decision.

**Q: Does this work with other AI coding tools?**

The hook is designed for Claude Code's `PreToolUse` hook protocol. Other tools would need adapters to match the expected JSON input/output format.

**Q: What about database, Docker, Kubernetes, and cloud commands?**

dcg already includes comprehensive packs for all of these! The modular pack system covers databases (PostgreSQL, MySQL, MongoDB, Redis, SQLite), containers (Docker, Podman, docker-compose), Kubernetes (kubectl, Helm, Kustomize), and all major cloud providers (AWS, GCP, Azure) including their container registries, secrets management services, and logging infrastructure. Enable the packs you need in your config. If you encounter a destructive command that should be blocked, please file an issue.

## Contributing

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

MIT

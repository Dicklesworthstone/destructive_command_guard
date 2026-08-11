# dcg (Destructive Command Guard)

<div align="center">
  <img src="illustration.webp" alt="Destructive Command Guard - Protecting your code from accidental destruction">
</div>

<div align="center">

[![Coverage](https://img.shields.io/codecov/c/github/Dicklesworthstone/destructive_command_guard?label=coverage)](https://codecov.io/gh/Dicklesworthstone/destructive_command_guard)
[![License: custom](https://img.shields.io/badge/license-custom-blue.svg)](LICENSE)

</div>

A high-performance hook for AI coding agents that blocks destructive commands before they execute, protecting your work from accidental deletion across Claude Code, Codex CLI, Gemini CLI, Copilot CLI, VS Code Copilot Chat, Cursor, Hermes Agent, Grok (xAI), Posit Assistant, and related tools.

**Supported:** [Claude Code](https://claude.ai/code), [Codex CLI 0.125.0+](https://github.com/openai/codex), [Gemini CLI](https://github.com/google-gemini/gemini-cli), [GitHub Copilot CLI](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-hooks), [VS Code Copilot Chat](https://code.visualstudio.com/docs/agent-customization/hooks), [Cursor IDE](https://cursor.com), [Hermes Agent](https://github.com/NousResearch/hermes-agent), [Posit Assistant](https://positron.posit.co/assistant/) (Positron/RStudio extension, standalone server, and `pa` terminal client), [Grok (xAI)](https://x.ai/news/grok-build-cli) (native `~/.grok/hooks/` plus Claude compatibility layer), [Antigravity CLI (`agy`)](https://antigravity.google) (native `~/.gemini/config/hooks.json` via `dcg install --agy`), [OpenCode](https://opencode.ai) (via [community plugin](https://github.com/aspiers/ai-config/blob/main/.config/opencode/plugins/dcg-guard.js)), [Pi](https://github.com/earendil-works/pi) (via [extension recipe](docs/pi-integration.md)), [Aider](https://aider.chat/) (limited—git hooks only), [Continue](https://continue.dev) (detection only)

<div align="center">
<h3>Quick Install</h3>

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

<p><em>Works on Linux, macOS, and Windows via WSL. Auto-detects your platform, downloads the right binary, and configures supported agent hooks including Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, VS Code Copilot Chat (through VS Code's Claude-hook compatibility), Cursor IDE, Hermes Agent, Posit Assistant, and Grok (xAI) (via <code>dcg install --grok</code> for a native <code>~/.grok/hooks/dcg.json</code>, or via the Claude compatibility layer automatically picked up by Grok). For native Windows, use the PowerShell installer below.</em></p>

<h4>Windows (native, PowerShell)</h4>

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.ps1"))) -EasyMode -Verify
```

<p><em>Installs native <code>dcg.exe</code>, verifies the mandatory SHA256 checksum, verifies the release's long-lived minisign signature when <code>minisign</code> is available, and verifies Sigstore/cosign provenance when both <code>cosign</code> and a trusted bundle are available. It adds dcg to your User <code>PATH</code> (<code>-EasyMode</code>), runs a self-test (<code>-Verify</code>), and configures detected agent hooks for Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, Cursor IDE, Hermes Agent, and Posit Assistant. Copilot is configured at the user level under <code>%COPILOT_HOME%\hooks</code> (or <code>%USERPROFILE%\.copilot\hooks</code>) so every workspace is protected. On Windows the <code>windows.filesystem</code> and <code>windows.system</code> packs are on by default, so <code>del /s</code>, <code>rd /s</code>, <code>Remove-Item -Recurse</code> (with or without <code>-Force</code>), <code>format</code>, and <code>vssadmin delete shadows</code> are blocked out of the box. Pin a version with <code>-Version vX.Y.Z</code>; use <code>-RequireMinisign</code> to fail closed if the sidecar or verifier is unavailable.</em></p>
</div>

---

## TL;DR

**The Problem**: AI coding agents (Claude, Codex, Gemini, Copilot, etc.) occasionally run catastrophic commands like `git reset --hard`, `rm -rf ./src`, or `DROP TABLE users`—destroying hours of uncommitted work in seconds.

**The Solution**: dcg is a high-performance hook that intercepts destructive commands *before* they execute, blocking them with clear explanations and safer alternatives.

### Why Use dcg?

| Feature | What It Does |
|---------|--------------|
| **Zero-Config Protection** | Blocks dangerous git/filesystem commands out of the box |
| **50+ Security Packs** | Databases, Kubernetes, Docker, AWS/GCP/Azure, Terraform, and more |
| **Sub-Millisecond Latency** | SIMD-accelerated filtering—you won't notice it's there |
| **Heredoc/Inline Script Scanning** | Catches `python -c "os.remove(...)"` and embedded shell scripts |
| **Smart Context Detection** | Won't block `grep "rm -rf"` (data) but will block `rm -rf /` (execution) |
| **Rich Terminal Output** | Human-readable denial panels, rule context, and suggestions on stderr |
| **Agent-Safe Streams** | Machine-readable hook output stays on stdout while rich UI stays on stderr |
| **Native Codex Support** | Codex CLI 0.125.0+ receives a minimal stdout JSON denial that current clients enforce reliably |
| **Graceful Degradation** | Plain output for CI, pipes, dumb terminals, and no-color environments |
| **Scan Mode for CI** | Pre-commit hooks and CI integration to catch dangerous commands in code review |
| **Bounded Failure Policy** | Analysis timeouts become explicit review/block outcomes; malformed raw hook envelopes remain auditable and configurable |
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

### Agent-Specific Profiles

dcg automatically detects which AI coding agent is invoking it and can apply
agent-specific configuration. The `trust_level` field is an **advisory label**
recorded in JSON output and logs — it does not directly change rule evaluation.
Behavioral differences come from the other profile fields:

| Option | Effect |
|--------|--------|
| `disabled_packs` | Removes rule packs from evaluation |
| `extra_packs` | Adds rule packs to evaluation |
| `additional_allowlist` | Adds command patterns that bypass deny rules |
| `disabled_allowlist` | When `true`, ignores all allowlist entries |

```toml
# Trust Claude Code more — wider allowlist, fewer packs
[agents.claude-code]
trust_level = "high"
additional_allowlist = ["npm run build", "cargo test"]
disabled_packs = ["kubernetes"]

# Restrict unknown agents — extra rules, no allowlist bypass
[agents.unknown]
trust_level = "low"
extra_packs = ["strict_git", "database"]  # real pack / category IDs (see `dcg packs`)
disabled_allowlist = true
```

> `extra_packs`/`disabled_packs` take the same pack and category IDs as
> `[packs] enabled`/`disabled` — a **category ID** like `"database"` expands to
> every `database.*` sub-pack. Use IDs listed by `dcg packs` or in
> `docs/packs/README.md`; `"paranoid"` is a
> [graduation mode](docs/graduated-response.md), not a pack, so enable the real
> `strict_git` pack for stricter git rules.

See [docs/agents.md](docs/agents.md) for full documentation on supported agents,
trust levels, and configuration options.

### Codex Support

dcg now treats Codex CLI as a first-class hook target, not just a Claude-shaped
compatibility path. The installer configures Codex CLI 0.125.0+ automatically
when it detects `codex` on `PATH` or an existing `~/.codex/` directory.

| Codex behavior | dcg handling |
|----------------|--------------|
| Hook config | Merges a `PreToolUse` Bash hook into `~/.codex/hooks.json` |
| Denied command | Exits 0 with a minimal `hookSpecificOutput` denial on stdout; human warning stays on stderr |
| Allowed command | Exits 0 with empty stdout and stderr |
| Existing hooks | Preserves coexisting hooks, keeps dcg first for Bash, and refuses to overwrite malformed JSON |
| Validation | Covered by subprocess protocol tests plus an opt-in real Codex E2E harness |

Codex's hook input is intentionally close to Claude Code's, but Codex rejects
unknown fields in hook output. dcg detects Codex payloads from the non-empty
`turn_id` field and emits only Codex's documented denial fields so a blocked
command is reported as blocked rather than as a failed hook. See
[docs/codex-integration.md](docs/codex-integration.md) for protocol details,
manual probes, and troubleshooting.

---

## Origins & Authors

This project began as a Python script by Jeffrey Emanuel, who recognized that AI coding agents, while incredibly useful, occasionally run catastrophic commands that destroy hours of uncommitted work. The original implementation was a simple but effective hook that intercepted dangerous git and filesystem commands before execution.

- **[Jeffrey Emanuel](https://github.com/Dicklesworthstone)** - Original concept and Python implementation ([source](https://github.com/Dicklesworthstone/misc_coding_agent_tips_and_scripts/blob/main/DESTRUCTIVE_GIT_COMMAND_CLAUDE_HOOKS_SETUP.md)); substantially expanded the Rust version with the modular pack system (50+ security packs), heredoc/inline-script scanning, the three-tier architecture, context classification, allowlists, scan mode, and the dual regex engine
- **[Darin Gordon](https://github.com/Dowwie)** - Initial Rust port with performance optimizations

The initial Rust port by Darin maintained pattern compatibility with the original Python implementation while adding sub-millisecond execution through SIMD-accelerated filtering and lazy-compiled regex patterns. Jeffrey subsequently expanded the Rust codebase dramatically to add the features described above.

## Escape Hatch / Bypass

If dcg is blocking something you genuinely need to run:

| Method | Scope | How |
|--------|-------|-----|
| **Env var bypass** | Single command | `DCG_BYPASS=1 <command>` |
| **Allow-once code** | Single command | Copy the short code from the block message, run `dcg allow-once <code>` |
| **Permanent allowlist** | Rule or command | `dcg allowlist add core.git:reset-hard -r "reason"` |
| **Remove the hook** | All commands | Delete or comment out the dcg entry in `~/.claude/settings.json` (or equivalent for your agent) |

`DCG_BYPASS=1` disables all protection for that invocation. Use it sparingly and prefer allowlists for recurring needs.

## Modular Pack System

dcg uses a modular "pack" system to organize destructive command patterns by category. Packs can be enabled or disabled in the configuration file.

**Category IDs expand to their sub-packs.** Listing a bare category in `enabled`
turns on every pack under it: `enabled = ["database"]` activates
`database.postgresql`, `database.mysql`, and the rest of that category. You can
still drop a single sub-pack with `disabled = ["database.redis"]`. The same
expansion applies to agent-profile `extra_packs` / `disabled_packs`. Always use
real pack or category IDs from `dcg packs` / `docs/packs/README.md` — a name like
`"paranoid"` is a [graduation mode](docs/graduated-response.md), not a pack.

- Full pack ID index: `docs/packs/README.md`
- Canonical descriptions + pattern counts: `dcg packs --verbose`

### Enabled by default (no config file)

With **no config file present**, dcg enables only the packs that guard against the
most catastrophic, unrecoverable mistakes:

- `core.filesystem` - Dangerous recursive `rm` operations and equivalent filesystem destruction outside literal temp subdirectories *(always on; cannot be disabled)*
- `core.git` - Destructive git commands that lose uncommitted work, rewrite history, or destroy stashes *(always on; cannot be disabled)*
- `system.disk` - `mkfs`, `dd`-to-device, `fdisk`, `parted`, `mdadm`, `lvm` removal, `wipefs` *(on by default; opt out with `disabled = ["system.disk"]`)*

On **Windows**, two additional packs are on by default so a fresh install blocks the
catastrophic native-Windows operations with no config:

- `windows.filesystem` - cmd `del /s`, `rd /s`, `format <drive>:` and PowerShell `Remove-Item -Recurse` (with or without `-Force`; aliases included), `Clear-Content`, `Clear-RecycleBin` *(default-on **on Windows only**; opt out with `disabled = ["windows.filesystem"]` or `["windows"]`)*
- `windows.system` - `vssadmin delete shadows` / `wmic shadowcopy delete` (Volume Shadow Copy destruction), `diskpart`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `cipher /w`, `bcdedit /delete` *(default-on **on Windows only**; opt out with `disabled = ["windows.system"]` or `["windows"]`)*

The broader `windows.misc` (`reg delete`, `net user /delete`, `wsl --unregister`, `robocopy /MIR`) and
`windows.powershell` (registry/provider deletes, `Remove-LocalUser`, `Disable-ComputerRestore`, `Remove-VM`)
packs are opt-in on every platform. On Unix the `windows.*` packs are registered but off by default; enable
them (e.g. to scan committed `.ps1`/`.cmd` scripts in CI) via `[packs] enabled = ["windows"]`.

Every other pack — including `database.postgresql` and `containers.docker` — is
**opt-in** and is *not* active until a config file enables it. Running `dcg init`
writes a starter `~/.config/dcg/config.toml` whose `[packs] enabled` list turns on
`database.postgresql` and `containers.docker` as common examples, but that is a
generated starter config, not the no-config default. Enable any pack below by adding
it to `[packs] enabled` — see [Enable More Protection](#enable-more-protection).

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
- `database.snowflake` - Protects modern `snow sql` inline queries, files, stdin, nested sources, destructive data operations, pipelines, warehouses, and account privileges.
- `database.supabase` - Protects against destructive Supabase CLI operations including database resets, migration rollbacks, function/secret/storage deletion, project removal, and infrastructure changes.
- `database.bigquery` - Protects the `bq` CLI and GoogleSQL against dataset drops (`DROP SCHEMA`), table overwrites, unfiltered DML (`WHERE TRUE` is GoogleSQL's full-table idiom), and settings that shorten the time-travel recovery window.

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
- `infrastructure.atmos` - Protects against destructive Atmos operations like terraform deploy (auto-approve), clean, destroy, state rm/taint, and helmfile destroy.
- `infrastructure.pulumi` - Protects against destructive Pulumi operations like destroy and up with -y (auto-approve).
- `infrastructure.terraform` - Protects against destructive Terraform operations like destroy, taint, and apply with -auto-approve.

### System Packs
- `system.disk` - Protects against destructive disk operations including dd to devices, mkfs, partition table modifications (fdisk/parted), RAID management (mdadm), btrfs filesystem operations, device-mapper (dmsetup), network block devices (nbd-client), and LVM commands (pvremove, vgremove, lvremove, lvreduce, pvmove).
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
- `platform.kamal` - Protects against destructive Kamal 2.x operations that tear down the stack (`kamal remove`), delete accessory data directories (`kamal accessory remove`), drop proxy routing, take the app offline, or prune the images that `kamal rollback` relies on.
- `platform.modal` - Protects against destructive Modal serverless platform operations like recursive volume removal, app stops with `--force`, and secret deletion.
- `platform.railway` - Protects against destructive Railway CLI and Public API operations that can delete projects, environments, services, functions, volumes, variables, or deployments.

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

### Windows Packs
Native-Windows (cmd.exe + PowerShell) destructive-command protection. `windows.filesystem` and
`windows.system` are **default-on on Windows** (off/opt-in on Unix); `windows.misc` and
`windows.powershell` are opt-in everywhere. All patterns are case-insensitive.
- `windows.filesystem` - Recursive/forced filesystem destruction: cmd `del /s`, `rd /s`/`rmdir /s`, `format <drive>:`; PowerShell `Remove-Item -Recurse` (with or without `-Force`; `-Force` only broadens coverage to hidden/read-only items; aliases `rm`/`del`/`rd`/`ri` included), `Clear-Content`, `Clear-RecycleBin`. Whitelists PowerShell `-WhatIf` previews only on cmdlets/aliases that honor it, plus temp-dir deletes.
- `windows.system` - Catastrophic disk/system operations: `vssadmin delete shadows` and `wmic shadowcopy delete` (Volume Shadow Copy destruction — a ransomware hallmark), `diskpart`, `Format-Volume`, `Clear-Disk`, `Remove-Partition`, `Initialize-Disk`/`Reset-PhysicalDisk`, `cipher /w`, `bcdedit /delete`.
- `windows.misc` - Registry/account/service/WSL/copy destruction: `reg delete`, `net user|localgroup /delete`, `sc delete`, `schtasks /delete`, `wsl --unregister` (destroys a WSL distro), `robocopy /MIR` (mirror-delete).
- `windows.powershell` - Destructive PowerShell cmdlets: registry/provider deletes (`Remove-Item HKLM:\`, `Remove-ItemProperty`, `Remove-PSDrive`), `Remove-LocalUser`/`Remove-LocalGroup`, `Unregister-ScheduledTask`, `Disable-ComputerRestore`, forced `Stop-Computer`/`Restart-Computer`, `Remove-VM`/`Remove-AppxPackage`.

### Careful Company (Windows) Preset

Every other pack answers "will this command destroy something?". This preset also
answers "is this command **sending our data somewhere**, or switching off the
controls that watch it?" — the question that matters once an agent runs on a
Windows workstation with tool-permission prompts disabled. The same policy is
applied to statically inspectable commands submitted through either
**PowerShell or `cmd.exe`**, including Cmd's caret escaping, control prefixes,
nested `cmd /c` / `call`, and command chaining. It is **opt-in on every
platform**, and one line enables the whole posture:

```toml
[packs]
enabled = ["careful_company_running_windows"]
```

With this exact preset ID enabled, the hook evaluation deadline defaults to
3000 ms instead of the ordinary 1000 ms unless config or
`DCG_HOOK_TIMEOUT_MS` explicitly supplies another value. This changes only the
time available to reach the same fail-closed decision. Inspect the effective
value and source with `dcg config --format json`.

That turns on the six sub-packs below **and** the existing destruction coverage
the same posture needs: the current `windows.*`, `database.*` (including
Snowflake), `storage.*`, `remote.*`, `backup.*`, `secrets.*`, and `cloud.*`
packs. Membership is an explicit pinned list rather than a prefix rule, so a
future pack added to one of those reused categories does not silently join this
security posture — it has to be added deliberately. (A future
`careful_company_running_windows.*` sub-pack *does* join, through ordinary
category expansion.) Any member can be dropped individually with
`disabled = ["remote.rsync"]`.

- `careful_company_running_windows.email` - Sending mail from the workstation: `Send-MailMessage`, `System.Net.Mail.SmtpClient`, Outlook COM automation, Microsoft Graph `sendMail`, transactional mail-API send endpoints, `aws ses send-email`, SMTP CLI tools (`blat`, `swaks`, `msmtp`, `git send-email`, `curl --mail-rcpt`), and persistent forwarding rules (`New-InboxRule -ForwardTo`, `Set-Mailbox -ForwardingSmtpAddress`).
- `careful_company_running_windows.chat` - Chat and webhook destinations: Slack incoming webhooks and Web API writes, Teams connectors and Power Automate triggers, Discord, Telegram, Google Chat, Twilio, Zapier/IFTTT, PagerDuty, and request catchers such as `webhook.site` and `interact.sh`.
- `careful_company_running_windows.upload` - HTTP file-upload primitives (`-InFile`, `-Form`, `curl -T`, `-F field=@file`, `--data-binary @file`, `--post-file`, `WebClient.UploadFile`, `GetRequestStream`, `MultipartFormDataContent`, BITS uploads), file-drop/paste services, `gh gist create`, `certreq -Post`, and request bodies built from file or clipboard contents.
- `careful_company_running_windows.transfer` - Outbound file transfer: scp/sftp/WinSCP to a remote destination, scripted FTP, `tftp put`, rsync and rclone to a remote, cloud-storage uploads (`aws s3 cp` local→`s3://`, `az storage blob upload`, azcopy, `gsutil cp`→`gs://`, b2/s3cmd/mc/wrangler r2), peer-to-peer senders, WebDAV mounts, and copy LOLBins (`esentutl /y`, `print /D:`).
- `careful_company_running_windows.tunnel` - Channels that expose the workstation or bypass inspection: ngrok, cloudflared, devtunnel/`code tunnel`, localtunnel, `tailscale funnel`, `ssh -R`/`-D`, chisel/frp, ncat/netcat/socat, PowerShell raw sockets, `netsh interface portproxy`, DNS tunnels, and out-of-band callback domains.
- `careful_company_running_windows.guardrails` - Turning off the safety net: Defender (`Set-MpPreference -Disable*`/`-ExclusionPath`), the firewall, EDR and event-log services, BitLocker, `Set-ExecutionPolicy Bypass`, script-block logging, event-log clearing, **dcg's own `DCG_BYPASS`, `dcg uninstall`, allowlist grants (`dcg allowlist add`, `dcg allow-once`), runtime config overrides (`DCG_DISABLE`/`DCG_PACKS`/`DCG_CONFIG`), and the agent's hook config**, plus unreviewed remote code (`iwr | iex`, `powershell -EncodedCommand`, mshta/regsvr32 remote payloads). Diagnosis stays open: `dcg explain`, `dcg allowlist list`, and `dcg allowlist validate` are whitelisted.

**False positives are the design constraint.** Rules require positive evidence of
egress — an attached file, a known egress host, a mutating method — so ordinary
`GET`s, `-OutFile`/`curl -o` downloads, and every package-manager install pass
through untouched (fetching from a known file-drop or paste host is the one
exception, and it warns rather than blocks). Requests whose destinations are all internal (loopback,
RFC1918, `*.internal`/`*.corp`/`*.local`, bare intranet hostnames) are
whitelisted, with the cloud metadata endpoints (`169.254.169.254`,
`metadata.google.internal`) deliberately excluded from that allowance. Searching
for a token (`Select-String "Send-MailMessage" *.ps1`) and `dcg explain
"<command>"` are never blocked. `git push` to a named remote is untouched, and
SMB copies to a corporate share are out of scope.

Genuinely ambiguous cases **warn instead of blocking** (`Medium` severity: the
command runs and the decision is recorded) — a `POST` with an inline body is a
GraphQL query as often as an exfiltration. Promote them when your posture calls
for it:

```toml
[policy.rules]
"careful_company_running_windows.upload:cli-http-mutating-request" = "deny"
"careful_company_running_windows.upload:ps-http-mutating-request" = "deny"
```

> **This preset carries one built-in trust boundary you should know about.**
> While any `careful_company_running_windows.*` pack is enabled, a command whose
> executable is `hfdt` (optionally path-qualified) is allowed **without
> evaluating any pack at all** — not just this preset's. `hfdt rm -rf /data` is
> permitted with the preset on and denied with it off. The exemption is
> structural rather than textual: it requires `hfdt` to be the actual executable
> of the whole command and refuses chains, redirection, and process
> substitution, so `hfdt …; Invoke-RestMethod …` and `hfdt $(…)` are evaluated
> normally. If you do not run that tool, this never fires; if you do, treat it
> as an explicit decision to trust it completely. See
> [`docs/careful-company-windows.md`](docs/careful-company-windows.md).

Other first-party internal tooling gets no such exemption and should be
allowlisted, which keeps the grant narrow and recorded:

```bash
dcg allowlist add-command "mytool publish --to https://artifacts.corp.internal" \
  -r "First-party internal publisher" --user
```

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
    "database.supabase",

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
    "platform.railway",

    # Monitoring
    "monitoring.splunk",
]
```

### Custom Packs

Create your own organization-specific security packs using YAML files. Custom packs let you define patterns for internal tools, deployment scripts, and proprietary systems without modifying dcg.

```toml
[packs]
custom_paths = [
    "~/.config/dcg/packs/*.yaml",      # User packs
    ".dcg/packs/*.yaml",               # Project-local packs
]
```

For detailed pack authoring guide, schema reference, and examples, see [`docs/custom-packs.md`](docs/custom-packs.md).

Validate your pack before deployment:

```bash
dcg pack validate mypack.yaml
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

# Bounded heredoc fallback (strict mode can block instead).
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
│ Tier 2: Extract │ ─── Error/Timeout ──► FALLBACK SCAN or BLOCK (strict)
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
- `DCG_VERBOSE=0-3`: verbosity level (0 = quiet, 3 = trace)
- `DCG_QUIET=1`: suppress non-error output
- `DCG_COLOR=auto|always|never`: color mode
- `DCG_NO_RICH=1`: disable rich terminal formatting and use plain rendering
- `DCG_NO_COLOR=1`: disable colored output (same as NO_COLOR)
- `DCG_LEGACY_OUTPUT=1`: force plain output paths (same as `--legacy-output`)
- `DCG_ROBOT=1`: enable robot mode for JSON stdout and quiet stderr
- `DCG_HIGH_CONTRAST=1`: enable high-contrast output (ASCII borders + monochrome palette)
- `DCG_FORMAT=text|json|sarif`: default output format (command-specific — see [Output Formats](#output-formats-and-dcg_format) for which values each subcommand actually accepts; real SARIF is `dcg scan`-only)
- `DCG_FAIL_CLOSED=1`: block (deny) on hook input that cannot be parsed, instead of the default fail-open allow (opt-in; see [Bounded Failure Policy](#bounded-failure-policy))
- `DCG_BYPASS=1`: bypass dcg entirely (escape hatch; use sparingly)
- `DCG_CONFIG=/path/to/config.toml`: use explicit config file
- `DCG_HEREDOC_ENABLED=true|false`: enable/disable heredoc scanning
- `DCG_HEREDOC_TIMEOUT=50`: heredoc extraction timeout (milliseconds)
- `DCG_HEREDOC_TIMEOUT_MS=50`: heredoc extraction timeout (milliseconds)
- `DCG_HEREDOC_LANGUAGES=python,bash`: filter heredoc languages
- `DCG_POLICY_DEFAULT_MODE=deny|ask|warn|log`: global default decision mode (`ask` requires native operator review and fails closed on unsupported clients)
- `DCG_HOOK_TIMEOUT_MS=<milliseconds>`: explicit hook evaluation timeout
  (ordinary default: 1000; automatic
  `careful_company_running_windows` preset default: 3000)

### Output Formats and `DCG_FORMAT`

`--format` (and the `DCG_FORMAT` env var, which seeds the default) is
**command-specific**: each subcommand accepts only its own set of values, and an
unrecognized value is a usage error (exit 2). `DCG_FORMAT` applies wherever a
command has a `--format` flag and is silently ignored by commands that don't.

| Command | Accepted `--format` values | Notes |
|---------|----------------------------|-------|
| `dcg scan` | `pretty`, `json`, `markdown`, `sarif` | **Only** command that emits real SARIF 2.1.0 |
| `dcg test` | `pretty` (alias `text`), `json` (aliases `sarif`, `structured`), `toon` | |
| `dcg config` | `pretty` (alias `text`), `json` (alias `sarif`) | |
| `dcg packs` | `pretty` (alias `text`), `json` (alias `sarif`) | |
| `dcg explain` | `pretty`, `json` (alias `sarif`) | |
| `dcg doctor` | `pretty`, `json` (alias `sarif`) | |
| `dcg simulate` | `pretty`, `json` (alias `sarif`) | |
| `dcg corpus` | `json`, `pretty` (alias `sarif`) | |
| `dcg suggest-allowlist` | `text`, `json` (alias `sarif`) | |

**`sarif` is a JSON alias on every command except `dcg scan`.** This is
deliberate so that setting `DCG_FORMAT=sarif` globally degrades gracefully —
`dcg scan` produces a real SARIF report while other commands fall back to their
structured JSON rather than erroring. If you need machine-readable output from a
non-scan command, prefer `--format json` (which is unambiguous); use `dcg scan
--format sarif` for SARIF. `--robot` forces JSON regardless of `--format`.

### Configuration Hierarchy

dcg supports layered configuration from multiple trusted sources, with
higher-priority sources overriding lower ones:

1. Environment Variables (DCG_* prefix)           [HIGHEST PRIORITY]
2. Explicit Config File (DCG_CONFIG env var)
3. User Config (~/.config/dcg/config.toml)
4. System Config (/etc/dcg/config.toml)
5. Compiled Defaults                              [LOWEST PRIORITY]

An automatically discovered `.dcg.toml` is intentionally **not** a normal
precedence layer. A repository is untrusted when it is first cloned, so its
config may only add enforcement: enable built-in packs, add `deny` policy
entries, opt into `general.fail_closed`, enable
heredoc scanning, or turn off heredoc bounded fallbacks. Settings that grant
trust or reduce coverage — including allow overrides, pack disables, custom
pack paths, custom regex overrides (including block regexes), resource limits,
language filters, agent profiles, nested project overrides, and per-rule
[target-path exemptions](#per-rule-target-path-exemptions) — are ignored during
automatic discovery.

Automatic project discovery currently runs only where dcg can bind a direct
regular file to the descriptor it actually reads (Unix, including macOS).
Native Windows ignores an automatically discovered `.dcg.toml` until equivalent
reparse-point and file-identity validation is available; this avoids turning a
workspace path race into a privileged file read. A reviewed Windows project
file can still be selected explicitly with `DCG_CONFIG=.dcg.toml`.

To deliberately trust the complete repository config for one invocation, select
it explicitly: `DCG_CONFIG=.dcg.toml dcg ...`. An explicit file has the same
full authority as any other user-selected config.

### Accessibility & Themes

dcg supports colorblind-safe palettes and high-contrast output. Colors are always paired
with symbols/labels to avoid conveying meaning by color alone.

```toml
[output]
high_contrast = true       # ASCII borders + black/white palette

[theme]
palette = "colorblind"     # default | colorblind | high-contrast
use_unicode = true         # false for ASCII-only
use_color = true           # false for monochrome
```

**Configuration File Locations**:

| Level | Path | Use Case |
|-------|------|----------|
| System | `/etc/dcg/config.toml` | Organization-wide defaults |
| User | `~/.config/dcg/config.toml` | Personal preferences |
| Project | `.dcg.toml` (repo root) | Automatically discovered enforcement-only policy |
| Explicit | `DCG_CONFIG=/path/to/file` | Testing or override |

The machine-wide system-config layer is accepted on Unix only after the file
and every directory in its direct path are root-owned and not group/world
writable. Native Windows currently ignores that implicit layer until native
ACL and reparse-point validation is implemented; use a user config or an
explicit `DCG_CONFIG` file there.

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

This means you can set organization defaults in `/etc/dcg/config.toml`, personal
preferences in `~/.config/dcg/config.toml`, and repository-owned hardening in
`.dcg.toml` without letting a newly cloned repository weaken the user's guard.
Use `DCG_CONFIG=.dcg.toml` only after reviewing a project file that needs full
override authority.

**Project-Specific Pack Configuration**:

The `[projects]` section allows different pack configurations for different repositories:

```toml
[projects."/home/user/work/production-api"]
packs = { enabled = ["database.postgresql", "cloud.aws"], disabled = [] }

[projects."/home/user/personal/experiments"]
packs = { enabled = [], disabled = ["core.git"] }  # More permissive for experiments
```

### Bounded Failure Policy

dcg distinguishes an unreadable hook envelope from a command whose safety
evaluation began but could not finish. It never treats elapsed analysis time or
an oversized extracted command as proof that execution is safe.

| Scenario | Default behavior | Strict/configured behavior |
|----------|------------------|----------------------------|
| Malformed or oversized raw hook JSON | Allow with an audit warning | `general.fail_closed = true` denies |
| Transient hook stdin I/O error | Allow with an audit warning | Always fail-open because the payload was not attacker-controlled |
| Extracted command exceeds `max_command_bytes` | Explicit indeterminate result | Review-capable clients receive `ask`; other clients block |
| Absolute evaluation deadline expires | Explicit indeterminate result | Review-capable clients receive `ask`; other clients block |
| Heredoc extraction/parse/AST failure | Run the bounded fallback scanner | `fallback_on_parse_error = false` or `fallback_on_timeout = false` blocks |

**Configurable Strictness**:

Raw hook-envelope fail-open behavior and embedded-code fallback behavior are
configured independently.

For **heredoc/inline-script** analysis specifically:

```toml
[heredoc]
fallback_on_parse_error = false  # Block on heredoc parse errors
fallback_on_timeout = false      # Block on heredoc timeouts
```

For the **top-level hook input** (the JSON dcg reads from stdin), enable
fail-closed mode so that input which cannot be parsed at all is **blocked**
instead of allowed:

```toml
[general]
fail_closed = true   # Deny when the hook input itself is unparseable
```

or at runtime:

```bash
DCG_FAIL_CLOSED=1   # env var overrides the config value
```

The default is **fail-open** (unparseable input is allowed) and is unchanged
unless you opt in. With fail-closed enabled, a genuinely unparseable hook
payload produces a deny (a `permissionDecision: deny` for Claude-style hooks; a
`"decision":"deny"` line plus a non-zero exit for `dcg hook --batch`).
Transient IO read errors still fail open even in this mode, since they are not
attacker-controlled malformed payloads.

> A leading UTF-8 BOM (`EF BB BF`) is stripped before parsing in all hook
> paths, so a BOM-prefixed but otherwise-valid command is correctly evaluated
> (and blocked if dangerous) rather than allowed through as "unparseable".

With strict mode enabled, dcg blocks malformed attacker-controlled hook input
and reports why. Separately, when heredoc parsing cannot complete and fallback
is enabled, dcg runs a lightweight bounded check over the original command:

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

This fallback is specific to embedded-code extraction. It is not used for a raw
hook envelope that could not be parsed, and it does not turn a deadline or an
oversized extracted command into an allow.

**Absolute Evaluation Deadline**:

To prevent any single command from blocking indefinitely, dcg enforces an
end-to-end evaluation deadline. The ordinary default is **1000ms**; the
`careful_company_running_windows` preset defaults to **3000ms**, and an
explicit `general.hook_timeout_ms` or `DCG_HOOK_TIMEOUT_MS` overrides either
default (values below **10ms** are clamped to that safety minimum). Exhausting
that budget produces an explicit indeterminate result, which requests operator
review where the hook protocol supports it and otherwise blocks.

The deadline intentionally uses monotonic wall-clock time. A CPU-time budget
would stop advancing while dcg was descheduled or waiting on a bounded
operation, so it could not guarantee hook latency. On a heavily loaded host,
increase `hook_timeout_ms` and use `dcg test --enforce-budget` to exercise the
same evaluator-side budget outside a live hook.

## Installation

### Quick Install (Recommended)

The easiest way to install is using the install script, which downloads a prebuilt binary for your platform:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

Easy mode auto-detects your platform, downloads the right binary, verifies SHA256 checksums, configures all supported AI agent hooks (Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, Cursor IDE, Hermes Agent, Posit Assistant, Aider), and updates your PATH. For Codex CLI 0.125.0+, the installer merges a `PreToolUse` Bash hook into `~/.codex/hooks.json`; invalid JSON or malformed existing Codex hook shapes are left unchanged and reported instead of being overwritten.

### Homebrew

The upstream tap supports Apple Silicon and Intel macOS plus ARM64 and x86_64
Linux:

```bash
brew install dicklesworthstone/tap/dcg
dcg install
```

Homebrew installs only the `dcg` binary. The explicit `dcg install` step
configures hooks for the coding agents detected on your machine; the formula
does not mutate hook or configuration files during package installation.

If your Homebrew installation enforces tap trust, trust this formula before
installing it:

```bash
brew trust --formula dicklesworthstone/tap/dcg
brew install dicklesworthstone/tap/dcg
dcg install
```

**Other options:**

Interactive mode (prompts for each step; prompts read your terminal via
`/dev/tty`, so they work even when the script is piped through `bash`. With no
terminal at all — e.g. CI — the installer proceeds with safe defaults and
prints each decision it makes):

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash
```

Install specific version:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --version v0.7.6
```

Install to /usr/local/bin (system-wide, requires sudo):

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | sudo bash -s -- --system
```

Build from source instead of downloading binary:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --from-source
```

Download/install only (skip agent hook configuration):

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --no-configure
```

> **Note:** If you have [gum](https://github.com/charmbracelet/gum) installed, the installer will use it for fancy terminal formatting.

The installer verifies each adjacent `.minisig` with the embedded release public
key when `minisign` is available. A present but invalid signature is always fatal;
`--require-minisign` also makes a missing sidecar or verifier fatal. The pinned key
ID for current releases is `69B3955C8D2E62A8`; the retired
`36B847D11BA5A0D0` key is accepted only when installing v0.6.7. Trusted Sigstore
cosign bundles are checked independently against either the pinned local-release
public key or the repository's GitHub Actions OIDC identity, and the SHA256
checksum remains mandatory. Cosign versions affected by CVE-2026-22703 are not
trusted. The installer falls back to building from source if no prebuilt is
available and removes the legacy Python predecessor (`git_safety_guard.py`) if
present.

<details>
<summary>Agent-specific notes</summary>

- **Aider:** No PreToolUse-style interception. The installer enables `git-commit-verify: true` in `~/.aider.conf.yml` so git hooks run. For full protection, install dcg as a [git pre-commit hook](docs/scan-precommit-guide.md).
- **Continue:** No shell command interception hooks. The installer detects Continue but cannot auto-configure protection. Use a [git pre-commit hook](docs/scan-precommit-guide.md) instead.
- **Codex CLI:** PreToolUse hooks via `~/.codex/hooks.json` (stable in Codex 0.125.0+; the `codex_hooks` feature is on by default). dcg detects Codex from the `turn_id` stdin field and emits the minimal documented `hookSpecificOutput` deny JSON with exit code 0; dcg-only metadata is omitted so Codex's strict parser accepts the decision. The Unix installer and `install.ps1` both merge dcg's hook into the existing hooks object, detect an already-current dcg hook exactly, leave invalid JSON or malformed hook shapes untouched, and surface the failure reason in the install summary. After installation, open Codex's `/hooks` UI once to trust the hook. `uninstall.sh` and `uninstall.ps1` remove only dcg-owned Codex hooks and preserve coexisting entries. See the [Codex integration notes](docs/codex-integration.md). Caveats: the model can still write scripts to disk to bypass hook-based blocking; and Codex's `PreToolUse` hooks [do not yet intercept every `unified_exec` shell path](docs/codex-integration.md#known-limitation-codex-unified_exec-path-windows-desktop--cli), so treat it as a guardrail rather than a complete enforcement boundary.
- **GitHub Copilot CLI:** The installer writes a user-level hook to `${COPILOT_HOME:-~/.copilot}/hooks/dcg.json`, protecting every workspace. The generated `preToolUse` hook covers both Unix `bash` and Windows `powershell` payloads and emits Copilot's exact top-level permission-decision JSON.
- **VS Code Copilot Chat:** Current VS Code releases load `~/.claude/settings.json` by default, so the Claude Code hook installed by dcg also protects Copilot Chat without a second bridge or duplicate hook. dcg recognizes VS Code's documented `runTerminalCommand` shell tool plus the observed compatibility names `run_in_terminal` and `runInTerminal`, reads `tool_input.command`, and returns VS Code's documented `hookSpecificOutput` deny. The newer Copilot **Agent Host** (and the Agents window built on it) sends a batched envelope instead — `{"toolCalls": [{"name": "powershell", "args": "{\"command\": …}"}]}` with JSON-encoded argument strings; dcg evaluates every shell entry in the batch independently and a single destructive entry denies the request (#252). Agent hooks are still a VS Code preview feature and can be disabled by organization policy; use **Developer: Show Agent Debug Logs** or the **GitHub Copilot Chat Hooks** output channel to confirm that the hook loaded.
- **Cursor IDE:** Hooks are configured through `~/.cursor/hooks.json` plus a generated bridge (`dcg-pre-shell.ps1` on Windows). The installer inserts dcg first in `beforeShellExecution`, collapses duplicate dcg entries, and preserves coexisting Cursor hooks.
- **Hermes Agent:** [NousResearch's Hermes Agent](https://github.com/NousResearch/hermes-agent) declares shell hooks in its `config.yaml` under `hooks.pre_tool_call`. Hermes resolves its data root from `HERMES_HOME` when set, else `%LOCALAPPDATA%\hermes` on native Windows and `~/.hermes` on Linux/macOS — both installers write the hook to that resolved path (`install.ps1` never writes to `%USERPROFILE%\.hermes` unless `HERMES_HOME` points there, since native Windows Hermes would never read it). The installer merges a single `matcher: "terminal"` entry that invokes dcg directly — no wrapper script — because Hermes' input JSON (`hook_event_name: "pre_tool_call"`, `tool_name: "terminal"`, `tool_input.command`) deserializes straight into dcg's existing `HookInput`. Hermes [explicitly documents](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md) that "non-zero exit codes... never abort the agent loop", so dcg switches to Hermes' JSON block protocol on output: `{"decision":"block","reason":...}` (plus the alternate `{"action":"block","message":...}` form for cross-version compatibility). The installer also sets `hooks_auto_accept: true` if not already set; Hermes silently drops un-allowlisted hooks in non-TTY runs (gateway/cron) without it. `unconfigure_hermes` in `uninstall.sh` removes only the dcg-owned entry and leaves `hooks_auto_accept` alone (other Hermes hooks may rely on it).
- **Grok (xAI):** [Grok Build / Grok CLI](https://x.ai/news/grok-build-cli) auto-discovers every `*.json` under `~/.grok/hooks/`. `dcg install --grok` writes a self-contained `~/.grok/hooks/dcg.json` with a `PreToolUse` / `matcher: "Bash"` entry — Grok internally aliases Claude-style `"Bash"` to its own `run_terminal_cmd` tool, so a single rule covers every shell command. dcg detects Grok at runtime from the camelCase wire shape (`hookEventName: "pre_tool_use"`, `toolName: "run_terminal_cmd"`) or from the `GROK_SESSION_ID` / `GROK_HOOK_EVENT` / `GROK_WORKSPACE_ROOT` environment variables, and switches its output to Grok's JSON contract: `{"decision":"deny","reason":...}` (note `"deny"`, not Hermes' `"block"`). Grok also picks up dcg automatically through its `~/.claude/settings.json` compatibility layer, so existing Claude Code users get protection with no additional install step. Add `--project` to write `<repo>/.grok/hooks/dcg.json` for a per-repo install (Grok requires `/hooks-trust` the first time it opens a repo with hooks).
- **Antigravity CLI (`agy`):** [Google Antigravity's `agy` CLI](https://antigravity.google) ships a Claude-Code-compatible hooks system. `dcg install --agy` merges a `PreToolUse` / `matcher: "Bash"` entry into `~/.gemini/config/hooks.json` (the canonical path; `agy` migrates the legacy `~/.gemini/antigravity-cli/hooks.json` here and symlinks the old path to it). `agy` runs the hook before its `run_command` shell tool; dcg detects `agy` at runtime from the distinctive nested `toolCall` envelope (`{"toolCall":{"name":"run_command","args":{"CommandLine":"…"}},"conversationId":…,"stepIdx":…}`) — the shell command is read from `toolCall.args.CommandLine` — or from the `ANTIGRAVITY_CONVERSATION_ID` environment variable / `agy` parent-process name. dcg switches its output to `agy`'s JSON contract: `{"decision":"block","reason":…}` with exit code 0 (verified: `agy` honors both `"block"` and `"deny"` and aborts the tool; a non-zero exit code is only logged and does NOT reliably block, so dcg always emits exit 0 + JSON). Add `--project` to write `<repo>/.gemini/config/hooks.json` for a per-repo install. Restart `agy` (start a new session) after installing.
- **Posit Assistant:** [Posit Assistant](https://positron.posit.co/assistant/) reads Claude-Code-compatible lifecycle hooks from `~/.posit/assistant/settings.json` (global) and `<workspace>/.posit/assistant/settings.json` (project). The installer merges one `PreToolUse` entry into the **global** file, so a single install covers the Positron/RStudio extension, the standalone server, and the `pa` terminal client across every workspace. No protocol work was needed on dcg's side: the `PreToolUse` stdin is the snake_case Claude shape (`tool_name`, `tool_input.command`, `tool_use_id`, `permission_mode`), exit code 2 blocks with stderr shown as the reason, and `hookSpecificOutput.permissionDecision` (`allow`/`deny`/`ask`) is read on exit 0 — dcg's existing Claude-compatible response answers all of it. Three details differ from the Claude Code entry: the matcher is **lowercase** `"bash|powershell"` (a simple matcher string is an *exact* match — or a `|`/`,`-separated list of exact matches — against the tool name, so a copied Claude `"Bash"` matcher would never fire; listing both names covers a Windows PowerShell host with one entry); only documented handler fields are written (`type`, `command`, `timeout`), so there is **no `shell` field** — the command path is quoted instead, since shell-form hooks run through `cmd.exe` on Windows; and `timeout` is in **seconds**. dcg identifies the agent at runtime from `PA_PROJECT_DIR`, which the hook contract sets in the hook subprocess (also used to keep a `powershell` tool name from being answered with Codex's minimal deny shape). Existing matcher groups are left structurally intact rather than consolidated — hook config is additive, so a user's `matcher: "bash,edit"` group keeps working untouched — and `unconfigure_posit_assistant` in `uninstall.sh` removes only dcg-owned entries and never deletes the settings file, since unrelated settings live there too. Note: Posit's hooks documentation is not public yet; this contract was verified empirically and is pinned by tests in `src/hook.rs`.
- **OpenCode:** Not auto-configured. Requires a Bun-based plugin with `"tool.execute.before"` hook key. A working community plugin: [aspiers/ai-config/dcg-guard.js](https://github.com/aspiers/ai-config/blob/main/.config/opencode/plugins/dcg-guard.js).
- **Pi:** Not auto-configured. [Pi](https://github.com/earendil-works/pi) intercepts shell commands through user-authored TypeScript extensions (`pi.on("tool_call", …)`, auto-loaded from `~/.pi/agent/extensions/*.ts` or `<repo>/.pi/extensions/*.ts`). A ready-to-use `dcg-guard.ts` extension that routes each `bash` command through `dcg --robot test` (exit 1 = deny) and blocks with the dcg reason is documented in [docs/pi-integration.md](docs/pi-integration.md).

</details>

> **Recommended:** After installing, run `dcg setup` to add a [shell startup check](#hook-silently-removed-recommended-add-shell-startup-check) that warns you if the dcg hook is ever silently removed from `~/.claude/settings.json`.

### From source (Rust 1.95+; pinned nightly recommended)

The locked dependency graph requires Rust 1.95 or newer. Release builds use the
repository's known-good `nightly-2026-06-06` pin; the included
`rust-toolchain.toml` selects it automatically inside a checkout.

```bash
# Install the release toolchain if you don't have it
rustup toolchain install nightly-2026-06-06

# Install the tagged source reproducibly
cargo +nightly-2026-06-06 install --locked --git https://github.com/Dicklesworthstone/destructive_command_guard --tag v0.7.6 destructive_command_guard
```

### Manual build

```bash
git clone https://github.com/Dicklesworthstone/destructive_command_guard
cd destructive_command_guard
# rust-toolchain.toml automatically selects the pinned release nightly
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
dcg update --version v0.7.6
dcg update --system
dcg update --verify
dcg update --verify --no-configure  # binary only; preserve existing hook wiring
```

You can always re-run `install.sh` / `install.ps1` directly if preferred.

### Prebuilt Binaries

Prebuilt binaries are available for:
- Linux x86_64, statically linked with musl (`x86_64-unknown-linux-musl`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)
- macOS Intel (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)
- Windows x64 (`x86_64-pc-windows-msvc`)
- Windows ARM64 (`aarch64-pc-windows-msvc`)

Download from [GitHub Releases](https://github.com/Dicklesworthstone/destructive_command_guard/releases) and verify the SHA256 checksum.
Starting with v0.7.5, each manually published artifact has an adjacent
`.minisig`, verifiable with the DSR-managed public key (key ID
`69B3955C8D2E62A8`). The installers do this automatically when `minisign` is
installed; pass `--require-minisign` on Unix or `-RequireMinisign` on Windows to
require that verification path. The v0.6.7 manual release used the retired key
`36B847D11BA5A0D0`; installer trust is explicitly scoped to that version.

```bash
minisign -Vm dcg-<target>.<archive> \
  -x dcg-<target>.<archive>.minisig \
  -P 'RWSoYi6NXJWzaRs1mJmOwwXrZfPWcq6MXnQlNMLBYKzlIQTLwuVQG6uO'
```

Release artifacts may also include a Sigstore bundle (`.sigstore.json`) for
verification with `cosign verify-blob`. Workflow builds bind that bundle to the
repository's GitHub Actions OIDC identity; local DSR builds use a pinned
self-managed cosign key (public-key DER SHA256 fingerprint
`0e6947743daf39d6413cb25f6c96601427e38885f3a756e9f98f37d66e6df7a4`).
The installers accept either trust path, require cosign 2.6.2+/3.0.4+, and still
require the per-artifact SHA256 checksum.

## Uninstalling

Remove dcg and all its hooks from AI agents:

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/uninstall.sh | bash
```

On Windows:

```powershell
irm https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/uninstall.ps1 | iex
```

The Unix uninstaller:
- Removes dcg hooks from Claude Code, Codex CLI, Cursor IDE, Gemini CLI, GitHub Copilot CLI (user-level plus legacy repo-local), Hermes Agent, Posit Assistant, and Aider
- Removes the dcg binary
- Removes configuration (`~/.config/dcg/`) and history (the
  `~/.config/dcg/history.db` SQLite files plus `~/.local/share/dcg/`)
- Prompts for confirmation before making changes

The PowerShell uninstaller removes the Windows `dcg.exe` binary, the exact User PATH entry added by `install.ps1`, dcg hooks from Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, Cursor IDE, Hermes Agent, Posit Assistant, Grok, and Antigravity (`agy`), plus dcg configuration/history from native `%APPDATA%` / `%LOCALAPPDATA%` and any legacy `~/.config` / `~/.local/share` locations.

Options:
- `--yes` - Skip confirmation prompt
- `--keep-config` - Preserve configuration files
- `--keep-history` - Preserve history database
- `--purge` - Remove everything (overrides keep flags)

## Claude Code Configuration

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/dcg"
          }
        ]
      }
    ]
  }
}
```

Replace `/absolute/path/to/dcg` with the exact output of `command -v dcg`.
Never register a safety hook as bare `dcg`: agent hooks run under a
non-interactive shell whose `PATH` may omit `~/.local/bin`, causing the hook to
fail open. On native Windows, let `install.ps1` write the PowerShell-safe
absolute invocation (`& 'C:\...\dcg.exe'` plus `"shell": "powershell"`).

Claude Code exposes separate `Bash` and `PowerShell` shell tools on Windows, so
the combined matcher is required for complete shell coverage. The native
PowerShell installer also runs dcg through an explicitly selected PowerShell
hook shell; this prevents Git Bash from stripping backslashes out of an
absolute `C:\...\dcg.exe` path. Re-running the installer migrates a legacy
dcg-only `Bash` entry while preserving unrelated Bash-only hooks.

**Important:** Restart Claude Code after adding the hook configuration.

The matcher is a regex over the tool name and must cover **both** shells: on
native Windows, Claude Code runs shell commands through a `PowerShell` tool, so
a `Bash`-only matcher leaves every PowerShell command unguarded. `dcg install`,
the installers, and `dcg doctor --fix` all write `Bash|PowerShell` and migrate a
pre-existing `Bash`-only dcg entry in place (no duplicate hook is added).

## Codex CLI Configuration

Codex CLI 0.125.0+ supports stable `PreToolUse` hooks. The installer writes or
merges this automatically, but the manual configuration lives at
`~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/dcg"
          }
        ]
      }
    ]
  }
}
```

Codex denials intentionally omit dcg's extended Claude-only fields: dcg exits 0
with the minimal documented `hookSpecificOutput` JSON on stdout. Allowed
commands stay silent with exit code 0.

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
            "command": "/absolute/path/to/dcg",
            "timeout": 5000
          }
        ]
      }
    ]
  }
}
```

**Important:** Restart Gemini CLI after adding the hook configuration.

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

### Test Mode (`dcg test`)

Use `dcg test` to evaluate a command **without executing it**. This is useful for CI checks, false-positive debugging, and config validation before rollout.

#### Basic Usage

```bash
# Basic evaluation (human-readable output)
dcg test "rm -rf ./build"

# Structured output for automation
dcg test --format json "kubectl delete namespace prod" | jq -r .decision

# Use a specific config file
dcg test --config .dcg.prod.toml "docker system prune"

# Temporarily enable extra packs only for this test run
dcg test --with-packs containers.docker,database.postgresql "docker system prune"

# Read the candidate from stdin so it need not appear in dcg's own arguments
dcg test --stdin --format json < candidate-command.txt

# Apply the same wall-clock evaluation budget as the live hook
dcg test --enforce-budget --config .dcg.prod.toml "git status"

# Print full evaluation trace (same engine as `dcg explain`)
dcg test --explain "git reset --hard"

# Evaluate on the single dialect the Bash PreToolUse hook resolves
dcg test --dialect posix "echo 'AT&T'"
```

#### Exit Codes

- `0`: command would be allowed
- `1`: command would be blocked

#### Flags and Options

- `-c, --config <PATH>`: use a specific config file
- `--stdin`: read the candidate command from standard input; conflicts with the
  positional `COMMAND`
- `--with-packs <ID1,ID2>`: temporarily enable extra packs
- `--explain`: print detailed decision trace
- `-f, --format <pretty|json|toon>`: output format (default: `pretty`)
- `--no-color`: disable ANSI color output
- `--heredoc-scan`: force-enable heredoc/inline-script scanning
- `--no-heredoc-scan`: force-disable heredoc/inline-script scanning
- `--heredoc-timeout <MS>`: override heredoc extraction timeout budget
- `--heredoc-languages <LANG1,LANG2>`: limit heredoc AST scanning languages
- `--enforce-budget`: apply the effective live-hook wall-clock deadline
  (`general.hook_timeout_ms`, `DCG_HOOK_TIMEOUT_MS`, or the applicable default)
- `--dialect <unknown|posix|ps|cmd>` (also `DCG_DIALECT`): evaluate a single
  shell dialect instead of all of them. The default `unknown` fans out to every
  dialect because the CLI cannot know the source shell; `posix` reproduces the
  path the `Bash` PreToolUse hook takes and `ps` the `PowerShell` one. Use it
  when a diagnostic must match the live hook — an all-dialect run can report
  costs and evaluation paths the hook never has (for example, a literal `&`
  byte defeats quick-reject only on the all-dialect route). Also available on
  `dcg explain`.

#### Output Formats

- `pretty`: human-readable output with command context, matched rule info, and suggestions
- `json`: structured payload for scripts/CI; includes metadata like `schema_version`, `dcg_version`, `command`, `decision`, rule/pack fields, and allowlist/agent context when present
- `toon`: token-efficient structured encoding of the same payload used by `json` (useful for agent-to-agent/tool pipelines)

#### CI/CD Integration Examples

Fail fast in shell pipelines:

```bash
dcg test --format json "rm -rf /" > /tmp/dcg.json
jq -e '.decision == "allow"' /tmp/dcg.json
```

Minimal GitHub Actions step:

```yaml
- name: Validate dangerous command policy
  run: |
    ~/.local/bin/dcg test --format json "git reset --hard HEAD~1" > /tmp/dcg-test.json
    jq -e '.decision == "allow"' /tmp/dcg-test.json
```

#### Troubleshooting

- Use `--format json` (or `DCG_FORMAT=json`) for machine parsing.
- Add `--no-color` if logs or parsers choke on ANSI output.
- If results differ between environments, check trusted config precedence
  (`DCG_CONFIG`, user/system config) plus the enforcement-only settings accepted
  from an automatically discovered project `.dcg.toml`.
- If a command is unexpectedly allowed, inspect active allowlists (`dcg allowlist list`) and enabled packs (`dcg packs --verbose`).
- For full decision traces, run `dcg test --explain "<command>"` (or `dcg explain "<command>"`).

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
# Allow-once code: 123456
# To allow this: dcg allow-once 123456

# Use the short code to create a temporary exception
dcg allow-once 123456

# Or, use --single-use to make the exception one-shot
dcg allow-once 123456 --single-use
```

**How Allow-Once Works**:

1. When dcg blocks a command, it generates a short code (currently 6 numeric digits; collisions are handled via `--pick` / `--hash`)
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

### Rebase Recovery Mode

AI coding agents routinely get stuck when `git pull --rebase` fails partway — unstaged-changes errors, stash-pop conflicts, interrupted rebases. The documented recovery path is almost always `git checkout -- .` or `git restore <paths>`, both of which dcg hard-blocks (`core.git:checkout-discard`, `core.git:restore-worktree`). Agents then have to stop and ask a human to run the command manually.

Rebase-recovery mode is a narrow, bounded relaxation of those two rules that only fires under a genuine recovery signal. Outside that signal the default block is unchanged.

**Two complementary signals unlock recovery:**

1. **Active rebase state (automatic, zero-config).** When `.git/rebase-merge/` or `.git/rebase-apply/` exists, a rebase is in progress and the discard operations *are* the documented recovery path. dcg detects this state and converts the deny into an allow with a `[dcg] Allowing ... → rebase-recovery mode` note on stderr. No permit needed.

2. **Explicit permit cookie (opt-in, short-lived).** When the rebase already finished but the worktree is still messy (e.g. after a bad `git stash pop`), run:

   ```bash
   dcg rebase-recover            # default ttl: 120s
   dcg rebase-recover --ttl 60   # custom ttl (max: 600s)
   ```

   This writes a timestamp to `.dcg/rebase-recovery-permit` at the repo root. For the next N seconds (or until the first matching allow, whichever comes first), `git checkout -- <path>` and `git restore <paths>` are allowed. The permit is **single-shot** — one successful allow consumes it — so it can't silently unblock later unrelated commands within the TTL.

**Scope and safety guarantees:**

- Only four rules participate: `core.git:checkout-discard`, `core.git:checkout-ref-discard`, `core.git:restore-worktree`, `core.git:restore-worktree-explicit`.
- **Nothing else is affected.** `git reset --hard`, `git clean -f`, `git push --force`, etc. stay blocked even during an active rebase or with a permit active.
- The permit is scoped to the current repo's `.dcg/` directory. It does not cross repos.
- Expired permits are auto-cleaned on the next check.

**Typical recovery flow:**

```bash
$ git pull --rebase
# ... fails with "unstaged changes" ...
$ git stash
$ git pull --rebase        # succeeds
$ git stash pop            # leaves messy worktree
$ git checkout -- .
BLOCKED by dcg  (core.git:checkout-discard)
  ... Recovering from a failed `git pull --rebase`?
  ... Run `dcg rebase-recover` in this repo, then retry the command.
$ dcg rebase-recover
dcg rebase-recovery permit issued ...
$ git checkout -- .        # now allowed, permit consumed
$ git push
```

See issue [#104](https://github.com/Dicklesworthstone/destructive_command_guard/issues/104) for background.

The `--version` output includes build metadata for debugging:

```
dcg 0.1.0
  Built: 2026-01-07T22:13:10.413872881Z
  Rustc: 1.94.0-nightly
  Target: x86_64-unknown-linux-musl
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

The key difference from grep: `dcg scan` understands that `"rm -rf /"` in a comment is data, not code. It uses extractors that understand file structure (shell scripts, Dockerfiles, CI workflows, package scripts, Makefiles, Terraform, Docker Compose) to find only actually-executed commands.

### Supported File Formats

dcg scan includes specialized extractors for each file format, understanding which parts contain executable commands:

| File Type | Detection | Executable Contexts |
|-----------|-----------|---------------------|
| **Shell Scripts** | `*.sh`, `*.bash`, `*.zsh`, `*.dash`, `*.ksh` | Non-comment executable command lines |
| **Dockerfile** | `Dockerfile`, `Dockerfile.*`, `*.dockerfile` | `RUN` instructions (shell and exec forms) |
| **GitHub Actions** | `.github/workflows/*.yml`, `.github/workflows/*.yaml` | `run:` fields in steps |
| **GitLab CI** | `.gitlab-ci.yml`, `*.gitlab-ci.yml` | `script:`, `before_script:`, `after_script:` |
| **Azure Pipelines** | `azure-pipelines.yml`, `azure-pipelines.yaml`, `azure-pipelines-*.yml`, `azure-pipelines-*.yaml` | `script:`, `bash:`, `powershell:`, `pwsh:` tasks |
| **CircleCI** | `.circleci/config.yml`, `.circleci/config.yaml` | `run:` steps and nested `command:` fields |
| **Makefile** | `Makefile` | Tab-indented recipe lines |
| **package.json** | `package.json` | `scripts` object values |
| **Terraform** | `*.tf` | `provisioner` blocks (`local-exec`, `remote-exec`) |
| **Docker Compose** | `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml` | `command:`, `entrypoint:`, `healthcheck.test:` fields |
| **PowerShell** | `*.ps1`, `*.psm1`, `*.psd1` | Executable statements with line and block comments excluded |
| **Batch Scripts** | `*.cmd`, `*.bat` | Executable command lines with comments excluded |

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

# Enable extra packs for this scan without changing persistent config
dcg scan --paths scripts/ --with-packs careful_company_running_windows
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
# User-owned exception scoped to this checkout
repo_root=$(git rev-parse --show-toplevel)
dcg allowlist add core.git:reset-hard --reason "Required for CI cleanup" \
  --user --path "$repo_root" --path "$repo_root/**"

# Or for a specific command
dcg allowlist add-command "rm -rf ./build" --reason "Build cleanup" \
  --user --path "$repo_root" --path "$repo_root/**"
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
          curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh" | bash
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
    - curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh" | bash
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

Your AI agent invokes dcg as a PreToolUse hook before executing each shell command. The hook receives the command as JSON on stdin and runs through a four-stage pipeline:

1. **JSON Parsing** -- Validates the hook payload (Claude/Gemini/Copilot variants), extracts the command string. Non-shell tools are immediately allowed.
2. **Normalization** -- Strips absolute paths (`/usr/bin/git` becomes `git`) while preserving arguments.
3. **Quick Reject** -- O(n) substring search for keywords like "git" or "rm". Commands without these substrings skip regex matching entirely (handles 99%+ of non-destructive commands).
4. **Pattern Matching** -- Safe patterns checked first (match = allow). Destructive patterns checked second (match = deny with explanation). No match on either = allow.

If blocked under a Claude-compatible JSON hook protocol, dcg outputs a JSON
denial on stdout and a colorful human-readable warning on stderr. If blocked
under Codex CLI, dcg follows Codex's strict hook contract with minimal stdout
JSON and exit code 0. If
allowed, dcg exits silently. Rich formatting is automatically disabled for CI,
non-TTY output, dumb terminals, and no-color environments.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│   Claude / Codex / Gemini / Copilot / Cursor / Hermes hooks      │
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
                      ▼ stdout: JSON deny / empty allow
                        stderr: rich human output / Codex deny reason
┌─────────────────────────────────────────────────────────────────┐
│   Claude / Codex / Gemini / Copilot / Cursor / Hermes hooks      │
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

The safe pattern list contains narrowly scoped patterns covering:

| Category | Patterns | Purpose |
|----------|----------|---------|
| Branch creation | `checkout -b`, `checkout --orphan` | Creating branches is safe |
| Staged-only | `restore --staged`, `restore -S` | Unstaging doesn't touch working tree |
| Dry run | `clean -n`, `clean --dry-run` | Preview mode, no actual deletion |
| Temp cleanup | `rm -rf /tmp/*`, `rm -rf /var/tmp/*` | Ephemeral directories are safe |
| Dynamic temp roots | `rm -rf $TMPDIR/*`, `rm -rf ${TMPDIR}/*` | Blocked for review because the caller controls the variable |
| Quoted paths | `rm -rf "/tmp/build"` | Literal quoted temp paths are recognized safely |
| Separate flags | `rm -r -f /tmp/*`, `rm -f -r /var/tmp/*` | Flag ordering variants |
| Long flags | `rm --recursive --force /tmp/*`, `/var/tmp/*` | GNU-style long options |

### Destructive Patterns (Blacklist)

The destructive pattern list covers:

| Category | Pattern | Reason |
|----------|---------|--------|
| Work destruction | `reset --hard`, `reset --merge` | Destroys uncommitted changes |
| File reversion | `checkout -- <path>` | Discards file modifications |
| Worktree restore | `restore` (without --staged) | Discards uncommitted changes |
| Untracked deletion | `clean -f` | Permanently removes untracked files |
| History rewrite | `push --force`, `push -f` | Can destroy remote commits |
| Branch ref deletion/update | `branch -d`, `branch --delete`, `branch -D`, `branch -f`, `branch -M`, `branch -C` | Removes or force-overwrites a user-owned branch ref |
| Stash destruction | `stash drop`, `stash clear` | Permanently deletes stashed work |
| Filesystem nuke | `rm -r`, `rm -R`, `rm --recursive` (non-temp paths) | Recursive deletion outside temp, with or without `--force` |

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

`TMPDIR` is controlled by the calling environment and can point anywhere.
DCG therefore reviews variable-rooted destructive commands instead of assuming
they resolve beneath `/tmp`:

```bash
rm -rf $TMPDIR/build           # Blocked: ambient root is unknown
rm -rf ${TMPDIR}/build         # Blocked: ambient root is unknown
rm -rf "$TMPDIR/build"         # Blocked even when quoted
rm -rf "${TMPDIR}/build"       # Blocked even when quoted
rm -rf "${TMPDIR:-/tmp}/build" # Blocked: environment may override default
rm -rf /tmp/build              # Allowed: literal temp subtree
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

dcg operates under strict latency constraints - every shell command passes through the hook, so even small delays compound into noticeable sluggishness. `src/perf.rs` is the source of truth for performance budgets, CI benchmark expectations, and hook-mode deadlines.

**Latency Tiers**:

| Tier | Path | Target | Warning Above | Panic Above |
|------|------|--------|---------------|-------------|
| 0 | Quick reject | < 1μs | > 5μs | > 50μs |
| 1 | Fast path | < 75μs | > 150μs | > 500μs |
| 2 | Pattern match | < 100μs | > 250μs | > 1ms |
| 3 | Heredoc trigger | < 5μs | > 10μs | > 100μs |
| 4 | Heredoc extract | < 200μs | > 500μs | > 2ms |
| 5 | Language detect | < 20μs | > 50μs | > 200μs |
| 6 | Full heredoc pipeline | < 5ms | > 15ms | > 20ms |

Hook mode also has an absolute wall-clock evaluation deadline (ordinary
default: 1000ms; configurable). If that deadline is exhausted, dcg returns an
explicit indeterminate decision: clients that support operator review receive
`ask`, and clients without that state receive a blocking decision. A timeout
never becomes a silent allow. Use `dcg test --enforce-budget` to apply the
effective hook budget during a diagnostic test.

**Bounded Evaluation Behavior**:

If the absolute hook deadline is exhausted, dcg logs the event and marks the
command **indeterminate**:

```
[WARN] Performance budget exceeded: Tier 2 (safe patterns) took 1.2ms (panic threshold: 500μs)
[WARN] Safety evaluation incomplete; requesting review or blocking
```

This design ensures that:
1. A pathological input cannot hang the user's terminal
2. Performance regressions are visible in logs
3. The tool never mistakes elapsed time for a safety proof

**Budget Enforcement**:

```rust
let deadline = Deadline::hook_default();

if deadline.is_exceeded() || !deadline.has_budget_for(&PATTERN_MATCH) {
    return EvaluationResult::indeterminate_due_to_budget();
}
```

**Monitoring Performance**:

Use `dcg explain --verbose` to see per-stage timing:

```
Evaluation Trace:
  [  0.3μs] Tier 0: Quick reject (PASS - below 1μs target)
  [  8.7μs] Tier 1: Fast path (PASS - below 75μs target)
  [ 15.2μs] Tier 2: Pattern match (PASS - below 100μs target)
  [ 15.4μs] Total: 15.4μs (PASS - below 5ms target)
```

### Keyword-Based Pack Pre-filtering

Before expensive regex matching, dcg uses a multi-level keyword filtering system to quickly skip irrelevant packs. This is critical for performance—with 50+ packs available, checking every pattern against every command would be prohibitively slow.

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

## Output Modes

dcg separates agent-facing data from human-facing display. This lets agents
parse stable output while people watching the terminal still get readable,
high-signal formatting.

| Mode | Trigger | stdout | stderr |
|------|---------|--------|--------|
| Hook allow | Safe command | Empty | Empty |
| JSON-hook deny | Claude Code, Gemini CLI, Copilot CLI, VS Code Copilot Chat, Posit Assistant, compatible hooks | Denial JSON | Rich or plain warning |
| Hermes block | Hermes Agent shell hook (`pre_tool_call`) | `{"decision":"block","reason":...,"action":"block","message":...}` | Rich or plain warning |
| Grok deny | Grok (xAI) PreToolUse hook (`pre_tool_use` event, `run_terminal_cmd` tool) | `{"decision":"deny","reason":...}` (exit 0) | Rich or plain warning |
| Antigravity block | Antigravity CLI (`agy`) PreToolUse hook (`toolCall.name: "run_command"`) | `{"decision":"block","reason":...}` (exit 0) | Rich or plain warning |
| Codex deny | Codex CLI 0.144.x hook input | Minimal `hookSpecificOutput` deny JSON | Deny reason with command, rule, and remediation |
| Robot mode | `--robot` or `DCG_ROBOT=1` | JSON | Silent |
| Plain fallback | `DCG_NO_RICH=1`, `NO_COLOR=1`, `DCG_NO_COLOR=1`, `TERM=dumb`, `CI=1`, non-TTY output, or `--legacy-output` | Mode-specific data | Plain text only |

### Rich Human Output

Rich output is for humans and always belongs on stderr. It includes the blocked
command, severity, rule id, pack id, explanation, and safer alternatives when
available:

```text
BLOCKED  dcg
Reason:  git reset --hard destroys uncommitted changes
Rule:    core.git:reset-hard
Command: git reset --hard HEAD~1
Tip:     Use git stash to save your changes first.
```

### Plain and No-Color Output

Use plain output for logs, terminals with limited capabilities, or tests that
assert exact strings:

```bash
DCG_NO_RICH=1 dcg test "git reset --hard HEAD"
NO_COLOR=1 dcg explain "rm -rf ./build"
TERM=dumb dcg scan .
```

### Build Features

Rich terminal output is enabled by default. For a lean build without the
`rich_rust` dependency, compile with:

```bash
cargo build --release --no-default-features
```

### Agent JSON Output

For automation, prefer robot mode or the hook protocol your agent expects:

```bash
# Robot-mode scripting: parse stdout JSON, ignore stderr.
dcg --robot test "rm -rf /" >decision.json 2>/dev/null

# Claude-compatible hook integration: parse stdout only when non-empty.
dcg < hook-input.json >hook-output.json 2>human-warning.txt
```

Codex integrations should parse the minimal stdout JSON; empty stdout with exit
code 0 means allow.

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
- **Dynamic stdin producers for protected REPL binaries** ([#191](https://github.com/Dicklesworthstone/destructive_command_guard/issues/191)): dcg traces bounded literal `echo`/`printf` pipelines, single-file `cat` pipelines, `< file` redirects, and literal command substitutions into `redis-cli`, `psql`, `mysql`/`mariadb`, `mongosh`/`mongo`, and `sqlite3`; the reconstructed payload is evaluated by the consumer's own pack. It deliberately does not execute arbitrary producers to discover their output. An unknown/dynamic producer, missing or non-regular file, non-UTF-8 file, or payload over 256 KiB therefore fails closed as the stable high-severity rule `<pack>:stdin-unverified` (which can be explicitly allowlisted after review) instead of silently recreating the bypass. Direct arguments, heredocs, and here-strings remain covered by their existing paths. `kubectl delete -f -` / `--filename=-` is blocked directly unless it is a genuine client/server dry-run.
- **Unverifiable embedded-execution sinks** ([#261](https://github.com/Dicklesworthstone/destructive_command_guard/issues/261)): `eval "$(cmd)"`, `source <(cmd)`, dynamic `Invoke-Expression` input, invoked ScriptBlocks, and pipeline consumers whose executable source dcg cannot statically reconstruct fail closed under stable rule ids in the `heredoc.*` family (`heredoc.posix:eval-dynamic`, `heredoc.posix:pipeline-consumer`, `heredoc.posix:process-substitution`, `heredoc.powershell:invoke-expression-dynamic`, …), so each denial can be reviewed and allowlisted (`dcg allowlist add 'heredoc.posix:eval-dynamic' -r "reviewed" --user`) or tuned via `[policy.rules]`. One narrow carve-out exists: the documented shell-init idioms (`eval "$(ssh-agent -s)"`, `eval "$(brew shellenv)"`, `eval "$(direnv hook bash)"`, `eval "$(pyenv init -)"`, `rbenv`/`starship`/`zoxide`/`mise` init/activate, and `source <(kubectl completion bash)`) are recognized as **exact literal argv shapes** — one plain producer segment, no chaining, redirection, nesting, quoting tricks, or path-qualified executables — and downgrade to a recorded warning under `heredoc.posix:eval-init-idiom`. Every near miss keeps the hard denial, and posture can promote the idioms back with `[policy.rules] "heredoc.posix:eval-init-idiom" = "deny"`. Note the residual: the allowance rests on the producer binary's *identity*; PATH order, shell functions, and aliases are outside dcg's static view.

### Threat Model

This hook assumes the AI agent is **well-intentioned but fallible**. It's designed to catch honest mistakes, not adversarial attacks. The hook runs with the same permissions as the Claude Code process.

## Troubleshooting

### Hook not blocking commands

1. **Check hook registration**: Verify `~/.claude/settings.json` contains the hook configuration
2. **Restart Claude Code**: Configuration changes require a restart
3. **Check binary location**: Ensure `dcg` is in your PATH
4. **Test manually**: Run `echo '{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}}' | dcg`

### Hook silently removed (recommended: add shell startup check)

Claude Code can silently remove the dcg hook when it rewrites `~/.claude/settings.json`. This means you may lose protection without any warning.

**Automatic setup** -- `dcg setup` installs the hook *and* offers to add a shell startup check:

```bash
dcg setup               # Interactive — prompts before modifying RC files
dcg setup --shell-check # Non-interactive — adds the check automatically
```

**Manual setup** -- add this snippet to your `~/.zshrc` and/or `~/.bashrc`:

```bash
# dcg: warn if hook was silently removed from Claude Code settings
if command -v dcg &>/dev/null && command -v jq &>/dev/null; then
  if [ -f "$HOME/.claude/settings.json" ] && \
     ! jq -e '.hooks.PreToolUse[]? | select(.hooks[]?.command | test("dcg\"?$"))' \
       "$HOME/.claude/settings.json" &>/dev/null; then
    printf '\033[1;33m[dcg] Hook missing from ~/.claude/settings.json — run: dcg install\033[0m\n'
  fi
fi
```

This check:
- Runs in milliseconds (no noticeable shell startup delay)
- Is completely silent when the hook is present
- Shows a yellow warning only when the hook is missing
- Gracefully skips if `dcg`, `jq`, or `settings.json` are absent
- Works identically in bash and zsh

> **Note:** The `install.sh` installer also offers to add this check during installation.

### Hook blocking safe commands

1. **Check for false positives**: Some edge cases may not be covered by safe patterns
2. **File an issue**: Report the command that was incorrectly blocked
3. **Temporary bypass**: Have the user run the command manually in a separate terminal
4. **Add to allowlist**: Use the allowlist feature below for persistent overrides

### Resolving False Positives with Allowlists

If dcg blocks a command that is safe in your specific context, you can add it
to an allowlist. Effective allowlists are checked in this order:

1. **Explicitly trusted project** (`.dcg/allowlist.toml`): Active only when
   `DCG_CONFIG` selects the canonical repo-root `.dcg.toml` for that invocation
2. **User** (`~/.config/dcg/allowlist.toml`): Applies to all your projects
3. **System** (`/etc/dcg/allowlist.toml`): Applies system-wide

A checked-in project allowlist is inert by default. This prevents a newly
cloned repository from granting itself permission to run destructive commands.
All mutation commands default to the user layer; use repeatable `--path` flags
to constrain an exception to a repository root and its descendants.

**Adding a rule to the allowlist:**

```bash
# Allow a specific rule by ID (recommended)
dcg allowlist add core.git:reset-hard -r "Used for CI cleanup"

# Scope a user-owned exception to one repository
repo_root=$(git rev-parse --show-toplevel)
dcg allowlist add core.git:reset-hard -r "CI cleanup" --user \
  --path "$repo_root" --path "$repo_root/**"

# Add to the user allowlist globally
dcg allowlist add core.git:reset-hard -r "Personal workflow" --user

# After reviewing .dcg.toml, explicitly activate and edit project policy
DCG_CONFIG="$repo_root/.dcg.toml" dcg allowlist add \
  core.git:reset-hard -r "Reviewed project policy" --project

# Allow with expiration (ISO 8601 format)
dcg allowlist add core.git:clean-force -r "Migration" --expires "2026-02-01T00:00:00Z"

# Allow a specific command (exact match) using add-command
dcg allowlist add-command "rm -rf ./build" -r "Build cleanup"
```

**Listing allowlist entries:**

```bash
# List entries from effective layers only
dcg allowlist list

# Inspect the raw project file (marked INACTIVE when it is untrusted)
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

# Remove from explicitly trusted project policy
DCG_CONFIG="$repo_root/.dcg.toml" dcg allowlist remove \
  core.git:reset-hard --project
```

**Validating allowlist files:**

```bash
# Check for issues (expired entries, invalid patterns)
dcg allowlist validate

# Strict mode: treat warnings as errors
dcg allowlist validate --strict
```

**Pruning expired entries:**

```bash
# Preview expired entries without changing files
dcg allowlist prune --dry-run

# Remove expired entries from effective layers (user, plus trusted project)
dcg allowlist prune
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

### Per-Rule Target-Path Exemptions

Agent runtimes hand each job a scratch directory under `$HOME` — Claude Code
uses `~/.claude/jobs/<id>/tmp`. An agent writing its own logs there trips
`core.filesystem:redirect-truncate-root-home` and the `rm -rf` rules over and
over, for a path that only the agent owns.

`[overrides] allow` is the wrong tool for that: it matches the whole command,
so a pattern written for the log write also admits
`<safe-op> && git reset --hard`. A target exemption is narrower — it is
evaluated *inside one rule's target check*:

```toml
[rules."core.filesystem:redirect-truncate-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**"]

[rules."core.filesystem:rm-rf-root-home"]
exempt_target_globs = ["~/.claude/jobs/*/tmp/**"]
```

When that rule matches, dcg resolves the operation's target path. If the target
is a literal path under one of the globs, **that one rule** does not fire.
Every other rule still evaluates the complete command, so
`echo x > ~/.claude/jobs/abc/tmp/log && git reset --hard` is still denied — by
`core.git:reset-hard`, on its own merits.

**Wiring doctor into automation.** `dcg doctor` exits `0` by default, even when
it reports `"ok": false` — so `dcg doctor || handle_failure` is dead code unless
you ask for the verdict. Use `--strict` to make the exit status carry it:

```bash
dcg doctor --strict            # non-zero when checks fail
dcg doctor --format json --strict
```

The default is unchanged so existing pipelines keep working, and both output
formats answer identically.

**Supported rules.** Target exemptions apply only where a literal target is
actually resolvable. Configuring them anywhere else is inert, and
`dcg doctor` warns about it rather than leaving you quietly unserved:

| Rule | Target |
|------|--------|
| `core.filesystem:redirect-truncate-root-home` | The redirect target(s) |
| `core.filesystem:rm-rf-general` | Every `rm` operand |
| `core.filesystem:rm-rf-root-home` | Every `rm` operand |
| `core.filesystem:rm-r-f-separate` | Every `rm` operand |
| `core.filesystem:rm-r-f-separate-root-home` | Every `rm` operand |
| `core.filesystem:rm-recursive-force` | Every `rm` operand |
| `core.filesystem:rm-recursive-force-root-home` | Every `rm` operand |
| `core.filesystem:rm-recursive-general` | Every `rm` operand |
| `core.filesystem:rm-recursive-root-home` | Every `rm` operand |

Note that `rm -rf ~/...` is attributed to `rm-rf-root-home`, not
`rm-rf-general`: any `~`- or `/`-rooted operand is the Critical root/home rule.
Check `dcg explain "<command>"` for the rule id you actually need.

**Dynamic paths are never exempted.**
`core.filesystem:redirect-truncate-dynamic-path` deliberately supports no
exemptions. It exists precisely because the runtime target cannot be proven, so
a glob over it would be a bypass, not a carve-out. `echo x > $DIR/log` stays
denied no matter what is configured. The same rule applies inside the supported
rules: a target containing a variable, command substitution, backtick, glob, or
`%VAR%` is not a literal, and is never matched against an exemption glob.

**Glob semantics.**

- `~` and `~/` expand to the user's home directory; `~user` is not supported.
- `*` matches within a single path component; `**` crosses separators.
- Matching is case-sensitive on every platform, like the scan include/exclude
  globs.
- Matching is lexical only — no `stat`, no canonicalization, no symlink
  resolution. A symlinked path is matched by its literal spelling, so a glob
  over `~/.claude/jobs/*/tmp/**` does not follow a symlink planted inside it.
- A target containing a `..` component is rejected outright rather than
  resolved: `rm -rf ~/.claude/jobs/abc/tmp/../../../Documents` never matches.
  Globs containing `..` are rejected at load.
- An operation with several targets must prove *every* target exempt.
  `rm -rf ~/.claude/jobs/abc/tmp/scratch ~/.ssh` stays denied.
- Single-quoted `rm` operands are never exempted: the shell does not expand `~`
  inside them, so the literal spelling names a different path.

**Trust boundary.** A target exemption reduces coverage, so it follows the same
rule as every other trust-reducing setting (see
[Configuration Hierarchy](#configuration-hierarchy)): it is **ignored** when it
comes from an automatically discovered `.dcg.toml`. It is honored from the
system config, the user config, and an explicit `DCG_CONFIG` file.

**Output.** A suppressed rule is an allow that came from configuration, so it
is not silent: with `general.verbose = true`, dcg notes on stderr which rule
matched, which target it saw, and which glob exempted it.

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

The repository includes a comprehensive E2E test script with hundreds of command scenarios:

```bash
# Run full E2E test suite
./scripts/e2e_test.sh

# With verbose output
./scripts/e2e_test.sh --verbose

# With specific binary path
./scripts/e2e_test.sh --binary ./target/release/dcg
```

Codex CLI integration has a separate opt-in harness because it drives a real
authenticated `codex exec` session against hermetic temporary repositories:

```bash
# Run the real Codex CLI smoke harness
./scripts/e2e_codex.sh --verbose --dcg-binary ./target/release/dcg

# Capture JSONL trace and failure artifacts for postmortems
./scripts/e2e_codex.sh --json --artifacts ./artifacts/codex-e2e --dcg-binary ./target/release/dcg
```

The Codex harness exits successfully with an explicit skipped status when Codex
is unavailable or unauthenticated, so CI and developer machines without Codex
access can run it without producing false failures. A full local run requires
`codex` 0.125.0 or newer on `PATH` plus an authenticated `codex login status`;
when Codex is responsive, expect roughly five minutes, with longer runtimes
possible under rate limiting.

Useful debugging flags:

- `--verbose` mirrors the per-scenario logging style from `scripts/e2e_test.sh`.
- `--artifacts DIR` writes `trace.jsonl` plus per-failure stdout, stderr,
  prompts, repository state, manifests, and diffs.
- `--keep-tempdirs` preserves temporary repositories and isolated Codex homes for
  manual inspection after a failed run.

CI runs `./scripts/e2e_codex.sh --verbose --json --artifacts
/tmp/codex_e2e_artifacts` in a dedicated `codex-e2e` job on pushes to `main`
only. The job installs Codex with npm, authenticates from the `CODEX_API_KEY`
secret, and still goes green with a clear notice when Codex is unavailable,
unauthenticated, quota-limited, or temporarily unable to reach the API.

The E2E suite covers:
- All destructive git commands (reset, checkout, restore, clean, push, branch, stash)
- Safe git commands (status, log, diff, add, commit, push, read-only branch listings)
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

- Builds optimized binaries for 6 platforms:
  - Linux x86_64, statically linked with musl (`x86_64-unknown-linux-musl`)
  - Linux ARM64 (`aarch64-unknown-linux-gnu`)
  - macOS Intel (`x86_64-apple-darwin`)
  - macOS Apple Silicon (`aarch64-apple-darwin`)
  - Windows x64 (`x86_64-pc-windows-msvc`)
  - Windows ARM64 (`aarch64-pc-windows-msvc`)
- Creates `.tar.xz` archives (Unix) or `.zip` (Windows)
- Generates SHA256 checksums for verification
- Publishes to GitHub Releases with auto-generated release notes

To create a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## FAQ

**Q: Why block both `git branch -d` and `git branch -D`?**

Lowercase `-d` verifies that Git considers a branch merged, but it still removes the branch name, upstream-tracking configuration, and convenient reflog reference. Those are user-owned state and may still matter after a merge. DCG therefore treats every branch deletion as an approval boundary; use `git branch -vv`, `git branch --merged`, and `git branch --no-merged` to review state without changing refs.

**Q: Why is `git push --force-with-lease` allowed?**

Force-with-lease is a safer alternative that refuses to push if the remote has commits you haven't seen. It prevents accidentally overwriting someone else's work.

**Q: Why block recursive `rm` outside temp directories?**

Recursive deletion can silently remove an ordinary writable directory tree even
without `-f`. A typo, unexpected working directory, or wrong variable expansion
can therefore destroy critical files with `rm -r`, `rm -R`, or their forced
variants. DCG treats all of those forms as an approval boundary, while retaining
the narrowly bounded policy for literal `/tmp` and `/var/tmp` subdirectories.

**Q: Can I add custom patterns?**

Yes. Create YAML pack files and point to them in your config. See the [Custom Packs](#custom-packs) section and [`docs/custom-packs.md`](docs/custom-packs.md) for the schema and examples.

**Q: What if I really need to run a blocked command?**

See [Escape Hatch / Bypass](#escape-hatch--bypass). Options include `DCG_BYPASS=1`, allow-once codes, permanent allowlists, or running the command manually in a separate terminal.

**Q: Does this work with other AI coding tools?**

Yes. dcg natively supports Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, VS Code Copilot Chat, and Cursor IDE hook paths. Aider has limited git-hook support, and Continue is detected but cannot be auto-configured because it does not expose a pre-execution shell hook.

**Q: What about database, Docker, Kubernetes, and cloud commands?**

dcg includes 50+ packs covering all of these. See the [Modular Pack System](#modular-pack-system) section for the full list. Enable the packs you need in your config.

## Contributing

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

Custom source license based on MIT with an OpenAI/Anthropic rider. See
[LICENSE](LICENSE) for the complete terms.

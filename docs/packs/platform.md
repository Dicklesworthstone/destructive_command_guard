# Platform Packs

This document describes packs in the `platform` category.

## Packs in this Category

- [GitHub Platform](#platformgithub)
- [GitLab Platform](#platformgitlab)
- [Railway Platform](#platformrailway)
- [Modal Platform](#platformmodal)
- [Kamal](#platformkamal)

---

## GitHub Platform

**Pack ID:** `platform.github`

Protects against destructive GitHub CLI operations like deleting repositories, gists, releases, or SSH keys.

### Keywords

Commands containing these keywords are checked against this pack:

- `gh`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `gh-repo-list-view` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+repo\s+(?:list\|view)\b` |
| `gh-gist-list-view` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+gist\s+(?:list\|view)\b` |
| `gh-release-list-view` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+release\s+(?:list\|view)\b` |
| `gh-issue-list-view` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+issue\s+(?:list\|view)\b` |
| `gh-ssh-key-list` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+ssh-key\s+list\b` |
| `gh-secret-list` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+secret\s+list\b` |
| `gh-variable-list` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+variable\s+list\b` |
| `gh-auth-status` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+auth\s+status\b` |
| `gh-status` | `gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+status\b` |
| `gh-api-explicit-get` | `^(?!(?=.*(?:-X\s*\|--method(?:=\|\s+))DELETE\b))gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo\|gist\|release\|issue\|ssh-key\|secret\|variable\|run\|auth\|status\|api)\b)(?:(?:\x22[^\x22]*\x22)\|(?:'[^']*')\|\S+))?)*\s+api\b.*(?:-X\s*\|--method(?:=\|\s+))GET\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `gh-repo-delete` | gh repo delete permanently deletes a GitHub repository. This cannot be undone. | high |
| `gh-repo-archive` | gh repo archive makes a repository read-only. While reversible, it stops all write access. | high |
| `gh-gist-delete` | gh gist delete permanently deletes a Gist. | high |
| `gh-release-delete` | gh release delete permanently deletes a release. | high |
| `gh-issue-delete` | gh issue delete permanently deletes an issue. | high |
| `gh-ssh-key-delete` | gh ssh-key delete removes an SSH key, potentially breaking access. | high |
| `gh-secret-delete` | gh secret delete removes GitHub Actions secrets. | high |
| `gh-variable-delete` | gh variable delete removes GitHub Actions variables. | high |
| `gh-repo-deploy-key-delete` | gh repo deploy-key delete removes a deploy key and can break access. | high |
| `gh-run-cancel` | gh run cancel stops a workflow run and may interrupt deployments. | high |
| `gh-api-delete-actions-secret` | gh api DELETE actions/secrets removes GitHub Actions secrets. | high |
| `gh-api-delete-actions-variable` | gh api DELETE actions/variables removes GitHub Actions variables. | high |
| `gh-api-delete-hook` | gh api DELETE hooks removes repository webhooks. | high |
| `gh-api-delete-deploy-key` | gh api DELETE keys removes deploy keys. | high |
| `gh-api-delete-release` | gh api DELETE releases removes GitHub releases. | high |
| `gh-api-delete-repo` | gh api DELETE calls can be destructive. Please verify the endpoint. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "platform.github:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "platform.github:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## GitLab Platform

**Pack ID:** `platform.gitlab`

Protects against destructive GitLab platform operations like deleting projects, releases, protected branches, and webhooks.

### Keywords

Commands containing these keywords are checked against this pack:

- `glab`
- `gitlab-rails`
- `gitlab-rake`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `glab-repo-list` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+list\b` |
| `glab-repo-view` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+view\b` |
| `glab-repo-clone` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+clone\b` |
| `glab-mr-list` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+mr\s+list\b` |
| `glab-mr-view` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+mr\s+view\b` |
| `glab-issue-list` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+issue\s+list\b` |
| `glab-issue-view` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+issue\s+view\b` |
| `glab-variable-list` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+list\b` |
| `glab-release-list` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+list\b` |
| `glab-release-view` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+view\b` |
| `glab-api-explicit-get` | `glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*\|--method(?:=\|\s+))GET\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `glab-repo-delete` | glab repo delete permanently deletes a GitLab project. | high |
| `glab-repo-archive` | glab repo archive makes a GitLab project read-only. | high |
| `glab-release-delete` | glab release delete removes GitLab releases. | high |
| `glab-variable-delete` | glab variable delete removes GitLab CI/CD variables. | high |
| `glab-api-delete-project` | glab api DELETE /projects/* deletes a GitLab project. | high |
| `glab-api-delete-release` | glab api DELETE releases removes GitLab releases. | high |
| `glab-api-delete-variable` | glab api DELETE variables removes CI/CD variables. | high |
| `glab-api-delete-protected-branch` | glab api DELETE protected_branches removes branch protections. | high |
| `glab-api-delete-hook` | glab api DELETE hooks removes GitLab webhooks. | high |
| `gitlab-rails-runner-destructive` | gitlab-rails runner destructive operations can remove data. | high |
| `gitlab-rake-destructive` | gitlab-rake destructive maintenance tasks can delete or replace data. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "platform.gitlab:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "platform.gitlab:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Railway Platform

**Pack ID:** `platform.railway`

Protects against destructive Railway CLI and Public API operations that can delete projects, environments, services, functions, volumes, variables, or deployments.

### Keywords

Commands containing these keywords are checked against this pack:

- `railway`
- `backboard.railway.app`
- `backboard.railway.com`
- `railway.app/graphql`
- `railway.com/graphql`
- `Project-Access-Token`
- `PROJECT_ACCESS_TOKEN`
- `projectDelete`
- `projectScheduleDelete`
- `environmentDelete`
- `serviceDelete`
- `volumeDelete`
- `volumeInstanceDelete`
- `volumeInstanceBackupDelete`
- `volumeInstanceBackupRestore`
- `volumeInstanceBackupScheduleUpdate`
- `volumeInstanceUpdate`
- `variableDelete`
- `variableUpsert`
- `variableCollectionUpsert`
- `deploymentRemove`
- `deploymentStop`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `railway-status` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?:\s\|$)` |
| `railway-project-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list\|ls)(?:\s\|$)` |
| `railway-project-subcommand-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+(?:list\|ls)(?:\s\|$)` |
| `railway-whoami` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?:\s\|$)` |
| `railway-logs` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?:\s\|$)` |
| `railway-service-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+(?:list\|ls)(?:\s\|$)` |
| `railway-function-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:function\|functions\|func\|funcs\|fn\|fns)\s+(?:list\|ls)(?:\s\|$)` |
| `railway-environment-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:environment\|env)\s+(?:list\|ls)(?:\s\|$)` |
| `railway-volume-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:list\|ls)(?:\s\|$)` |
| `railway-variable-list` | `(?<![\w-])railway\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable\|variables\|vars\|var)\s+(?:list\|ls)(?:\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `railway-project-delete` | railway delete schedules deletion of the entire Railway project. | critical |
| `railway-project-subcommand-delete` | railway project delete schedules deletion of the entire Railway project. | critical |
| `railway-environment-delete` | railway environment delete removes a Railway environment and its resources. | critical |
| `railway-service-delete` | railway service delete permanently deletes a Railway service. | critical |
| `railway-function-delete` | railway functions delete removes a Railway serverless function. | critical |
| `railway-volume-delete` | railway volume delete removes persistent Railway storage. | critical |
| `railway-volume-detach` | railway volume detach disconnects persistent storage from a service. | high |
| `railway-variable-delete` | railway variable delete removes Railway environment variables. | high |
| `railway-database-variable-set` | railway variable set is changing a database connection variable. | high |
| `railway-database-variable-legacy-set` | railway variable legacy flags are changing a database connection variable. | high |
| `railway-deployment-remove` | railway down removes the latest successful deployment. | high |
| `railway-api-project-delete` | Railway Public API project deletion mutation detected. | critical |
| `railway-api-environment-delete` | Railway Public API environment deletion mutation detected. | critical |
| `railway-api-service-delete` | Railway Public API service deletion mutation detected. | critical |
| `railway-api-volume-delete` | Railway Public API volume deletion mutation detected. | critical |
| `railway-api-volume-backup-restore` | Railway Public API volume backup restore mutation detected. | critical |
| `railway-api-volume-backup-delete` | Railway Public API volume backup deletion mutation detected. | high |
| `railway-api-volume-backup-schedule-update` | Railway Public API volume backup schedule update mutation detected. | high |
| `railway-api-volume-detach` | Railway Public API volume detach mutation detected. | high |
| `railway-api-variable-delete` | Railway Public API variable deletion mutation detected. | high |
| `railway-api-variable-collection-replace` | Railway Public API variableCollectionUpsert with replace=true detected. | high |
| `railway-api-database-variable-upsert` | Railway Public API upsert is changing a database connection variable. | high |
| `railway-api-deployment-remove` | Railway Public API deployment removal or stop mutation detected. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "platform.railway:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "platform.railway:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Modal Platform

**Pack ID:** `platform.modal`

Protects against destructive Modal CLI operations that can delete or wipe Modal Volumes, Secrets, Apps, Containers, Environments, Dicts, or Queues. Catches commands even when `-y`/`--yes` is passed to bypass interactive confirmation.

### Keywords

Commands containing these keywords are checked against this pack:

- `modal`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `modal-volume-list` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:list\|ls)\b` |
| `modal-volume-get` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:get\|cp\|cat)\b` |
| `modal-volume-create` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:create\|rename)\b` |
| `modal-app-readonly` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+app\s+(?:list\|ls\|logs\|history\|dashboard\|rollback\|rollover)\b` |
| `modal-container-readonly` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+container\s+(?:list\|ls\|logs\|exec)\b` |
| `modal-secret-list` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+(?:list\|ls)\b` |
| `modal-secret-create-no-force` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+create\b(?!(?:[^;&\|\r\n]\|\\\r?\n)*(?:--force\|--overwrite)\b)` |
| `modal-environment-list` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:list\|ls)\b` |
| `modal-environment-mutate` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:create\|update)\b` |
| `modal-dict-readonly` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+(?:list\|ls\|get\|items\|create)\b` |
| `modal-queue-readonly` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+(?:list\|ls\|peek\|len\|create)\b` |
| `modal-shell` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+shell\b` |
| `modal-deploy` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:deploy\|serve\|run\|profile\|launch)\b` |
| `modal-token` | `(?<![\w-])modal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+(?:info\|new\|set)\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `modal-environment-delete` | modal environment delete schedules removal of an entire Modal environment. | critical |
| `modal-volume-delete` | modal volume delete removes a Modal Volume and all data inside it. | critical |
| `modal-secret-delete` | modal secret delete permanently removes a published Modal Secret. | critical |
| `modal-dict-delete` | modal dict delete removes a named Modal Dict and all its data. | critical |
| `modal-queue-delete` | modal queue delete removes a named Modal Queue and all its data. | critical |
| `modal-app-stop` | modal app stop terminates a Modal app and its running containers. | high |
| `modal-container-stop` | modal container stop terminates a running Modal container and reassigns inputs. | high |
| `modal-volume-rm-recursive` | modal volume rm -r recursively deletes files inside a Modal Volume. | high |
| `modal-dict-clear` | modal dict clear empties a Modal Dict. | high |
| `modal-queue-clear` | modal queue clear drains every message from a Modal Queue. | high |
| `modal-volume-rm` | modal volume rm deletes a file inside a Modal Volume. | medium |
| `modal-secret-create-force` | modal secret create --force overwrites an existing Modal Secret in place. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "platform.modal:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "platform.modal:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Kamal

**Pack ID:** `platform.kamal`

Protects against destructive Kamal 2.x operations that tear down the stack, delete accessory data directories, drop proxy routing, take the app offline, or prune the images that rollback depends on.

### Keywords

Commands containing these keywords are checked against this pack:

- `kamal`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `kamal-audit` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?:\s\|$)` |
| `kamal-details` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+details(?:\s\|$)` |
| `kamal-config` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?:\s\|$)` |
| `kamal-secrets` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets(?:\s\|$)` |
| `kamal-deploy` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deploy(?:\s\|$)` |
| `kamal-redeploy` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+redeploy(?:\s\|$)` |
| `kamal-setup` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+setup(?:\s\|$)` |
| `kamal-build` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?:\s\|$)` |
| `kamal-rollback` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+rollback(?:\s\|$)` |
| `kamal-upgrade` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+upgrade(?:\s\|$)` |
| `kamal-registry` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+registry\s+(?:login\|logout)(?:\s\|$)` |
| `kamal-lock` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+lock(?:\s\|$)` |
| `kamal-server-bootstrap` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+server\s+bootstrap(?:\s\|$)` |
| `kamal-init` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+init(?:\s\|$)` |
| `kamal-docs` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+docs(?:\s\|$)` |
| `kamal-help` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+help(?:\s\|$)` |
| `kamal-version` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?:\s\|$)` |
| `kamal-app-safe` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot\|start\|restart\|details\|containers\|images\|logs\|version\|stale_containers\|maintenance\|live)(?:\s\|$)` |
| `kamal-accessory-safe` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot\|start\|restart\|details\|logs\|upgrade)(?:\s\|$)` |
| `kamal-proxy-safe` | `(?<![\w-])kamal\b(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot\|boot_config\|start\|restart\|details\|logs)(?:\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `kamal-remove` | kamal remove tears down the entire deployment, including stateful accessories. | critical |
| `kamal-accessory-remove` | kamal accessory remove deletes the accessory container, image, AND its host data directory. | critical |
| `kamal-app-remove` | kamal app remove takes the app offline by removing its containers and images. | high |
| `kamal-app-stop` | kamal app stop stops the app container, causing an outage until restarted. | high |
| `kamal-proxy-remove` | kamal proxy remove drops routing for every app behind that proxy on the host. | high |
| `kamal-proxy-reboot` | kamal proxy reboot stops, removes, and recreates the proxy, causing a short outage. | high |
| `kamal-proxy-stop` | kamal proxy stop drops routing for every app behind that proxy until it is started. | high |
| `kamal-accessory-reboot` | kamal accessory reboot stops, removes, and recreates the accessory container (downtime). | high |
| `kamal-accessory-stop` | kamal accessory stop stops the accessory (e.g. the database), erroring the app. | high |
| `kamal-prune` | kamal prune removes older images/containers that kamal rollback relies on. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "platform.kamal:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "platform.kamal:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

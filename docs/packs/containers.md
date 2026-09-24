# Container Packs

This document describes packs in the `containers` category.

## Packs in this Category

- [Docker](#containersdocker)
- [Docker Compose](#containerscompose)
- [Podman](#containerspodman)

---

## Docker

**Pack ID:** `containers.docker`

Protects against destructive Docker operations like system prune, volume prune, and force removal

### Keywords

Commands containing these keywords are checked against this pack:

- `docker`
- `prune`
- `rmi`
- `volume`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `docker-ps` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ps(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-images` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+images(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-logs` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-inspect` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-build` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-pull` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+pull(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-run` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-exec` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+exec(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-stats` | `^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stats(?=\s\|$)(?:\s+[^;&\|`$()]*)*$` |
| `docker-dry-run` | `^\s*docker\b(?:\s+[^;&\|`$()]*)*--dry-run(?:\s+[^;&\|`$()]*)*$` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `system-prune` | docker system prune removes ALL unused containers, networks, images. Use 'docker system df' to preview. | high |
| `volume-prune` | docker volume prune removes ALL unused volumes and their data permanently. | high |
| `network-prune` | docker network prune removes ALL unused networks. | high |
| `image-prune` | docker image prune removes unused images. Use 'docker images' to review first. | medium |
| `container-prune` | docker container prune removes ALL stopped containers. | medium |
| `rm-force` | docker rm -f forcibly removes containers, potentially losing data. | high |
| `rmi-force` | docker rmi -f forcibly removes images even if in use. | high |
| `volume-rm` | docker volume rm permanently deletes volumes and their data. | high |
| `stop-all` | Stopping/killing all containers can disrupt services. Be specific about which containers. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "containers.docker:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "containers.docker:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Docker Compose

**Pack ID:** `containers.compose`

Protects against destructive Docker Compose operations like 'down -v' which removes volumes

### Keywords

Commands containing these keywords are checked against this pack:

- `docker-compose`
- `docker compose`
- `podman-compose`
- `podman compose`
- `compose`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `compose-config` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+config` |
| `compose-ps` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+ps` |
| `compose-logs` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+logs` |
| `compose-up` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+up` |
| `compose-build` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+build` |
| `compose-pull` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+pull` |
| `compose-down-no-volumes` | `(?:docker-compose\|docker\s+compose\|podman-compose\|podman\s+compose)\s+(?:-[^\s;\|&`()<>]*\s+(?:[^\s;\|&`()<>-][^\s;\|&`()<>]*\s+)?)*down(?!\s+.*(?:-[vt]*v[vt]*\b\|--volumes\|--rmi))(?:\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `down-volumes` | docker-compose down -v removes volumes and their data permanently. | critical |
| `down-rmi-all` | docker-compose down --rmi all removes all images used by services. | high |
| `rm-volumes` | docker-compose rm -v removes volumes attached to containers. | high |
| `rm-force` | docker-compose rm -f forcibly removes containers without confirmation. | medium |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "containers.compose:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "containers.compose:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Podman

**Pack ID:** `containers.podman`

Protects against destructive Podman operations like system prune, volume prune, and force removal

### Keywords

Commands containing these keywords are checked against this pack:

- `podman`
- `prune`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `podman-ps` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ps(?=\s\|$)` |
| `podman-images` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+images(?=\s\|$)` |
| `podman-logs` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s\|$)` |
| `podman-inspect` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s\|$)` |
| `podman-build` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?=\s\|$)` |
| `podman-pull` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+pull(?=\s\|$)` |
| `podman-run` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s\|$)` |
| `podman-exec` | `podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+exec(?=\s\|$)` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `system-prune` | podman system prune removes ALL unused containers, pods, images. Use 'podman system df' to preview. | high |
| `system-reset` | podman system reset deletes ALL containers, pods, images, networks and volumes. | critical |
| `volume-prune` | podman volume prune removes ALL unused volumes and their data permanently. | critical |
| `pod-prune` | podman pod prune removes ALL stopped pods. | medium |
| `image-prune` | podman image prune removes unused images. Use 'podman images' to review first. | medium |
| `container-prune` | podman container prune removes ALL stopped containers. | medium |
| `rm-force` | podman rm -f forcibly removes containers, potentially losing data. | high |
| `rmi-force` | podman rmi -f forcibly removes images even if in use. | high |
| `volume-rm` | podman volume rm permanently deletes volumes and their data. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "containers.podman:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "containers.podman:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

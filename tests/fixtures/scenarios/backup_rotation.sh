#!/usr/bin/env bash
# Backup rotation workflow with retention enforcement.
set -euo pipefail

# Restic backup and prune
restic backup /srv/data
restic snapshots
restic forget --keep-daily 7 --keep-weekly 4 --prune
restic prune

# Borg backup and prune
borg create repo::archive-2025-01-10 /srv/data
borg list repo
borg prune --keep-last 3 --keep-daily 7

# Velero cleanup
velero backup get
velero backup delete daily-backup --confirm
velero schedule delete nightly --confirm

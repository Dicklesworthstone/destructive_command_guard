# Database Packs

This document describes packs in the `database` category.

## Packs in this Category

- [PostgreSQL](#databasepostgresql)
- [MySQL/MariaDB](#databasemysql)
- [MongoDB](#databasemongodb)
- [Redis](#databaseredis)
- [SQLite](#databasesqlite)
- [Supabase](#databasesupabase)

---

## PostgreSQL

**Pack ID:** `database.postgresql`

Protects against destructive PostgreSQL operations like DROP DATABASE, TRUNCATE, and dropdb

### Keywords

Commands containing these keywords are checked against this pack:

- `psql`
- `dropdb`
- `DROP`
- `TRUNCATE`
- `pg_dump`
- `postgres`
- `DELETE`
- `delete`
- `drop`
- `truncate`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `pg-dump-no-clean` | `pg_dump\s+(?!.*--clean)(?!.*-c\b)` |
| `select-query` | `(?i)^\s*SELECT\s+` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-database` | DROP DATABASE permanently deletes the entire database (even with IF EXISTS). Verify and back up first. | critical |
| `drop-table` | DROP TABLE permanently deletes the table (even with IF EXISTS). Verify and back up first. | high |
| `drop-schema` | DROP SCHEMA permanently deletes the schema and all its objects (even with IF EXISTS). | critical |
| `truncate-table` | TRUNCATE permanently deletes all rows without logging individual deletions. | high |
| `delete-without-where` | DELETE without WHERE clause deletes ALL rows. Add a WHERE clause or use TRUNCATE intentionally. | high |
| `dropdb-cli` | dropdb permanently deletes the entire database. Verify the database name carefully. | critical |
| `pg-dump-clean` | pg_dump --clean drops objects before creating them. This can be destructive on restore. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.postgresql:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.postgresql:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## MySQL/MariaDB

**Pack ID:** `database.mysql`

Protects against destructive MySQL/MariaDB operations like DROP DATABASE, TRUNCATE, and mysqladmin drop

### Keywords

Commands containing these keywords are checked against this pack:

- `mysql`
- `mysqladmin`
- `mysqldump`
- `mariadb`
- `DROP`
- `TRUNCATE`
- `DELETE`
- `delete`
- `drop`
- `truncate`
- `GRANT`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `select-query` | `(?i)^\s*SELECT\s+` |
| `show-command` | `(?i)^\s*SHOW\s+` |
| `describe-query` | `(?i)^\s*(?:DESCRIBE\|DESC\|EXPLAIN)\s+` |
| `mysqldump-no-drop` | `mysqldump\s+(?!.*--add-drop-database)(?!.*--add-drop-table)` |
| `mysql-select` | `mysql\s+.*(?:-e\|--execute)\s*['"]?\s*SELECT` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-database` | DROP DATABASE permanently deletes the entire database. Verify and back up first. | critical |
| `drop-table` | DROP TABLE permanently deletes the table. Verify and back up first. | high |
| `truncate-table` | TRUNCATE permanently deletes all rows. Cannot be rolled back in MySQL. | high |
| `delete-without-where` | DELETE without WHERE clause deletes ALL rows. Add a WHERE clause. | high |
| `mysqladmin-drop` | mysqladmin drop permanently deletes the database. Verify carefully. | critical |
| `mysqldump-add-drop-database` | mysqldump --add-drop-database drops the database before restore. | high |
| `mysqldump-add-drop-table` | mysqldump --add-drop-table drops tables before creating them on restore. | medium |
| `grant-all` | GRANT ALL ON *.* gives unrestricted access to all databases. | high |
| `drop-user` | DROP USER permanently removes the user account and all their privileges. | medium |
| `reset-master` | RESET MASTER deletes all binary logs and resets the binlog position. | critical |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.mysql:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.mysql:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## MongoDB

**Pack ID:** `database.mongodb`

Protects against destructive MongoDB operations like dropDatabase, dropCollection, and remove without criteria

### Keywords

Commands containing these keywords are checked against this pack:

- `mongo`
- `mongosh`
- `dropDatabase`
- `dropCollection`
- `deleteMany`
- `.drop(`
- `.remove(`
- `.deleteMany(`
- `mongorestore`
- `mongodump`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `mongo-find` | `^(?!.*(?:dropDatabase\|dropCollection\|\.drop\s*\(\|\.(?:remove\|deleteMany)\s*\(\s*\{\s*\}\s*\)\|mongorestore\s+.*--drop)).*\.find\s*\(` |
| `mongo-count` | `^(?!.*(?:dropDatabase\|dropCollection\|\.drop\s*\(\|\.(?:remove\|deleteMany)\s*\(\s*\{\s*\}\s*\)\|mongorestore\s+.*--drop)).*\.count(?:Documents)?\s*\(` |
| `mongo-aggregate` | `^(?!.*(?:dropDatabase\|dropCollection\|\.drop\s*\(\|\.(?:remove\|deleteMany)\s*\(\s*\{\s*\}\s*\)\|mongorestore\s+.*--drop)).*\.aggregate\s*\(` |
| `mongodump-no-drop` | `mongodump\s+(?!.*--drop)` |
| `mongo-explain` | `^(?!.*(?:dropDatabase\|dropCollection\|\.drop\s*\(\|\.(?:remove\|deleteMany)\s*\(\s*\{\s*\}\s*\)\|mongorestore\s+.*--drop)).*\.explain\s*\(` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-database` | dropDatabase permanently deletes the entire database. | critical |
| `drop-collection` | drop/dropCollection permanently deletes the collection. | high |
| `delete-all` | remove({}) or deleteMany({}) deletes ALL documents. Add filter criteria. | high |
| `mongorestore-drop` | mongorestore --drop deletes existing data before restoring. | high |
| `collection-drop` | collection.drop() permanently deletes the collection. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.mongodb:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.mongodb:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Redis

**Pack ID:** `database.redis`

Protects against destructive Redis operations like FLUSHALL, FLUSHDB, and mass key deletion

### Keywords

Commands containing these keywords are checked against this pack:

- `redis`
- `valkey`
- `keydb`
- `FLUSHALL`
- `FLUSHDB`
- `DEBUG`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `redis-get` | `(?i)^(?!.*\b(?:FLUSHALL\|FLUSHDB\|DEBUG\|SHUTDOWN\|CONFIG\s+(?:SET\|REWRITE\|RESETSTAT)\|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL\|UNLINK))\b).*\b(?:GET\|MGET)\b` |
| `redis-scan` | `(?i)^(?!.*\b(?:FLUSHALL\|FLUSHDB\|DEBUG\|SHUTDOWN\|CONFIG\s+(?:SET\|REWRITE\|RESETSTAT)\|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL\|UNLINK))\b).*\bSCAN\b` |
| `redis-info` | `(?i)^(?!.*\b(?:FLUSHALL\|FLUSHDB\|DEBUG\|SHUTDOWN\|CONFIG\s+(?:SET\|REWRITE\|RESETSTAT)\|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL\|UNLINK))\b).*\bINFO\b` |
| `redis-keys` | `(?i)^(?!.*\b(?:FLUSHALL\|FLUSHDB\|DEBUG\|SHUTDOWN\|CONFIG\s+(?:SET\|REWRITE\|RESETSTAT)\|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL\|UNLINK))\b).*\bKEYS\b` |
| `redis-dbsize` | `(?i)^(?!.*\b(?:FLUSHALL\|FLUSHDB\|DEBUG\|SHUTDOWN\|CONFIG\s+(?:SET\|REWRITE\|RESETSTAT)\|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL\|UNLINK))\b).*\bDBSIZE\b` |
| `redis-config-get` | `(?i)^(?!.*\b(?:FLUSHALL\|FLUSHDB\|DEBUG\|SHUTDOWN\|CONFIG\s+(?:SET\|REWRITE\|RESETSTAT)\|xargs\s+(?:-\S+(?:\s+\S+)?\s+)*redis-cli(?:\s+\S+)*\s+(?:DEL\|UNLINK))\b).*\bCONFIG\s+GET\b` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `flushall` | FLUSHALL permanently deletes ALL keys in ALL databases. | critical |
| `flushdb` | FLUSHDB permanently deletes ALL keys in the current database. | high |
| `config-resetstat` | CONFIG RESETSTAT clears Redis runtime counters and can hide recent incidents. | medium |
| `mass-delete-pipeline` | Redis KEYS/SCAN piped to DEL/UNLINK can delete many keys at once. | high |
| `debug-crash` | DEBUG SEGFAULT/CRASH will crash the Redis server. | critical |
| `debug-sleep` | DEBUG SLEEP blocks the Redis server and can cause availability issues. | high |
| `shutdown` | SHUTDOWN stops the Redis server. SHUTDOWN NOSAVE risks data loss. | high |
| `config-dangerous` | CONFIG SET for dir/dbfilename/slaveof can be used for security attacks. | critical |
| `config-set-maxmemory` | CONFIG SET maxmemory can trigger immediate mass key eviction if new limit is below current usage. | critical |
| `config-set-maxmemory-policy` | CONFIG SET maxmemory-policy changes how Redis evicts keys, risking silent data loss. | critical |
| `config-set-save` | CONFIG SET save can disable RDB persistence entirely, risking data loss on restart. | high |
| `config-set-appendonly` | CONFIG SET appendonly can disable AOF persistence, risking data loss on restart. | high |
| `config-rewrite` | CONFIG REWRITE persists all runtime CONFIG SET changes to redis.conf permanently. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.redis:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.redis:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## SQLite

**Pack ID:** `database.sqlite`

Protects against destructive SQLite operations like DROP TABLE, DELETE without WHERE, and accidental data loss

### Keywords

Commands containing these keywords are checked against this pack:

- `sqlite`
- `sqlite3`
- `DROP`
- `TRUNCATE`
- `DELETE`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `select-query` | `(?i)^\s*SELECT\s+` |
| `sqlite3-dot-command` | `sqlite3\b[^\|;&]*['"]\s*\.(?:schema\|tables\|dump\|backup\|help)\b[^'"]*['"]?\s*$` |
| `dot-command-standalone` | `^\s*\.(?:schema\|tables\|dump\|backup\|help)\b` |
| `explain` | `(?i)^\s*EXPLAIN\s+` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `drop-table` | DROP TABLE permanently deletes the table (even with IF EXISTS). Verify it is intended. | critical |
| `delete-without-where` | DELETE without WHERE deletes ALL rows. Add a WHERE clause. | critical |
| `vacuum-into` | VACUUM INTO overwrites the target file if it exists. | medium |
| `sqlite3-stdin` | Running SQL from file could contain destructive commands. Review the file first. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.sqlite:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.sqlite:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

## Supabase

**Pack ID:** `database.supabase`

Protects against destructive Supabase CLI operations including database resets, migration rollbacks, function/secret/storage deletion, project removal, and infrastructure changes

### Keywords

Commands containing these keywords are checked against this pack:

- `supabase`
- `db reset`
- `db push`
- `migration repair`
- `migration down`
- `migration squash`
- `functions delete`
- `secrets unset`
- `storage rm`
- `projects delete`
- `orgs delete`
- `branches delete`
- `domains delete`
- `vanity-subdomains delete`
- `sso remove`
- `network-restrictions`
- `config push`

### Safe Patterns (Allowed)

These patterns match safe commands that are always allowed:

| Pattern Name | Pattern |
|--------------|----------|
| `supabase-db-diff` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+diff` |
| `supabase-db-lint` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+lint` |
| `supabase-db-dump` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+dump` |
| `supabase-db-shell-safe` | `(?i)supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+shell\s*$` |
| `supabase-inspect-db` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect\s+db` |
| `supabase-status` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+status` |
| `supabase-start` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+start` |
| `supabase-services` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+services` |
| `supabase-gen-types` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+gen\s+types` |
| `supabase-test-db` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+test\s+db` |
| `supabase-migration-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+list` |
| `supabase-migration-new` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+new` |
| `supabase-migration-fetch` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+migration\s+fetch` |
| `supabase-db-push-dry-run` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+db\s+push\b.*--dry-run(?:=true)?(?:\s\|$)` |
| `supabase-functions-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+list` |
| `supabase-functions-serve` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+serve` |
| `supabase-functions-download` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+download` |
| `supabase-functions-new` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+functions\s+new` |
| `supabase-secrets-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets\s+list` |
| `supabase-storage-ls` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+storage\s+ls` |
| `supabase-projects-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+projects\s+list` |
| `supabase-orgs-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+orgs\s+list` |
| `supabase-branches-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+branches\s+list` |
| `supabase-branches-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+branches\s+get` |
| `supabase-domains-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+domains\s+get` |
| `supabase-domains-reverify` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+domains\s+reverify` |
| `supabase-vanity-subdomains-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+vanity-subdomains\s+get` |
| `supabase-vanity-subdomains-check` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+vanity-subdomains\s+check-availability` |
| `supabase-sso-list` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+list` |
| `supabase-sso-show` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+show` |
| `supabase-sso-info` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+sso\s+info` |
| `supabase-network-restrictions-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+network-restrictions\s+get` |
| `supabase-network-bans-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+network-bans\s+get` |
| `supabase-ssl-enforcement-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+ssl-enforcement\s+get` |
| `supabase-postgres-config-get` | `supabase(?:\s+--?\S+(?:\s+\S+)?)*\s+postgres-config\s+get` |

### Destructive Patterns (Blocked)

These patterns match potentially destructive commands:

| Pattern Name | Reason | Severity |
|--------------|--------|----------|
| `supabase-db-reset` | supabase db reset drops and recreates the entire database. All data will be lost. | critical |
| `supabase-db-push` | supabase db push applies migrations to the remote database. Use --dry-run to preview first. | critical |
| `supabase-db-shell-destructive` | supabase db shell with destructive SQL (DROP/TRUNCATE/DELETE/ALTER). Verify the command carefully. | high |
| `supabase-migration-repair` | supabase migration repair modifies the migration history. This can cause drift between schema and migrations. | critical |
| `supabase-migration-down` | supabase migration down reverts applied migrations. Schema changes and associated data may be lost. | critical |
| `supabase-migration-squash` | supabase migration squash consolidates migrations and omits data manipulation statements (INSERT/UPDATE/DELETE). | high |
| `supabase-functions-delete` | supabase functions delete removes a deployed Edge Function. This causes immediate downtime for that function. | high |
| `supabase-storage-rm` | supabase storage rm deletes objects from storage. With --recursive, entire directories are removed. | high |
| `supabase-secrets-unset` | supabase secrets unset removes secrets from the project. Edge Functions depending on them will break immediately. | high |
| `supabase-projects-delete` | supabase projects delete permanently removes the entire Supabase project and all its data. | critical |
| `supabase-orgs-delete` | supabase orgs delete permanently removes the organization and may affect all projects within it. | high |
| `supabase-branches-delete` | supabase branches delete permanently removes a preview branch and its database. | high |
| `supabase-domains-delete` | supabase domains delete removes the custom domain configuration. Clients using the custom domain will lose access. | high |
| `supabase-vanity-subdomains-delete` | supabase vanity-subdomains delete removes the vanity subdomain. Clients using it will lose access. | high |
| `supabase-network-restrictions-update` | supabase network-restrictions update modifies allowed CIDR ranges. Misconfiguration can lock out all database connections. | high |
| `supabase-sso-remove` | supabase sso remove disconnects an SSO identity provider. All users authenticating via that provider will be locked out. | critical |
| `supabase-config-push` | supabase config push overwrites the remote project configuration with local config.toml settings. | high |
| `supabase-stop-no-backup` | supabase stop --no-backup stops the local stack and permanently deletes all data volumes. | high |

### Allowlist Guidance

To allowlist a specific rule from this pack, add to your allowlist:

```toml
[[allow]]
rule = "database.supabase:<pattern-name>"
reason = "Your reason here"
```

To allowlist all rules from this pack (use with caution):

```toml
[[allow]]
rule = "database.supabase:*"
reason = "Your reason here"
risk_acknowledged = true
```

---

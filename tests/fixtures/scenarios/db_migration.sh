#!/usr/bin/env bash
# Database migration workflow touching search indices and secrets.
set -euo pipefail

# Load credentials safely
vault kv get secret/db/prod
aws secretsmanager get-secret-value --secret-id prod/db

# Search index preparation (safe reads)
curl -X GET 'http://localhost:9200/_cluster/health'
curl -X GET 'http://localhost:9200/logs-2024/_mapping'

# Reindex to new index (safe create)
curl -X POST 'http://localhost:9200/_reindex' -H 'Content-Type: application/json' -d '{"source":{"index":"logs-2024"},"dest":{"index":"logs-2024-v2"}}'

# Cleanup old data (destructive)
curl -X DELETE 'http://localhost:9200/logs-2024'
curl -X POST 'http://localhost:9200/logs-2024-v2/_delete_by_query' -H 'Content-Type: application/json' -d '{"query":{"range":{"@timestamp":{"lt":"now-90d"}}}}'

# Rotate secret after migration (potentially destructive)
aws secretsmanager update-secret --secret-id prod/db --description "rotated after migration"

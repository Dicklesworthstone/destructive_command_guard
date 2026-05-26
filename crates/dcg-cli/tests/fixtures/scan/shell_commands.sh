#!/bin/bash
# Fixture for scan regression testing
# Contains a mix of safe and destructive commands

# Safe commands
ls -la
echo "Hello World"
git status
npm install
cargo build

# Destructive commands that should be flagged
git reset --hard
git push --force origin main
git clean -fd

# Safe rm operations (within temp directories)
rm -rf /tmp/build-cache
rm -rf "$TMPDIR/artifacts"

# Dangerous rm operations that should be flagged
rm -rf ~/projects
rm -rf /home/*

# Container operations
docker system prune -af
docker volume rm my-volume

# Kubernetes destructive operations
kubectl delete namespace production
kubectl delete pods --all

# Database operations
psql -c "DROP TABLE users;"
mysql -e "TRUNCATE TABLE orders;"

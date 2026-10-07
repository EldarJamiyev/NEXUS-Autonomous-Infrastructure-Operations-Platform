#!/usr/bin/env bash
# Restore the demo SQLite database from a backup file, then restart NEXUS.
#   ./scripts/restore.sh backups/nexus-20261006T120000Z.db
set -euo pipefail
cd "$(dirname "$0")/.."
file="${1:?usage: restore.sh <backup.db>}"
if [[ "${NEXUS_LOCAL:-0}" == "1" ]]; then
  (cd backend && python -m nexus.database.backup restore "$(realpath "../$file" 2>/dev/null || realpath "$file")")
else
  docker compose cp "$file" "nexus:/data/restore.db"
  docker compose exec -T nexus python -m nexus.database.backup restore /data/restore.db
  docker compose restart nexus
fi
echo "restore complete"

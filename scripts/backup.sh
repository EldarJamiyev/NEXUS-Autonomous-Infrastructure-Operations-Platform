#!/usr/bin/env bash
# Online backup of the demo SQLite database (safe while NEXUS runs).
#   ./scripts/backup.sh                 -> Docker volume (container "nexus"), copied to ./backups/
#   NEXUS_LOCAL=1 ./scripts/backup.sh   -> local development database
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p backups
if [[ "${NEXUS_LOCAL:-0}" == "1" ]]; then
  (cd backend && python -m nexus.database.backup backup "../backups/nexus-$(date -u +%Y%m%dT%H%M%SZ).db")
else
  name="nexus-$(date -u +%Y%m%dT%H%M%SZ).db"
  docker compose exec -T nexus python -m nexus.database.backup backup "/data/backups/$name"
  docker compose cp "nexus:/data/backups/$name" "backups/$name"
  echo "copied to backups/$name"
fi

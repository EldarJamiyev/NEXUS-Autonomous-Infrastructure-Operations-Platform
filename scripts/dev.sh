#!/usr/bin/env bash
# Run the backend (:8000) and the Vite dev server (:5173) together. Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")/.."
(cd backend && nexus-server) &
BACK=$!
trap 'kill $BACK 2>/dev/null' EXIT
(cd frontend && npm run dev)

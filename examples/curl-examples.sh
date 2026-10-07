#!/usr/bin/env bash
# Exercise the API from a shell. Requires curl and jq; NEXUS on localhost:8000 with demo login enabled.
set -euo pipefail
B=${NEXUS_URL:-http://localhost:8000}
T=$(curl -s -X POST "$B/api/auth/demo-login" -H 'Content-Type: application/json' -d '{"user_id":"eldar"}' | jq -r .token)
H=(-H "Authorization: Bearer $T" -H 'Content-Type: application/json')
curl -s "$B/health" | jq
curl -s "${H[@]}" "$B/api/explain/access?user=aysel&device=PC-024&destination=LINUX01&port=22" | jq -r .narrative
curl -s "${H[@]}" -X POST "$B/api/access/request" -d @"$(dirname "$0")/access-request.json" | jq '{decision, lease: .lease.id}'
curl -s "${H[@]}" -X POST "$B/api/alerts/alertmanager" -d @"$(dirname "$0")/alertmanager-webhook.json" | jq   # STALE unless nginx is really down
curl -s "${H[@]}" -X POST "$B/api/whatif" -d '{"scenario":"vlan_down","params":{"vlan":30}}' | jq .impact.counts
curl -s "${H[@]}" -X POST "$B/api/chaos/kill-nginx" | jq

# API guide

Interactive reference (OpenAPI): **http://localhost:8000/api/docs** · schema: `/api/openapi.json`.

## Authentication

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/auth/demo-login -H 'Content-Type: application/json' -d '{"user_id":"eldar"}' | jq -r .token)
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/status
```
With demo login disabled, use an API key from `NEXUS_API_KEYS` as the bearer token. WebSocket: `ws://host/ws?token=…`.

## Main endpoints

| Area | Endpoints |
|---|---|
| Health | `GET /health`, `GET /metrics`, `GET /api/status`, `GET /api/overview`, `GET /api/system/selftest` |
| Inventory | `GET /api/devices[/{id}]`, `/api/users[/{id}]`, `/api/groups`, `/api/sessions`, `/api/identity`, `/api/network`, `/api/network/inventory`, `/api/firewall`, `/api/dependencies` |
| Access | `GET /api/leases`, `POST /api/access/request`, `POST /api/leases/{id}/revoke`, `GET /api/explain/access` |
| Devices | `POST /api/devices/{id}/quarantine`, `/release`, `/healthcheck`, `/compare`, `/services/{name}/restart` |
| Incidents | `GET /api/incidents[/{id}]`, `/report?format=md|html`, `POST …/acknowledge|resolve|false-positive|remediate` |
| AutoHeal | `GET /api/remediations[/{id}]`, `/catalog`, `/scorecard`, `POST /api/remediations/{id}/rollback`, `GET/POST /api/approvals` |
| Drift | `GET /api/drift`, `POST /api/drift/scan`, `POST /api/drift/{id}/remediate|accept` |
| Policy | `GET /api/policies[/{id}]`, `/compile`, `/diff`, `POST /api/policies/validate|simulate|apply`, `POST /api/policies/{id}/activate|rollback|deactivate` |
| Analysis | `POST /api/changes/impact`, `POST /api/whatif`, `GET /api/timemachine/timeline|state|compare`, `POST /api/snapshots` |
| Chaos / demo | `GET /api/chaos/scenarios`, `POST /api/chaos/{scenario}`, `GET /api/chaos/runs/{id}`, `POST /api/demo/start|reset|blackout` |
| Explain | `GET /api/explain/risk|incident|drift|decision|quarantine/…` |
| Integrations | `POST /api/alerts/alertmanager`, `/api/ingest/windows-events`, `/api/ingest/ad-inventory`, `/api/ingest/config-report` |
| Other | `GET /api/audit`, `/api/events`, `/api/chatops`, `POST /api/chatops/test`, `/api/operations/*`, `/api/runbooks`, `POST /api/copilot/ask`, `GET /api/search` |

Errors are JSON `{"detail": …}` with 400 (validation), 401, 403 (role), 404, 409 (not in simulation), 422, 429 (with
`Retry-After`) and 503 with `"state": "PENDING"` when the firewall is unreachable.

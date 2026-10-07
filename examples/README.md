# Examples

| File | Use |
|---|---|
| `alertmanager-webhook.json` | `POST /api/alerts/alertmanager` - validated against state; STALE if nginx is actually healthy |
| `windows-events.json` | `POST /api/ingest/windows-events` - logon, failure (bad password) and group membership change |
| `access-request.json` | `POST /api/access/request` |
| `config-report.json` | `POST /api/ingest/config-report` - what the nexus-agent sends |
| `curl-examples.sh` | end-to-end shell walkthrough |

Sample generated reports: run the guided demo or blackout and open the Reports page (Markdown/HTML download).

# Container layout

| Service | Image | Port | Profile | Purpose |
|---|---|---|---|---|
| nexus | built from `Dockerfile` | 8000 | default | API, control plane, simulation and the web console (one process) |
| prometheus | prom/prometheus | 9090 | observability | Scrapes `nexus:8000/metrics`, evaluates `prometheus/rules/` |
| alertmanager | prom/alertmanager | 9093 | observability | Routes alerts to the NEXUS webhook `/api/alerts/alertmanager` |
| grafana | grafana/grafana | 3000 | observability | Eight provisioned NEXUS dashboards (anonymous Viewer enabled) |
| loki | grafana/loki | 3100 | observability | Stores NEXUS structured JSON logs |
| promtail | grafana/promtail | - | observability | Ships `/data/logs/nexus.log` from the shared volume to Loki |

The `nexus-data` volume holds the SQLite database (`/data/nexus.db`), logs and backups. The image runs as an
unprivileged user (uid 10001) and has a health check on `/health`.

The closed monitoring loop in the observability profile: NEXUS exports simulated service, disk, reachability
and certificate metrics -> Prometheus rules fire -> Alertmanager posts to NEXUS -> NEXUS validates each alert
against current state (stale alerts are discarded) and de-duplicates it against its internal detector.

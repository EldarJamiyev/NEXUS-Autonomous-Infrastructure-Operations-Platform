# Troubleshooting the project

| Problem | Check | Fix |
|---|---|---|
| Docker won't start | `docker compose ps`, `docker compose logs nexus` | Docker Desktop running? Compose ≥ 2.24 (`docker compose version`) for the optional `.env` file. |
| Port already used | `docker compose up` reports `bind: address already in use` | Set `NEXUS_HTTP_PORT=8080` in `.env`; for Grafana/Prometheus change the left side of their `ports:` |
| Database error / migration failed | log line from `alembic` | Stop, back up `nexus-data`, then `docker compose down -v` to recreate. Local: delete `backend/data/nexus.db`. |
| Frontend cannot reach API | browser devtools → network | In dev, run the backend on :8000 before `npm run dev`; behind a proxy, forward `/api` and `/ws`. |
| WebSocket disconnected | top bar shows **Offline** | Reconnects automatically with backoff; behind a proxy enable WebSocket upgrade for `/ws`. |
| Blank page after login | `curl localhost:8000/` returns JSON instead of HTML | The UI was not built: `cd frontend && npm run build` (Docker builds it automatically). |
| Prometheus unavailable | http://localhost:9090/targets | Start with `--profile observability`; the `nexus` target must be UP. |
| Grafana unavailable / no data | Grafana → Connections → Data sources | Prometheus must be running; dashboards are under the "NEXUS OMNIS" folder. |
| ChatOps unavailable | ChatOps page shows DRY_RUN or FAILED | Set `CHATOPS_PROVIDER` and `CHATOPS_WEBHOOK_URL`; FAILED rows show the HTTP error. |
| Simulation stuck | System → Self test (Simulation check) | `docker compose restart nexus`; transactions interrupted by a restart are marked FAILED for review. |
| "requires ENGINEER role" | operator switcher in the top bar | Switch to Eldar (ADMIN) or Murad (ENGINEER) - this is RBAC working. |
| Access request shows APPROVAL_REQUIRED | Access page shows the schedule check | Outside 08:00-18:00 site time POL-IT-ADMIN requires a second admin; approve on the Approvals page. |

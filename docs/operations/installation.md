# Installation

## Docker (recommended)

Requirements: Docker Engine 24+ with Compose v2.24+ (Docker Desktop on Windows/macOS), 2 GB RAM free.

```bash
git clone https://github.com/<you>/nexus-omnis.git && cd nexus-omnis
cp .env.example .env          # optional; every value has a safe demo default
docker compose up --build     # http://localhost:8000
```

Add the observability stack with `docker compose --profile observability up --build`:
Prometheus :9090, Alertmanager :9093, Grafana :3000 (anonymous viewer; the `admin` login asks for a new
password on first sign-in), Loki :3100.

Windows PowerShell: `.\scripts\start.ps1` (add `-Observability`). It builds, waits for `/health` and opens the browser.

Data lives in the `nexus-data` volume. `docker compose down` keeps it; `docker compose down -v` deletes it.
Reset the demo from the System page or with `docker compose exec nexus nexusctl demo reset`.

## Local development (Linux, macOS, WSL, Windows)

Requirements: Python 3.11+, Node.js 20+.

```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.lock && pip install -e ".[dev]"
nexus-server                                            # http://localhost:8000 (API + built UI)
```
```bash
cd frontend && npm ci
npm run dev        # http://localhost:5173 with hot reload, proxies /api and /ws to :8000
npm run build      # produces frontend/dist, which nexus-server serves automatically
```

The database defaults to `backend/data/nexus.db`. Change it with `DATABASE_URL`.

## PostgreSQL

```bash
pip install -e ".[postgres]"
export DATABASE_URL=postgresql+psycopg://nexus:<password>@localhost:5432/nexus
nexus-server        # Alembic migrations run at startup
```
Back up with `pg_dump -Fc nexus > nexus.dump`, restore with `pg_restore -d nexus nexus.dump`.

## Backup and restore (SQLite)

```bash
./scripts/backup.sh                         # online copy from the container into ./backups/
./scripts/restore.sh backups/nexus-<timestamp>.db
NEXUS_LOCAL=1 ./scripts/backup.sh           # local development database
```
The backup uses SQLite's online backup API, so NEXUS can keep running.

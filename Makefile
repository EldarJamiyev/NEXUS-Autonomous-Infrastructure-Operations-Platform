# NEXUS OMNIS developer commands. On Windows use the equivalent commands in README.md or scripts/start.ps1.
.PHONY: help install dev backend frontend build test lint typecheck check up up-full down logs demo blackout reset backup restore clean dashboards

help:
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

install: ## Install backend (editable, with dev tools) and frontend dependencies
	cd backend && pip install -r requirements.lock && pip install -e ".[dev]"
	cd frontend && npm ci

backend: ## Run the API + control plane on :8000
	cd backend && nexus-server

frontend: ## Run the Vite dev server on :5173 (proxies /api and /ws to :8000)
	cd frontend && npm run dev

dev: ## Run backend and frontend together
	./scripts/dev.sh

build: ## Build the production frontend (served by the backend from frontend/dist)
	cd frontend && npm run build

test: ## Run backend and frontend tests
	cd backend && pytest -q
	cd frontend && npm test

lint: ## Lint the backend
	cd backend && ruff check nexus tests

typecheck: ## Type-check backend and frontend
	cd backend && mypy nexus
	cd frontend && npm run typecheck

check: lint typecheck test ## Everything CI runs (except the Docker build)

up: ## docker compose up --build
	docker compose up --build -d && echo "NEXUS: http://localhost:8000"

up-full: ## Include Prometheus, Alertmanager, Grafana, Loki, Promtail
	docker compose --profile observability up --build -d && echo "NEXUS :8000  Grafana :3000  Prometheus :9090  Alertmanager :9093"

down: ## Stop containers (data volume is kept)
	docker compose --profile observability down

logs: ## Follow NEXUS logs (structured JSON)
	docker compose logs -f nexus

demo: ## Run the 20-scene guided demo from the CLI
	nexusctl demo

blackout: ## Run the full infrastructure blackout drill
	nexusctl demo blackout

reset: ## Reset the demo environment
	nexusctl demo reset

backup: ## Back up the SQLite database
	./scripts/backup.sh

restore: ## Restore the SQLite database: make restore FILE=backups/nexus-....db
	./scripts/restore.sh $(FILE)

dashboards: ## Regenerate Grafana dashboards from scripts/generate_grafana_dashboards.py
	python scripts/generate_grafana_dashboards.py

clean:
	rm -rf backend/data frontend/dist backend/.pytest_cache backend/.ruff_cache backend/.mypy_cache

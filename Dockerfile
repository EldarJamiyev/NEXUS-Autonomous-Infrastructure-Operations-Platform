# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------- frontend build
FROM node:20-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NEXUS_CONFIG_ROOT=/app \
    NEXUS_FRONTEND_DIST=/app/frontend_dist \
    DATABASE_URL=sqlite:////data/nexus.db
WORKDIR /app

# Pinned, tested dependency set first (better layer caching), then the package itself.
COPY backend/requirements.lock /tmp/requirements.lock
RUN pip install -r /tmp/requirements.lock
COPY backend/ /tmp/backend/
RUN pip install --no-deps /tmp/backend && rm -rf /tmp/backend

# Desired state, simulation definition and automation content (Git-controlled intent).
COPY policies/ /app/policies/
COPY baselines/ /app/baselines/
COPY runbooks/ /app/runbooks/
COPY simulation/ /app/simulation/
COPY ansible/ /app/ansible/
COPY --from=frontend /src/frontend/dist /app/frontend_dist

RUN useradd --create-home --uid 10001 nexus && mkdir -p /data && chown -R nexus:nexus /data
USER nexus
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"
CMD ["nexus-server"]

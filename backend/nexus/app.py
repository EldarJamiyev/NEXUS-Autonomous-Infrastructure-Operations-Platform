"""FastAPI application factory: builds the context (DB, migrations, adapters, seed) and wires routes."""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from nexus import __version__
from nexus.api.deps import RateLimiter, TokenSigner
from nexus.chatops.notifier import ChatOpsNotifier
from nexus.clock import SimClock
from nexus.config import Settings, get_settings
from nexus.core.context import Context
from nexus.database.migrate import upgrade
from nexus.database.session import create_db_engine, make_session_factory
from nexus.events.bus import InProcessEventBus
from nexus.firewall.base import FirewallUnavailable
from nexus.identity.adapter import DirectoryIdentityProvider
from nexus.logs import configure_logging
from nexus.monitoring.metrics import Metrics
from nexus.remediation.catalog import Catalog


def build_adapters(ctx: Context) -> None:
    from nexus.firewall.mock import MockFirewallAdapter
    from nexus.remediation.executor import AnsibleExecutor, SimulatedExecutor
    from nexus.remediation.verification import NetworkProbes, Probes
    from nexus.simulation.world import World

    s = ctx.settings
    ctx.world = World(ctx)
    ctx.identity = DirectoryIdentityProvider(simulated=s.is_simulation)
    if s.firewall_adapter == "pfsense":
        from nexus.firewall.pfsense import PfSenseAdapter

        ctx.firewall = PfSenseAdapter(s.pfsense_url or "", s.pfsense_api_key or "", s.pfsense_verify_tls)
    else:
        ctx.firewall = MockFirewallAdapter(ctx)
    ctx.executor = AnsibleExecutor(ctx) if s.executor == "ansible" else SimulatedExecutor(ctx)
    ctx.probes = Probes(ctx) if s.is_simulation else NetworkProbes(ctx)
    ctx.chatops = ChatOpsNotifier(ctx)
    ctx.catalog = Catalog()
    ctx.metrics = Metrics(ctx)


def seed_if_empty(ctx: Context) -> bool:
    from nexus.policy.cache import refresh
    from nexus.simulation.history import generate
    from nexus.simulation.seed import is_seeded, seed_enterprise

    with ctx.session() as db:
        seeded = is_seeded(db)
        if not seeded and ctx.settings.seed_demo:
            seed_enterprise(ctx, db)
        refresh(ctx, db)
    if not seeded and ctx.settings.seed_demo and ctx.settings.seed_history:
        generate(ctx)
    return not seeded


def create_context(settings: Settings) -> Context:
    upgrade(settings.database_url)
    engine = create_db_engine(settings.database_url)
    factory = make_session_factory(engine)
    clock = SimClock(settings.site_timezone)
    bus = InProcessEventBus(clock)
    bus.attach(factory)
    ctx = Context(settings, engine, factory, bus, clock)
    ctx.signer = TokenSigner(settings.secret_key or secrets.token_urlsafe(32))  # type: ignore[attr-defined]
    ctx.limiter = RateLimiter(settings.rate_limit_per_minute)  # type: ignore[attr-defined]
    build_adapters(ctx)
    seed_if_empty(ctx)
    return ctx


def reset_environment(ctx: Context) -> None:
    from nexus.drift.engine import reload_baselines
    from nexus.simulation.seed import wipe

    wipe(ctx)
    ctx.clock.reset()
    reload_baselines(ctx)
    seed_if_empty(ctx)


def create_app(settings: Settings | None = None, ctx: Context | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_file)
    context = ctx or create_context(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        from nexus.core.controlplane import ControlPlane

        cp = ControlPlane(context)
        app.state.cp = cp
        await cp.start()
        yield
        await cp.stop()

    app = FastAPI(title="NEXUS OMNIS API", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json",
                  description="Infrastructure operations control plane prototype. Default environment: SIMULATION (no real infrastructure is changed).")
    app.state.ctx = context
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=False, allow_methods=["*"],
                       allow_headers=["Authorization", "Content-Type"])

    @app.exception_handler(KeyError)
    async def _not_found(request: Request, exc: KeyError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc.args[0]) if exc.args else "not found"})

    @app.exception_handler(PermissionError)
    async def _forbidden(request: Request, exc: PermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ValueError)
    async def _bad(request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        import logging

        logging.getLogger("nexus.api").exception("unhandled error", extra={"event": "API_ERROR", "path": request.url.path})
        return JSONResponse(status_code=500, content={"detail": "internal error", "type": type(exc).__name__, "path": request.url.path})

    @app.exception_handler(FirewallUnavailable)
    async def _fw(request: Request, exc: FirewallUnavailable) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc), "state": "PENDING"})

    from nexus.api.routers import control, inventory, operations, system, ws

    for module in (system, inventory, operations, control):
        app.include_router(module.router)
    app.include_router(ws.router)

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, Any]:
        from nexus.core.store import get_setting

        db_ok = True
        try:
            with context.session() as db:
                db.execute(text("SELECT 1"))
                mode = (get_setting(db, "system_mode") or {}).get("mode", "NORMAL")
        except Exception:  # noqa: BLE001
            db_ok, mode = False, "DEGRADED"
        sim_ok = (not context.settings.background_tasks) or context.live
        return {"status": "healthy" if db_ok and sim_ok else "degraded", "mode": mode, "database": "healthy" if db_ok else "unavailable",
                "event_bus": "healthy", "simulation": "healthy" if sim_ok else "stopped", "environment": context.environment_label, "version": __version__}

    @app.get("/metrics", tags=["system"], include_in_schema=False)
    async def metrics() -> Response:
        return Response(context.metrics.render(), media_type="text/plain; version=0.0.4")

    dist = settings.resolved_frontend_dist()
    if dist:
        if (dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str) -> Response:
            if full_path.startswith(("api/", "ws")):
                return JSONResponse(status_code=404, content={"detail": "not found"})
            candidate = dist / full_path
            if full_path and candidate.is_file() and dist in candidate.resolve().parents:
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        async def root() -> dict[str, str]:
            return {"product": "NEXUS OMNIS", "version": __version__, "ui": "frontend not built - run `make frontend` or use docker compose",
                    "api_docs": "/api/docs"}
    return app

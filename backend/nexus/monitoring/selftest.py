"""NEXUS SELF TEST - twelve component checks with honest results."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select, text

from nexus.models import Device

if TYPE_CHECKING:
    from nexus.core.context import Context


def run(ctx: Context, route_count: int) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, warn: bool = False) -> None:
        checks.append({"component": name, "status": "HEALTHY" if ok else ("WARNING" if warn else "FAILED"), "detail": detail})

    t0 = time.perf_counter()
    try:
        with ctx.session() as db:
            db.execute(text("SELECT 1"))
            n = db.scalar(select(func.count()).select_from(Device))
        add("Database", True, f"{ctx.engine.dialect.name}, {n} devices, {1000 * (time.perf_counter() - t0):.1f} ms")
    except Exception as exc:  # noqa: BLE001
        add("Database", False, str(exc))
    q = ctx.bus.subscribe(10)
    try:
        with ctx.session() as db:
            ctx.bus.emit(db, "SELFTEST", "self-test event", source="selftest")
        got = not q.empty()
        add("Event Bus", got, f"publish/subscribe round trip {'ok' if got else 'failed'}; {ctx.bus.published} events published, {ctx.bus.dropped} dropped")
    finally:
        ctx.bus.unsubscribe(q)
    add("API", route_count > 40, f"{route_count} routes registered")
    with ctx.session() as db:
        from nexus.dependencies.graph import ServiceGraph

        graph = ServiceGraph(db)
        add("State Engine", len(graph.services) > 0, f"{len(graph.services)} services, {sum(len(v) for v in graph.deps.values())} dependencies")
        from nexus.policy.compiler import compile_policy_set

        report = compile_policy_set(ctx, db)
        ctx.runtime.last_compile = report  # type: ignore[attr-defined]
        add("Policy Engine", not report["errors"], f"{len(report['policies'])} policies, {len(report['conflicts'])} conflict(s), {len(report['shadowed'])} shadowed rule(s)")
        from nexus.risk.engine import _score_row, device_factors

        dev = db.get(Device, "PC-023") or db.scalars(select(Device)).first()
        assert dev is not None, "no devices in inventory"
        row = _score_row(ctx, db, "device", dev.id)
        same = device_factors(ctx, db, dev, row) == device_factors(ctx, db, dev, row)
        add("Risk Engine", same, f"deterministic scoring verified on {dev.id}")
        state = ctx.firewall.get_state(db)
        add("Firewall Adapter", bool(state.get("available")), f"{state.get('adapter')} ({state.get('mode')}) {'reachable' if state.get('available') else 'UNREACHABLE'}",
            warn=True)
        from nexus.drift.engine import baselines, normalize

        hosts = baselines(ctx)["hosts"]
        sample = normalize("ssh", {"PermitRootLogin": "no", "Port": 22})
        add("Drift Engine", bool(hosts) and sample.get("permit_root_login") is False, f"{len(hosts)} host baselines loaded from Git intent")
    from nexus.remediation.executor import CommandRejected, render

    with ctx.session() as db:
        linux = db.get(Device, "LINUX01") or db.scalars(select(Device)).first()
        assert linux is not None, "no devices in inventory"
        try:
            render("service_restart", linux, {"service": "nginx; rm -rf /"})
            rejected = False
        except CommandRejected:
            rejected = True
        ok_render = render("service_restart", linux, {"service": "nginx"}) == ["systemctl", "restart", "nginx"]
    add("Remediation Engine", rejected and ok_render, f"{len(ctx.catalog.actions)} catalog actions; injection attempt rejected: {rejected}")
    age = time.time() - ctx.runtime.last_tick if ctx.runtime.last_tick else None
    if ctx.settings.background_tasks:
        add("Simulation", age is not None and age < 4 * ctx.settings.sim_tick_interval, f"last tick {age:.1f} s ago" if age is not None else "no tick yet",
            warn=True)
    else:
        add("Simulation", True, "background loop disabled by configuration (tests/offline)")
    add("ChatOps", True, f"{ctx.settings.chatops_provider} webhook configured" if ctx.chatops.configured else "dry-run mode: messages recorded, nothing sent")
    body = ctx.metrics.render()
    add("Monitoring", b"nexus_controller_health" in body, f"/metrics exports {body.count(b'# HELP')} metric families")
    healthy = sum(1 for c in checks if c["status"] == "HEALTHY")
    return {"healthy": healthy, "total": len(checks), "summary": f"{healthy}/{len(checks)} HEALTHY", "checks": checks,
            "environment": ctx.environment_label, "ran_at": ctx.clock.now().isoformat()}

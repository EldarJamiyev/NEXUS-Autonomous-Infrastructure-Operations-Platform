"""Status, overview, system settings, self-test, clock, search and authentication."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from nexus import __version__
from nexus.api.deps import ROLE_RANK, Principal, current_principal, get_ctx, limited, require
from nexus.api.serializers import device_brief
from nexus.core.audit import record_audit
from nexus.core.context import Context
from nexus.core.decision import AUTONOMY_LEVELS, in_change_window, next_window
from nexus.core.store import get_setting, set_setting
from nexus.models import (
    Device,
    DriftEvent,
    Event,
    Incident,
    IpAddress,
    Lease,
    Policy,
    RemediationTransaction,
    RiskScore,
    User,
)
from nexus.models import Session as UserSession
from nexus.monitoring.health import distribution
from nexus.risk.engine import global_risk

router = APIRouter(prefix="/api", tags=["system"])


def status_payload(ctx: Context) -> dict[str, Any]:
    from nexus.operations.daily import scorecard

    with ctx.session() as db:
        since = ctx.clock.now() - timedelta(hours=24)
        counts = {
            "devices": db.scalar(select(func.count()).select_from(Device)) or 0,
            "users": db.scalar(select(func.count()).select_from(User)) or 0,
            "active_sessions": db.scalar(select(func.count()).select_from(UserSession).where(UserSession.active.is_(True))) or 0,
            "active_leases": db.scalar(select(func.count()).select_from(Lease).where(Lease.status == "ACTIVE")) or 0,
            "open_incidents": db.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING")))) or 0,
            "drift_events": db.scalar(select(func.count()).select_from(DriftEvent).where(DriftEvent.status.in_(("OPEN", "APPROVAL_REQUIRED", "REMEDIATING", "FAILED")))) or 0,
            "quarantined": db.scalar(select(func.count()).select_from(Device).where(Device.quarantined.is_(True))) or 0,
            "automated_remediations": db.scalar(select(func.count()).select_from(RemediationTransaction).where(
                RemediationTransaction.status == "COMMITTED", RemediationTransaction.created_at >= since)) or 0,
            "pending_approvals": db.scalar(select(func.count()).select_from(RemediationTransaction).where(RemediationTransaction.status == "AWAITING_APPROVAL")) or 0,
        }
        level = int(get_setting(db, "autonomy_level") or 0)
        window_ok, window_text = in_change_window(ctx, db)
        return {"product": "NEXUS OMNIS", "version": __version__, "environment": ctx.environment_label,
                "mode": get_setting(db, "system_mode") or {"mode": "NORMAL", "reasons": [], "behaviors": []},
                "autonomy": {"level": level, "name": AUTONOMY_LEVELS[level]}, "clock": ctx.clock.describe(), "health": distribution(db),
                "counts": counts, "global_risk": global_risk(db), "scorecard": scorecard(ctx, db, hours=24),
                "maintenance": {**(get_setting(db, "maintenance") or {}), "window": "INSIDE MAINTENANCE" if window_ok else "OUTSIDE MAINTENANCE",
                                "detail": window_text, "next": next_window(ctx, db)},
                "firewall": {"adapter": ctx.firewall.name, "available": ctx.firewall.available(), "mode": ctx.firewall.mode},
                "chatops": {"provider": ctx.settings.chatops_provider, "configured": ctx.chatops.configured},
                "demo": ctx.runtime.demo.snapshot() if ctx.runtime.demo else None, "live": ctx.live,
                "loops": {"reconcile_count": ctx.runtime.reconcile_count, "detection_count": ctx.runtime.detection_count}}


@router.get("/status")
async def status(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    return status_payload(ctx)


@router.get("/overview")
async def overview(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.incidents.engine import incident_dict
    from nexus.remediation.runner import tx_dict

    payload = status_payload(ctx)
    with ctx.session() as db:
        payload["recent_incidents"] = [incident_dict(i, brief=True) for i in db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(8))]
        payload["recent_remediations"] = [tx_dict(t) for t in db.scalars(select(RemediationTransaction).order_by(RemediationTransaction.created_at.desc()).limit(6))]
        payload["top_risk"] = [{"id": r.entity_id, "score": r.score, "level": r.level, "factors": r.factors[:3]}
                               for r in db.scalars(select(RiskScore).where(RiskScore.entity_type == "device").order_by(RiskScore.score.desc()).limit(5))]
        payload["recent_events"] = [{"id": e.id, "ts": e.ts.isoformat(), "type": e.type, "severity": e.severity, "source": e.source, "target": e.target,
                                     "message": e.message, "correlation_id": e.correlation_id}
                                    for e in db.scalars(select(Event).where(Event.type.notin_(("SELFTEST", "AUTH_FAILURE"))).order_by(Event.id.desc()).limit(40))]
        payload["devices"] = [device_brief(db, d) for d in db.scalars(select(Device).order_by(Device.id))]
    return payload


class AutonomyIn(BaseModel):
    level: int = Field(ge=0, le=5)


class MaintenanceIn(BaseModel):
    active: bool
    reason: str = Field("", max_length=200)


class ClockIn(BaseModel):
    mode: Literal["real", "set", "accelerate"]
    time: str | None = Field(None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    factor: float | None = Field(None, gt=0, le=3600)


@router.get("/system")
async def system(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    s = ctx.settings
    with ctx.session() as db:
        level = int(get_setting(db, "autonomy_level") or 0)
        return {"version": __version__, "environment": ctx.environment_label,
                "adapters": {"firewall": {"name": ctx.firewall.name, "mode": ctx.firewall.mode}, "identity": {"name": ctx.identity.name, "mode": ctx.identity.mode},
                             "executor": {"name": ctx.executor.name, "mode": ctx.executor.mode}, "probes": {"mode": ctx.probes.mode},
                             "chatops": {"provider": s.chatops_provider, "configured": ctx.chatops.configured}, "event_bus": "in-process (Redis-ready interface)",
                             "database": ctx.engine.dialect.name},
                "intervals": {"reconcile": s.reconcile_interval, "detection": s.detection_interval, "simulation_tick": s.sim_tick_interval,
                              "snapshot": s.snapshot_interval, "step_delay_ms": s.step_delay_ms},
                "autonomy": {"level": level, "name": AUTONOMY_LEVELS[level], "levels": [{"level": k, "name": v} for k, v in AUTONOMY_LEVELS.items()]},
                "maintenance": get_setting(db, "maintenance"), "change_windows": get_setting(db, "change_windows"), "next_window": next_window(ctx, db),
                "mode": get_setting(db, "system_mode"), "clock": ctx.clock.describe(), "policy_count": db.scalar(select(func.count()).select_from(Policy)),
                "background_tasks": s.background_tasks, "demo_auth": s.demo_auth}


@router.put("/system/autonomy", dependencies=[Depends(limited("system"))])
async def set_autonomy(body: AutonomyIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    with ctx.session() as db:
        old = get_setting(db, "autonomy_level")
        set_setting(db, "autonomy_level", body.level, ctx.clock.now())
        ctx.bus.emit(db, "SETTING_CHANGED", f"Autonomy level {old} -> {body.level} ({AUTONOMY_LEVELS[body.level]}) by {p.user_id}", severity="notice",
                     source="console", user_id=p.user_id, data={"setting": "autonomy_level", "old": old, "new": body.level})
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action="changed autonomy level", reason=f"{old} -> {body.level}", target="NEXUS", result="SUCCESS")
    return {"level": body.level, "name": AUTONOMY_LEVELS[body.level]}


@router.post("/system/maintenance", dependencies=[Depends(limited("system"))])
async def maintenance(body: MaintenanceIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.drift.engine import end_maintenance_review

    reopened: list[str] = []
    with ctx.session() as db:
        state = {"active": body.active, "reason": body.reason, "started_at": ctx.clock.now().isoformat() if body.active else None,
                 "started_by": p.user_id if body.active else None, "expected": []}
        set_setting(db, "maintenance", state, ctx.clock.now())
        ctx.bus.emit(db, "MAINTENANCE_STARTED" if body.active else "MAINTENANCE_ENDED",
                     f"Maintenance mode {'started' if body.active else 'ended'} by {p.user_id}" + (f": {body.reason}" if body.reason else ""),
                     severity="notice", source="console", user_id=p.user_id)
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action=f"{'started' if body.active else 'ended'} maintenance mode",
                     reason=body.reason or "operator", target="NEXUS", result="SUCCESS")
        if not body.active:
            reopened = end_maintenance_review(ctx, db)
    if not body.active and ctx.controlplane:
        ctx.controlplane.reconcile_once(None)
    return {"maintenance": state, "reopened_drift": reopened}


@router.put("/system/clock", dependencies=[Depends(limited("system"))])
async def clock(body: ClockIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    if body.mode == "real":
        ctx.clock.reset()
    elif body.mode == "set" and body.time:
        site = ctx.clock.site_now()
        hh, mm = (int(x) for x in body.time.split(":"))
        ctx.clock.set_time(site.replace(hour=hh, minute=mm, second=0, microsecond=0))
    elif body.mode == "accelerate" and body.factor:
        ctx.clock.set_acceleration(body.factor)
    with ctx.session() as db:
        ctx.bus.emit(db, "SETTING_CHANGED", f"Simulation clock {body.mode} by {p.user_id}: {ctx.clock.describe()['site_time']} x{ctx.clock.acceleration}",
                     severity="notice", source="console", user_id=p.user_id)
    return ctx.clock.describe()


@router.get("/system/selftest")
async def selftest(request: Request, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.monitoring.selftest import run

    return run(ctx, len(request.app.openapi().get("paths", {})))


@router.get("/metrics/history")
async def metrics_history(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {"devices": {k: list(v)[-90:] for k, v in ctx.runtime.metric_history.items()}}


@router.get("/search")
async def search(q: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    needle = q.strip().lower()
    if len(needle) < 2:
        return []
    out: list[dict[str, Any]] = []
    with ctx.session() as db:
        for d in db.scalars(select(Device)):
            ip = db.scalar(select(IpAddress.address).where(IpAddress.device_id == d.id)) or ""
            if needle in d.id.lower() or needle in ip or needle in d.role.lower():
                out.append({"type": "device", "id": d.id, "label": d.id, "detail": f"{ip} - {d.role}", "route": f"/devices/{d.id}"})
        for u in db.scalars(select(User)):
            if needle in u.id or needle in u.display_name.lower():
                out.append({"type": "user", "id": u.id, "label": u.display_name, "detail": u.title, "route": f"/identity/{u.id}"})
        for i in db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(200)):
            if needle in i.id.lower() or needle in i.title.lower():
                out.append({"type": "incident", "id": i.id, "label": i.id, "detail": f"{i.priority} {i.title} ({i.status})", "route": f"/incidents/{i.id}"})
        for x in db.scalars(select(Lease).order_by(Lease.created_at.desc()).limit(200)):
            if needle in x.id.lower():
                out.append({"type": "lease", "id": x.id, "label": x.id, "detail": f"{x.user_id} -> {x.destination_id}:{x.port} ({x.status})", "route": "/access"})
        for dr in db.scalars(select(DriftEvent).order_by(DriftEvent.detected_at.desc()).limit(200)):
            if needle in dr.id.lower():
                out.append({"type": "drift", "id": dr.id, "label": dr.id, "detail": f"{dr.device_id} {dr.component}.{dr.key} ({dr.status})", "route": "/drift"})
        for t in db.scalars(select(RemediationTransaction).order_by(RemediationTransaction.created_at.desc()).limit(200)):
            if needle in t.id.lower() or (t.correlation_id and needle in t.correlation_id.lower()):
                out.append({"type": "transaction", "id": t.id, "label": t.id, "detail": f"{t.action_name} on {t.target} ({t.status})", "route": f"/autoheal?tx={t.id}"})
        for pol in db.scalars(select(Policy)):
            if needle in pol.id.lower() or needle in pol.name.lower():
                out.append({"type": "policy", "id": pol.id, "label": pol.id, "detail": pol.name, "route": "/policies"})
    return out[:25]


class LoginIn(BaseModel):
    user_id: str = Field(max_length=64)


@router.get("/auth/config", tags=["auth"])
async def auth_config(ctx: Context = Depends(get_ctx)) -> dict[str, Any]:
    users = []
    if ctx.settings.demo_auth:
        with ctx.session() as db:
            users = [{"id": u.id, "name": u.display_name, "role": u.console_role} for u in db.scalars(select(User).order_by(User.id))]
    return {"demo_auth": ctx.settings.demo_auth, "users": users, "environment": ctx.environment_label, "version": __version__}


@router.post("/auth/demo-login", tags=["auth"], dependencies=[Depends(limited("auth"))])
async def demo_login(body: LoginIn, ctx: Context = Depends(get_ctx)) -> dict[str, Any]:
    if not ctx.settings.demo_auth:
        raise HTTPException(status_code=403, detail="demo login disabled; use an API key")
    with ctx.session() as db:
        user = db.get(User, body.user_id.lower())
        if user is None or not user.enabled:
            raise HTTPException(status_code=404, detail="unknown user")
        record_audit(ctx, db, actor=user.id, actor_type="OPERATOR", action="console login (demo)", reason="demo authentication", target="NEXUS", result="SUCCESS")
        token = ctx.signer.sign({"sub": user.id})  # type: ignore[attr-defined]
        return {"token": token, "principal": {"user_id": user.id, "name": user.display_name, "role": user.console_role, "method": "console-token"}}


@router.get("/auth/me", tags=["auth"])
async def me(p: Principal = Depends(current_principal)) -> dict[str, Any]:
    return p.model_dump() | {"rank": ROLE_RANK[p.role]}

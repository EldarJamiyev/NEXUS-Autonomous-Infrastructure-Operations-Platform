"""Network Time Machine: state snapshots and historical reconstruction from recorded data."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from nexus.core.util import sha256_of
from nexus.models import (
    Device,
    DriftEvent,
    Event,
    Incident,
    IpAddress,
    Lease,
    Policy,
    RiskScore,
    Service,
    StateSnapshot,
    User,
    Vlan,
)
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context

CATEGORIES = ["devices", "users", "services", "vlans", "firewall", "leases", "policies", "risk", "drift", "incidents"]


def capture(ctx: Context, db: Session) -> dict[str, Any]:
    ips = {r.device_id: r.address for r in db.scalars(select(IpAddress).where(IpAddress.device_id.is_not(None)))}
    risk = {f"{r.entity_type}:{r.entity_id}": r.score for r in db.scalars(select(RiskScore))}
    sessions: dict[str, list[str]] = {}
    for s in db.scalars(select(UserSession).where(UserSession.active.is_(True))):
        sessions.setdefault(s.user_id, []).append(s.device_id)
    try:
        firewall = {r["id"]: f"{r['action']} {r['source']} -> {r['destination']}:{r['port']}/{r['protocol']}" for r in ctx.firewall.list_rules(db)}
    except Exception:  # noqa: BLE001 - firewall unreachable: record that fact instead of guessing
        firewall = {"_unavailable": "firewall state unknown (API unreachable)"}
    from nexus.core.store import get_setting

    return {
        "devices": {d.id: {"status": d.status, "vlan": d.vlan_id, "ip": ips.get(d.id), "identity": d.identity_confidence, "level": d.identity_level,
                           "quarantined": d.quarantined, "kind": d.kind, "risk": risk.get(f"device:{d.id}", 0)} for d in db.scalars(select(Device))},
        "users": {u.id: {"risk": risk.get(f"user:{u.id}", 0), "sessions": sessions.get(u.id, [])} for u in db.scalars(select(User))},
        "services": {s.id: {"status": s.status, "enabled": s.enabled} for s in db.scalars(select(Service))},
        "vlans": {str(v.id): {"name": v.name, "status": v.status, "dhcp_in_use": v.dhcp_in_use} for v in db.scalars(select(Vlan))},
        "firewall": firewall,
        "leases": {x.id: {"user": x.user_id, "device": x.device_id, "destination": f"{x.destination_id}:{x.port}", "status": x.status,
                          "expires": x.expires_at.isoformat()} for x in db.scalars(select(Lease).where(Lease.status.in_(("ACTIVE", "PENDING", "PENDING_APPROVAL"))))},
        "policies": {p.id: {"version": p.active_version, "status": p.status} for p in db.scalars(select(Policy))},
        "risk": risk,
        "drift": {d.id: {"device": d.device_id, "key": f"{d.component}.{d.key}", "class": d.classification, "status": d.status}
                  for d in db.scalars(select(DriftEvent).where(DriftEvent.status.in_(("OPEN", "APPROVAL_REQUIRED", "REMEDIATING", "FAILED", "EXPECTED"))))},
        "incidents": {i.id: {"title": i.title, "priority": i.priority, "status": i.status}
                      for i in db.scalars(select(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING", "MITIGATED"))))},
        "mode": (get_setting(db, "system_mode") or {}).get("mode", "NORMAL"),
    }


def create_snapshot(ctx: Context, db: Session, reason: str, label: str | None = None, correlation_id: str | None = None,
                    force: bool = False) -> StateSnapshot | None:
    import time

    if not force and ctx.runtime.db_degraded_until and time.time() < ctx.runtime.db_degraded_until:
        return None
    data = capture(ctx, db)
    snap = StateSnapshot(ts=ctx.clock.now(), reason=reason[:128], label=label, data=data, checksum=sha256_of(data), correlation_id=correlation_id)
    db.add(snap)
    db.flush()
    total = db.scalar(select(func.count()).select_from(StateSnapshot)) or 0
    excess = total - ctx.settings.snapshot_retention
    if excess > 0:
        oldest = db.scalars(select(StateSnapshot.id).where(StateSnapshot.label.is_(None)).order_by(StateSnapshot.ts).limit(excess)).all()
        if oldest:
            db.execute(delete(StateSnapshot).where(StateSnapshot.id.in_(oldest)))
    ctx.runtime.last_snapshot = time.time()
    ctx.runtime.snapshot_dirty = False
    return snap


def summarize(data: dict[str, Any]) -> dict[str, Any]:
    devices = data.get("devices", {})
    return {"devices": len(devices), "quarantined": sum(1 for d in devices.values() if d.get("quarantined")),
            "services_down": sum(1 for s in data.get("services", {}).values() if s.get("status") != "running"),
            "active_leases": sum(1 for x in data.get("leases", {}).values() if x.get("status") == "ACTIVE"),
            "open_incidents": len(data.get("incidents", {})), "open_drift": len(data.get("drift", {})), "mode": data.get("mode"),
            "max_risk": max((v for k, v in data.get("risk", {}).items() if k.startswith("device:")), default=0),
            "sessions": sum(len(u.get("sessions", [])) for u in data.get("users", {}).values())}


def timeline(db: Session, since: datetime | None = None, limit: int = 400) -> dict[str, Any]:
    q = select(StateSnapshot).order_by(StateSnapshot.ts.desc()).limit(limit)
    if since:
        q = q.where(StateSnapshot.ts >= since)
    snaps = list(reversed(db.scalars(q).all()))
    markers = db.scalars(select(Event).where(Event.type.in_(("INCIDENT_CREATED", "INCIDENT_RESOLVED", "QUARANTINE_STARTED", "DRIFT_DETECTED",
                                                              "FAILURE_INJECTED", "SYSTEM_MODE_CHANGED")))
                         .where(Event.ts >= (snaps[0].ts if snaps else datetime.min)).order_by(Event.ts)).all()
    return {"snapshots": [{"id": s.id, "ts": s.ts.isoformat(), "reason": s.reason, "label": s.label, "summary": summarize(s.data)} for s in snaps],
            "markers": [{"ts": e.ts.isoformat(), "type": e.type, "message": e.message, "target": e.target} for e in markers]}


def state_at(db: Session, at: datetime) -> dict[str, Any] | None:
    snap = db.scalar(select(StateSnapshot).where(StateSnapshot.ts <= at).order_by(StateSnapshot.ts.desc()))
    if snap is None:
        snap = db.scalar(select(StateSnapshot).order_by(StateSnapshot.ts))
        if snap is None:
            return None
    events = db.scalars(select(Event).where(Event.ts > snap.ts, Event.ts <= at).order_by(Event.ts).limit(200)).all()
    return {"requested_at": at.isoformat(), "snapshot": {"id": snap.id, "ts": snap.ts.isoformat(), "reason": snap.reason, "checksum": snap.checksum},
            "state": snap.data, "summary": summarize(snap.data),
            "events_since_snapshot": [{"ts": e.ts.isoformat(), "type": e.type, "message": e.message, "target": e.target} for e in events]}


def compare(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cat in CATEGORIES:
        av, bv = a.get(cat, {}) or {}, b.get(cat, {}) or {}
        added = sorted(set(bv) - set(av))
        removed = sorted(set(av) - set(bv))
        changed = []
        for key in sorted(set(av) & set(bv)):
            if av[key] != bv[key]:
                if isinstance(av[key], dict) and isinstance(bv[key], dict):
                    fields = {f: [av[key].get(f), bv[key].get(f)] for f in set(av[key]) | set(bv[key]) if av[key].get(f) != bv[key].get(f)}
                else:
                    fields = {"value": [av[key], bv[key]]}
                changed.append({"id": key, "fields": fields})
        out[cat] = {"added": [{"id": k, "value": bv[k]} for k in added], "removed": [{"id": k, "value": av[k]} for k in removed], "changed": changed}
    out["totals"] = {c: sum(len(out[c][k]) for k in ("added", "removed", "changed")) for c in CATEGORIES}
    return out

"""Observed health of devices and services, and the infrastructure health distribution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, DriftEvent, Incident, Service

if TYPE_CHECKING:
    from nexus.core.context import Context


def device_status(dev: Device, services: list[Service], drift_devices: set[str], incident_targets: set[str]) -> str:
    if dev.quarantined:
        return "quarantined"
    if not dev.reachable:
        return "critical"
    down = [s for s in services if s.status != "running"]
    disks = (dev.metrics or {}).get("disk", {})
    peak = max(disks.values()) if disks else 0
    if any(s.criticality in ("CRITICAL", "HIGH") for s in down) or peak >= 95:
        return "critical"
    if down or peak >= 85 or dev.kind == "unknown" or dev.id in incident_targets or dev.id in drift_devices:
        return "warning"
    return "healthy"


def update_statuses(ctx: Context, db: Session) -> dict[str, str]:
    services: dict[str, list[Service]] = {}
    for s in db.scalars(select(Service)):
        services.setdefault(s.device_id, []).append(s)
    drift_devices = set(db.scalars(select(DriftEvent.device_id).where(DriftEvent.status.in_(("OPEN", "APPROVAL_REQUIRED", "FAILED")), DriftEvent.classification != "COSMETIC")))
    incident_targets = set(db.scalars(select(Incident.target).where(Incident.status.in_(("OPEN", "INVESTIGATING")))))
    out = {}
    for dev in db.scalars(select(Device)):
        status = device_status(dev, services.get(dev.id, []), drift_devices, incident_targets)
        dev.status = status
        if dev.reachable:
            dev.last_seen = ctx.clock.now()
        out[dev.id] = status
    return out


def distribution(db: Session) -> dict[str, Any]:
    counts = {"healthy": 0, "warning": 0, "critical": 0, "quarantined": 0}
    for status in db.scalars(select(Device.status)):
        counts[status if status in counts else "warning"] += 1
    total = sum(counts.values()) or 1
    pct = {k: round(100 * v / total) for k, v in counts.items()}
    services = db.scalars(select(Service)).all()
    up = sum(1 for s in services if s.status == "running")
    return {"counts": counts, "percent": pct, "total": total, "health_percent": round(100 * (counts["healthy"] + 0.5 * counts["warning"]) / total),
            "services_up": up, "services_total": len(services), "services_down": len(services) - up}

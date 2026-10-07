"""Security policy evaluation (SECURITY-004 quarantine of identityless high-risk endpoints)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, Event
from nexus.risk.engine import score_of

if TYPE_CHECKING:
    from nexus.core.context import Context


def matching_policy(ctx: Context, db: Session, dev: Device):  # noqa: ANN201
    cache = ctx.policy_cache
    if not cache:
        return None
    for pol in cache.security:
        q = pol.spec.quarantine
        if dev.quarantined or dev.id in q.protected_devices:
            continue
        if dev.identity_level in q.identity_levels and dev.kind in q.device_kinds and score_of(db, "device", dev.id) >= q.min_risk:
            return pol
    return None


def evaluate_security_policies(ctx: Context, db: Session, dev: Device, correlation_id: str | None = None) -> None:
    pol = matching_policy(ctx, db, dev)
    if pol is None:
        return
    from nexus.incidents.engine import open_finding

    admin = [e for e in db.scalars(select(Event).where(Event.type == "PORT_ACTIVITY", Event.target == dev.id)) if (e.data or {}).get("admin_port")]
    summary = (f"{dev.id} has no establishable identity ({dev.identity_confidence}%) and risk {score_of(db, 'device', dev.id)}"
               + (f"; attempted TCP/{admin[-1].data.get('port')} to {admin[-1].data.get('dst')}" if admin else ""))
    open_finding(ctx, db, name="HighRiskDevice", target=dev.id, summary=summary,
                 labels={"policy": pol.metadata.id, "admin_activity": bool(admin), "identity": dev.identity_level})

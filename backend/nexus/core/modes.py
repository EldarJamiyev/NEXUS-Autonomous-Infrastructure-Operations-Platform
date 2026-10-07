"""System operating modes: NORMAL, DEGRADED, RECOVERY, EMERGENCY - with the behaviour each implies."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.core.store import get_setting, set_setting
from nexus.models import Device, Incident, Lease, RemediationTransaction, Service

if TYPE_CHECKING:
    from nexus.core.context import Context


def evaluate_mode(ctx: Context, db: Session) -> dict[str, Any]:
    now_s = time.time()
    degraded, behaviors = [], []
    if not ctx.firewall.available():
        degraded.append("pfSense API unavailable")
        behaviors += ["Existing safe state preserved", "New privileged leases blocked", "Firewall changes queued as PENDING", "Reconciliation pending"]
    if ctx.runtime.db_degraded_until and now_s < ctx.runtime.db_degraded_until:
        degraded.append("state store latency high (simulated)")
        behaviors += ["Snapshots deferred", "Only SAFE actions run automatically"]
    mon = db.get(Device, "MON01")
    prom = db.get(Service, "prometheus@MON01")
    if (mon and not mon.reachable) or (prom and prom.status != "running"):
        degraded.append("monitoring visibility reduced (MON01)")
        behaviors += ["Detection relies on NEXUS internal probes"]
    open_q = select(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING")))
    open_incidents = db.scalars(open_q).all()
    p1 = sum(1 for i in open_incidents if i.priority == "P1")
    emergency = ctx.runtime.blackout_running or p1 >= 2 or (p1 >= 1 and len(open_incidents) >= 4)
    previous = get_setting(db, "system_mode") or {}
    running = db.scalar(select(func.count()).select_from(RemediationTransaction).where(RemediationTransaction.status.in_(("PLANNED", "RUNNING")))) or 0
    pending_fw = db.scalar(select(func.count()).select_from(Lease).where(Lease.firewall_state.in_(("PENDING", "PENDING_REMOVAL"))) ) or 0
    if emergency:
        mode = "EMERGENCY"
        reasons = (["full infrastructure blackout drill running"] if ctx.runtime.blackout_running else []) + [f"{p1} open P1 incident(s), {len(open_incidents)} open in total"]
        behaviors = ["Incidents correlated before acting", "Remediation follows dependency order", "Mass-change guard enforced", *behaviors]
    elif degraded:
        mode, reasons = "DEGRADED", degraded
    elif previous.get("mode") in ("DEGRADED", "EMERGENCY") or (ctx.runtime.recovery_until and now_s < ctx.runtime.recovery_until) or (
            previous.get("mode") == "RECOVERY" and (running or pending_fw)):
        if previous.get("mode") in ("DEGRADED", "EMERGENCY"):
            ctx.runtime.recovery_until = now_s + 20
        mode = "RECOVERY"
        reasons = ["recovering from " + (previous.get("mode", "DEGRADED").lower() if previous.get("mode") != "RECOVERY" else "degradation")]
        behaviors = ["Replaying pending firewall changes", "Re-verifying remediated components", "Returning to NORMAL when queues are empty"]
    else:
        mode, reasons = "NORMAL", []
        behaviors = [f"Autonomy level {get_setting(db, 'autonomy_level')}", f"Reconciliation every {int(ctx.settings.reconcile_interval)} s"]
    state = {"mode": mode, "reasons": reasons, "behaviors": behaviors, "since": previous.get("since") if previous.get("mode") == mode else ctx.clock.now().isoformat()}
    if previous.get("mode") != mode:
        set_setting(db, "system_mode", state, ctx.clock.now())
        ctx.bus.emit(db, "SYSTEM_MODE_CHANGED", f"System mode {previous.get('mode', 'NORMAL')} -> {mode}" + (f": {'; '.join(reasons)}" if reasons else ""),
                     severity="high" if mode in ("DEGRADED", "EMERGENCY") else "notice", source="controller", data=state)
    elif previous.get("reasons") != reasons:
        set_setting(db, "system_mode", state, ctx.clock.now())
    return state

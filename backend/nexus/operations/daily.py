"""Everyday operations: AutoHeal scorecard, daily operations view, morning brief, shift handover."""

from __future__ import annotations

from datetime import timedelta
from statistics import mean
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.core.decision import in_change_window, next_window
from nexus.models import (
    Alert,
    Approval,
    Certificate,
    ChangeRequest,
    Device,
    DriftEvent,
    Event,
    Incident,
    Lease,
    RemediationTransaction,
    RiskScore,
)
from nexus.monitoring.health import distribution

if TYPE_CHECKING:
    from nexus.core.context import Context


def scorecard(ctx: Context, db: Session, hours: int = 24 * 7) -> dict[str, Any]:
    since = ctx.clock.now() - timedelta(hours=hours)
    alerts = db.scalars(select(Alert).where(Alert.first_seen >= since)).all()
    txs = db.scalars(select(RemediationTransaction).where(RemediationTransaction.created_at >= since)).all()
    incidents = db.scalars(select(Incident).where(Incident.created_at >= since)).all()
    finished = [t for t in txs if t.status in ("COMMITTED", "ROLLED_BACK", "FAILED")]
    ok = [t for t in finished if t.result == "SUCCESS"]
    detection = []
    for a in alerts:
        inj = db.scalar(select(Event).where(Event.type == "FAILURE_INJECTED", Event.target == a.target, Event.ts <= a.first_seen,
                                            Event.ts >= a.first_seen - timedelta(minutes=5)).order_by(Event.ts.desc()))
        if inj:
            detection.append((a.first_seen - inj.ts).total_seconds())
    verify = []
    for t in ok:
        steps = {s["name"]: s for s in t.steps}
        a, b = steps.get("EXECUTION", {}).get("ts"), steps.get("VERIFICATION", {}).get("ts")
        if a and b:
            from datetime import datetime

            verify.append((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds())
    resolved = [i for i in incidents if i.resolved_at]
    auto = [i for i in resolved if not i.human_required]
    return {
        "label": "SIMULATION METRICS" if ctx.settings.is_simulation else "LAB METRICS", "window_hours": hours,
        "alerts_received": len(alerts), "auto_resolved": len(auto), "human_required": sum(1 for i in incidents if i.human_required),
        "remediation_success_pct": round(100 * len(ok) / len(finished), 1) if finished else None,
        "rollbacks": sum(1 for t in txs if t.status == "ROLLED_BACK"),
        "mean_detection_seconds": round(mean(detection), 1) if detection else None,
        "mean_remediation_seconds": round(mean((t.duration_ms or 0) / 1000 for t in ok), 1) if ok else None,
        "mean_verification_seconds": round(mean(verify), 1) if verify else None,
        "mttr_seconds": round(mean(((i.resolved_at or i.created_at) - i.created_at).total_seconds() for i in resolved), 1) if resolved else None,
        "open_incidents": db.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING")))) or 0,
        "false_positives": sum(1 for i in incidents if i.status == "FALSE_POSITIVE") + sum(1 for a in alerts if a.status == "STALE"),
        "active_leases": db.scalar(select(func.count()).select_from(Lease).where(Lease.status == "ACTIVE")) or 0,
        "quarantined_devices": db.scalar(select(func.count()).select_from(Device).where(Device.quarantined.is_(True))) or 0,
        "manual_interventions_avoided": len(ok), "repeated_incidents": sum(1 for i in incidents if i.recurring),
        "notes": "Measured from simulated runs in this database. These are not real-world performance claims.",
    }


def daily_operations(ctx: Context, db: Session) -> dict[str, Any]:
    now = ctx.clock.now()
    site = ctx.clock.site_now()
    night_start = (site - timedelta(days=1)).replace(hour=18, minute=0, second=0, microsecond=0)
    overnight = db.scalars(select(Incident).where(Incident.created_at >= night_start.astimezone(now.tzinfo)).order_by(Incident.created_at.desc())).all()
    soon = now + timedelta(minutes=30)
    window_ok, window_text = in_change_window(ctx, db)
    certs = [{"id": c.id, "device": c.device_id, "days": round((c.not_after - now).total_seconds() / 86400, 1)} for c in db.scalars(select(Certificate))]
    capacity = []
    for d in db.scalars(select(Device)):
        for mount, pct in ((d.metrics or {}).get("disk", {}) or {}).items():
            if pct >= 75:
                capacity.append({"device": d.id, "resource": f"disk {mount}", "value": pct})
        if (d.metrics or {}).get("cpu") and d.metrics["cpu"] >= 80:
            capacity.append({"device": d.id, "resource": "cpu", "value": d.metrics["cpu"]})
    return {
        "overnight_incidents": [{"id": i.id, "title": i.title, "priority": i.priority, "status": i.status, "created_at": i.created_at.isoformat()} for i in overnight],
        "unresolved_alerts": [{"id": a.id, "name": a.name, "target": a.target, "since": a.first_seen.isoformat()} for a in db.scalars(select(Alert).where(Alert.status == "FIRING"))],
        "maintenance": {"current": "INSIDE MAINTENANCE" if window_ok else "OUTSIDE MAINTENANCE", "detail": window_text, "next": next_window(ctx, db)},
        "expiring_leases": [{"id": x.id, "user": x.user_id, "destination": f"{x.destination_id}:{x.port}", "expires_at": x.expires_at.isoformat()}
                            for x in db.scalars(select(Lease).where(Lease.status == "ACTIVE", Lease.expires_at <= soon))],
        "drift": [{"id": d.id, "device": d.device_id, "key": f"{d.component}.{d.key}", "class": d.classification, "status": d.status}
                  for d in db.scalars(select(DriftEvent).where(DriftEvent.status.in_(("OPEN", "APPROVAL_REQUIRED", "FAILED", "EXPECTED"))))],
        "high_risk_devices": [{"id": r.entity_id, "score": r.score, "level": r.level} for r in db.scalars(select(RiskScore).where(RiskScore.entity_type == "device", RiskScore.score >= 50).order_by(RiskScore.score.desc()))],
        "failed_automations": [{"id": t.id, "action": t.action_name, "target": t.target, "status": t.status} for t in db.scalars(select(RemediationTransaction).where(RemediationTransaction.status.in_(("FAILED", "ROLLED_BACK"))).order_by(RemediationTransaction.created_at.desc()).limit(10))],
        "certificates": sorted(certs, key=lambda c: c["days"]), "capacity_warnings": capacity,
        "pending_approvals": db.scalar(select(func.count()).select_from(Approval).where(Approval.status == "PENDING")) or 0,
    }


def morning_brief(ctx: Context, db: Session) -> dict[str, Any]:
    ops = daily_operations(ctx, db)
    sc = scorecard(ctx, db, hours=24)
    dist = distribution(db)
    recurring = db.scalar(select(Incident).where(Incident.recurring != {}).order_by(Incident.created_at.desc()))
    recs = []
    if recurring and recurring.recurring:
        recs.append(f"Investigate recurring {recurring.title.split(' (')[0]} ({recurring.recurring.get('occurrences')} occurrences in 7 days)")
    recs += [f"Renew certificate {c['id']} ({c['days']} days left)" for c in ops["certificates"] if c["days"] <= 14]
    if ops["pending_approvals"]:
        recs.append(f"Review {ops['pending_approvals']} pending approval(s)")
    system = "Healthy" if dist["counts"]["critical"] == 0 and not ops["unresolved_alerts"] else "Degraded"
    ok = sum(1 for t in db.scalars(select(RemediationTransaction).where(RemediationTransaction.created_at >= ctx.clock.now() - timedelta(hours=24), RemediationTransaction.result == "SUCCESS")))
    failed = sum(1 for t in db.scalars(select(RemediationTransaction).where(RemediationTransaction.created_at >= ctx.clock.now() - timedelta(hours=24), RemediationTransaction.result == "FAILED")))
    brief: dict[str, Any] = {"system": system, "incidents_overnight": len(ops["overnight_incidents"]), "drift": len(ops["drift"]), "high_risk_devices": len(ops["high_risk_devices"]),
             "autoheal_successful": ok, "autoheal_failed": failed, "upcoming": f"Maintenance window {ops['maintenance']['next']}", "recommended": recs or ["No action required"],
             "scorecard": sc}
    md = ["NEXUS DAILY INFRASTRUCTURE BRIEF", f"{ctx.clock.site_now():%A %d %B %Y, %H:%M} ({ctx.environment_label})", "",
          f"SYSTEM:            {system}", f"INCIDENTS:         {brief['incidents_overnight']} overnight", f"DRIFT:             {brief['drift']}",
          f"HIGH-RISK DEVICES: {brief['high_risk_devices']}", f"AUTOHEAL:          {ok} successful / {failed} failed (24 h)",
          f"UPCOMING:          {brief['upcoming']}", "RECOMMENDED:"] + [f"  - {r}" for r in brief["recommended"]]
    brief["text"] = "\n".join(md)
    return brief


def handover_markdown(ctx: Context, db: Session, hours: int = 8) -> str:
    since = ctx.clock.now() - timedelta(hours=hours)
    incs = db.scalars(select(Incident).where(Incident.updated_at >= since).order_by(Incident.created_at)).all()
    fixed = [i for i in incs if i.status in ("RESOLVED", "MITIGATED")]
    open_ = db.scalars(select(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING")))).all()
    risky = db.scalars(select(RiskScore).where(RiskScore.entity_type == "device", RiskScore.score >= 40).order_by(RiskScore.score.desc())).all()
    changes = db.scalars(select(ChangeRequest).where(ChangeRequest.status.in_(("PENDING_APPROVAL", "APPROVED", "SCHEDULED")))).all()
    approvals = db.scalars(select(Approval).where(Approval.status == "PENDING")).all()
    L = [f"# Shift handover - {ctx.clock.site_now():%Y-%m-%d %H:%M}", "", f"Covers the last {hours} hours. Environment: {ctx.environment_label}.", "",
         "## What happened", ""] + ([f"- {i.id} {i.priority} {i.title} ({i.status})" for i in incs] or ["- Quiet shift: no incidents."])
    L += ["", "## What was fixed", ""] + ([f"- {i.id}: {i.root_cause or i.title}" for i in fixed] or ["- Nothing needed fixing."])
    L += ["", "## Still unresolved", ""] + ([f"- {i.id} {i.priority} {i.title}" + (" - human action required" if i.human_required else "") for i in open_] or ["- Nothing open."])
    L += ["", "## Risky systems", ""] + ([f"- {r.entity_id}: risk {r.score} ({r.level})" for r in risky] or ["- No device above risk 40."])
    L += ["", "## Pending changes", ""] + ([f"- {c.id} {c.title} ({c.status}, window {c.window or '-'})" for c in changes] or ["- None."])
    L += ["", "## Waiting approvals", ""] + ([f"- {a.id} {a.title} ({a.category}) - {a.reason}" for a in approvals] or ["- None."])
    return "\n".join(L) + "\n"

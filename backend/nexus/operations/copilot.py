"""NEXUS Operator Assistant - deterministic, read-only natural-language queries over NEXUS state.

No language model is involved: questions are matched to a small set of intents and answered by
read-only queries. Nothing here can change infrastructure (ADR-009 AI trust boundary).
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, DriftEvent, Event, Incident, RiskScore, Service, User

if TYPE_CHECKING:
    from nexus.core.context import Context

EXAMPLES = ["Why is PC-023 quarantined?", "What changed on LINUX01 today?", "Which users would be affected if VLAN 30 goes down?",
            "Why can't Aysel access port 22?", "What caused the latest P1 incident?", "Which devices currently have elevated risk?",
            "Why is LINUX01 unhealthy?"]


def _find_device(db: Session, q: str) -> Device | None:
    for d in db.scalars(select(Device)):
        if d.id.lower() in q.lower():
            return d
    return None


def _find_user(db: Session, q: str) -> User | None:
    for u in db.scalars(select(User)):
        if u.id in q.lower() or u.display_name.split()[0].lower() in q.lower():
            return u
    return None


def ask(ctx: Context, db: Session, question: str) -> dict[str, Any]:
    q = question.strip()
    ql = q.lower()
    dev, user = _find_device(db, q), _find_user(db, q)
    port = int(m.group(1)) if (m := re.search(r"port (\d{1,5})", ql)) else None
    if "quarantin" in ql and dev:
        intent = f"explain_quarantine(device={dev.id})"
        if not dev.quarantined:
            answer = f"{dev.id} is not quarantined. It is in VLAN {dev.vlan_id} with identity confidence {dev.identity_confidence}% and status {dev.status}."
        else:
            inc = db.scalar(select(Incident).where(Incident.target == dev.id).order_by(Incident.created_at.desc()))
            answer = (f"{dev.id} is quarantined in VLAN 99 because {dev.quarantine_reason}. Identity confidence is {dev.identity_confidence}% "
                      f"({dev.identity_level}).") + (f" Incident {inc.id}: {inc.title} ({inc.status}); root cause: {inc.root_cause}." if inc else "")
    elif ("changed" in ql or "change" in ql) and dev:
        intent = f"changes(device={dev.id}, since=today)"
        start = ctx.clock.site_now().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(ctx.clock.now().tzinfo)
        evs = db.scalars(select(Event).where(Event.target == dev.id, Event.ts >= start, Event.type.in_(
            ("CONFIG_CHANGED", "FIREWALL_CHANGE", "DRIFT_DETECTED", "DRIFT_REMEDIATED", "REMEDIATION_COMPLETED", "REMEDIATION_FAILED", "QUARANTINE_STARTED"))).order_by(Event.ts)).all()
        answer = (f"{len(evs)} change-related event(s) on {dev.id} today:\n" + "\n".join(f"- {e.ts.astimezone(ctx.clock.site_tz):%H:%M:%S} {e.message}" for e in evs[-12:])) if evs else f"No configuration changes recorded on {dev.id} today."
    elif "vlan" in ql and ("affect" in ql or "goes down" in ql or "fail" in ql) and (m := re.search(r"vlan\s*(\d+)", ql)):
        from nexus.whatif.engine import simulate

        intent = f"whatif(vlan_down, vlan={m.group(1)})"
        r = simulate(ctx, db, "vlan_down", {"vlan": int(m.group(1))})
        imp = r["impact"]
        answer = (f"If VLAN {m.group(1)} goes down: {imp['counts']['devices']} device(s) ({', '.join(imp['devices']) or 'none'}), "
                  f"{imp['counts']['users']} user(s) ({', '.join(imp['user_names']) or 'none'}), {imp['counts']['leases']} active lease(s). Simulation only - nothing was changed.")
    elif ("access" in ql or "can't" in ql or "cannot" in ql) and user and (port or dev):
        from nexus.models import Session as UserSession
        from nexus.policy.evaluator import evaluate_access

        session = db.scalar(select(UserSession).where(UserSession.user_id == user.id, UserSession.active.is_(True)))
        src = session.device_id if session else "PC-024"
        dst = dev.id if dev and dev.id != src else "LINUX01"
        intent = f"explain_access(user={user.id}, device={src}, destination={dst}, port={port or 22})"
        answer = evaluate_access(ctx, db, user.id, src, dst, port or 22)["narrative"]
    elif "p1" in ql or ("latest" in ql and "incident" in ql) or "caused" in ql:
        prio = "P1" if "p1" in ql else None
        qy = select(Incident).order_by(Incident.created_at.desc())
        if prio:
            qy = qy.where(Incident.priority == prio)
        inc = db.scalar(qy)
        intent = f"latest_incident(priority={prio or 'any'})"
        answer = (f"{inc.id} {inc.priority} \"{inc.title}\" ({inc.status}). Root cause ({inc.root_cause_confidence}): {inc.root_cause}. "
                  f"Evidence: {'; '.join((inc.evidence or [])[:3])}.") if inc else "No matching incident."
    elif "risk" in ql:
        intent = "devices_by_risk(min=30)"
        rows = db.scalars(select(RiskScore).where(RiskScore.entity_type == "device", RiskScore.score >= 30).order_by(RiskScore.score.desc())).all()
        answer = ("Devices with elevated risk:\n" + "\n".join(f"- {r.entity_id}: {r.score} ({r.level}) - " + ", ".join(f["label"] for f in sorted(r.factors, key=lambda f: -f["points"])[:2]) for r in rows)) if rows else "No device is above risk 30."
    elif ("unhealthy" in ql or "health" in ql or "status of" in ql) and dev:
        intent = f"explain_health(device={dev.id})"
        down = db.scalars(select(Service).where(Service.device_id == dev.id, Service.status != "running")).all()
        drift = db.scalars(select(DriftEvent).where(DriftEvent.device_id == dev.id, DriftEvent.status.in_(("OPEN", "REMEDIATING", "APPROVAL_REQUIRED", "FAILED")))).all()
        incs = db.scalars(select(Incident).where(Incident.target == dev.id, Incident.status.in_(("OPEN", "INVESTIGATING", "MITIGATED")))).all()
        parts = [f"{dev.id} status is {dev.status}."]
        if down:
            parts.append("Services not running: " + ", ".join(f"{s.name} ({s.status})" for s in down) + ".")
        if drift:
            parts.append("Open drift: " + ", ".join(f"{d.component}.{d.key} ({d.status})" for d in drift) + ".")
        if incs:
            parts.append("Incidents: " + "; ".join(f"{i.id} {i.title} - {i.status}, root cause: {i.root_cause}" for i in incs) + ".")
        recent = db.scalar(select(Event).where(Event.target == dev.id, Event.type == "CONFIG_CHANGED", Event.ts >= ctx.clock.now() - timedelta(hours=1)).order_by(Event.ts.desc()))
        if recent:
            parts.append(f"Most recent configuration change: {recent.message} at {recent.ts.astimezone(ctx.clock.site_tz):%H:%M:%S}.")
        if len(parts) == 1:
            parts.append("No failing services, drift or open incidents.")
        answer = " ".join(parts)
    else:
        intent = "unrecognised"
        answer = "I can answer read-only questions about NEXUS state. Try: " + " | ".join(EXAMPLES[:4])
    return {"question": q, "interpreted_as": intent, "answer": answer, "read_only": True, "engine": "deterministic intent matcher (no LLM)"}

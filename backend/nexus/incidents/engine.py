"""Incident engine: alert ingest -> validation -> correlation -> incident -> RCA -> plan.

One incident, many symptoms: alerts in the availability family are merged when the dependency
graph connects them; security/network findings merge only on the same target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.core.audit import record_audit
from nexus.core.util import sha256_of
from nexus.dependencies.graph import ServiceGraph, impact_of
from nexus.ids import new_id
from nexus.incidents import rca
from nexus.incidents.catalog import correlation_group, family, meta
from nexus.incidents.triage import triage
from nexus.models import (
    Alert,
    Certificate,
    Decision,
    Device,
    Event,
    Incident,
    IncidentEvent,
    RemediationTransaction,
    Service,
)
from nexus.risk.engine import score_of

if TYPE_CHECKING:
    from nexus.core.context import Context

OPEN = ("OPEN", "INVESTIGATING", "MITIGATED")
CORRELATION_WINDOW = timedelta(minutes=10)


@dataclass
class AlertIn:
    name: str
    target: str
    source: str = "nexus-monitor"
    severity: str | None = None
    service_id: str | None = None
    summary: str = ""
    labels: dict[str, Any] = field(default_factory=dict)


def fingerprint(name: str, target: str, service_id: str | None, labels: dict[str, Any] | None = None) -> str:
    extra = (labels or {}).get("port") or (labels or {}).get("certificate") or (labels or {}).get("mount") or ""
    return sha256_of(f"{name}|{target}|{service_id or ''}|{extra}")[:16]


# --------------------------------------------------------------------------- validation
def validate(ctx: Context, db: Session, a: Alert) -> tuple[bool, str]:
    """Never act on an alert blindly: confirm the condition against current observed state."""
    m = meta(a.name)
    if a.source == "nexus-analytics":
        return True, "derived from current NEXUS state"
    if m.get("service") and a.service_id:
        svc = db.get(Service, a.service_id)
        if svc is None:
            return False, f"{a.service_id} not in inventory"
        if a.name == "NginxDown":
            ok, detail = ctx.world.tcp_reachable(db, svc.device_id, 443)
            if svc.status != "running" or not ok:
                return True, f"nginx {svc.status}; {detail}"
            return False, "nginx running and TCP/443 reachable - alert is stale"
        if a.name == "PortalHealthCheckFailed":
            code, detail = ctx.world.http_status(db, "APP01", 8080)
            return (code != 200), detail
        if a.name == "ADAuthenticationFailures":
            return True, a.summary
        if a.name == "NTPClockSkew":
            skew = ctx.world.clock_skew(db, svc.device_id)
            return (skew > 60 or svc.status != "running"), f"offset {skew:.0f}s, W32Time {svc.status}"
        return (svc.status != "running"), f"{a.service_id} is {svc.status}"
    dev = db.get(Device, a.target)
    if a.name == "NodeDown":
        return bool(dev and not dev.reachable), "no ARP/ICMP response" if dev and not dev.reachable else "host answers - stale"
    if a.name == "DiskSpaceCritical" and dev:
        peak = max((dev.metrics or {}).get("disk", {}).values() or [0])
        return peak >= 90, f"peak filesystem {peak:.0f}%"
    if a.name == "HighCPU" and dev:
        cpu = ctx.world.cpu_now(dev)
        return cpu >= 90, f"CPU {cpu:.0f}%"
    if a.name.startswith("Certificate"):
        cert = db.get(Certificate, a.labels.get("certificate", ""))
        if cert is None:
            return False, "unknown certificate"
        days = (cert.not_after - ctx.clock.now()).total_seconds() / 86400
        return days <= 14, f"{days:.1f} days remaining"
    return True, "condition accepted"


# ------------------------------------------------------------------------------ ingest
def ingest_alert(ctx: Context, db: Session, a_in: AlertIn) -> Alert | None:
    m = meta(a_in.name)
    if a_in.service_id is None and m.get("service") and "@" not in a_in.target:
        a_in.service_id = f"{m['service']}@{a_in.target}"
    fp = fingerprint(a_in.name, a_in.target, a_in.service_id, a_in.labels)
    now = ctx.clock.now()
    existing = db.scalar(select(Alert).where(Alert.fingerprint == fp, Alert.status == "FIRING"))
    if existing:
        existing.last_seen = now
        existing.count += 1
        return existing
    alert = Alert(id=new_id(db, "alert"), name=a_in.name, source=a_in.source, severity=a_in.severity or m["severity"], target=a_in.target,
                  service_id=a_in.service_id, fingerprint=fp, labels=a_in.labels, summary=(a_in.summary or m["title"].format(target=a_in.target))[:256],
                  status="FIRING", count=1, correlation_id=new_id(db, "corr"), first_seen=now, last_seen=now)
    db.add(alert)
    db.flush()
    ctx.bus.emit(db, "ALERT_RECEIVED", f"{alert.id} {alert.name} {alert.target}: {alert.summary}", severity=alert.severity if alert.severity in ("critical", "high", "warning") else "warning",
                 source=alert.source, target=alert.target, data={"alert": alert.id, "name": alert.name, "labels": alert.labels},
                 correlation_id=alert.correlation_id)
    valid, note = validate(ctx, db, alert)
    alert.validated, alert.validation_note = valid, note[:256]
    if not valid:
        alert.status = "STALE"
        alert.resolved_at = now
        ctx.bus.emit(db, "ALERT_STALE", f"{alert.id} {alert.name} discarded: {note}", source="alert-triage", target=alert.target,
                     data={"alert": alert.id}, correlation_id=alert.correlation_id)
        return alert
    correlate(ctx, db, alert)
    return alert


def correlate(ctx: Context, db: Session, alert: Alert) -> Incident:
    m = meta(alert.name)
    fam = family(m["category"])
    graph = ServiceGraph(db)
    since = ctx.clock.now() - CORRELATION_WINDOW
    for inc in db.scalars(select(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING")), Incident.created_at >= since)
                          .order_by(Incident.created_at)):
        if family(inc.category) != fam:
            continue
        if fam == "AVAILABILITY":
            entity = alert.service_id or alert.target
            related = alert.target == inc.target or any(graph.related(entity, s) for s in (inc.affected_services or []) if s in graph.services)
        else:
            related = alert.target == inc.target and correlation_group(alert.name) == correlation_group((inc.triage or {}).get("alert", ""))
        if related:
            attach(ctx, db, inc, alert)
            return inc
    return create_incident(ctx, db, alert)


def _impact_for(ctx: Context, db: Session, alert: Alert) -> dict[str, Any]:
    m = meta(alert.name)
    if family(m["category"]) == "AVAILABILITY":
        if alert.name == "NodeDown":
            return impact_of(ctx, db, devices={alert.target})
        if alert.service_id:
            return impact_of(ctx, db, services={alert.service_id})
    dev = db.get(Device, alert.target)
    return {"level": "LOW", "devices": [alert.target] if dev else [], "services": [], "users": [], "leases": [], "policies": [],
            "counts": {"devices": 1 if dev else 0, "services": 0, "users": 0, "leases": 0, "policies": 0}, "propagation": [], "recovery_order": []}


def create_incident(ctx: Context, db: Session, alert: Alert) -> Incident:
    m = meta(alert.name)
    now = ctx.clock.now()
    impact = _impact_for(ctx, db, alert)
    dev = db.get(Device, alert.target)
    svc = db.get(Service, alert.service_id) if alert.service_id else None
    criticality = (svc.criticality if svc else (dev.criticality if dev else "LOW"))
    recent_change = bool(db.scalar(select(func.count()).select_from(Event).where(Event.type.in_(("CONFIG_CHANGED", "FIREWALL_CHANGE")),
                                                                               Event.target == alert.target, Event.ts >= now - timedelta(minutes=30))))
    risk = score_of(db, "device", alert.target)
    t = triage(severity=alert.severity, criticality=criticality, users=impact["counts"]["users"], services=impact["counts"]["services"],
               risk=risk, recent_change=recent_change)
    t["alert"] = alert.name
    title = m["title"].format(target=alert.target, **{k: v for k, v in alert.labels.items() if isinstance(v, str)})
    if alert.name == "HighRiskDevice" and alert.labels.get("admin_activity"):
        title = "Identityless device attempted administrative access"
    inc = Incident(id=new_id(db, "incident"), title=title, category=m["category"], severity=t["severity"], priority=t["priority"], status="OPEN",
                   risk=risk, evidence=[], affected_users=impact["users"], affected_devices=impact["devices"], affected_services=impact["services"],
                   impact=impact, triage=t, recommendations=[], recurring={}, fingerprint=alert.fingerprint, target=alert.target,
                   detection_source=alert.source, human_required=False, summary=alert.summary, correlation_id=alert.correlation_id,
                   created_at=now, updated_at=now)
    db.add(inc)
    db.flush()
    alert.incident_id = inc.id
    db.add(IncidentEvent(incident_id=inc.id, ts=alert.first_seen, stage="EVENT", message=f"{alert.name} from {alert.source}: {alert.summary}",
                         data={"alert": alert.id}))
    db.add(IncidentEvent(incident_id=inc.id, ts=now, stage="OBSERVATION", message=f"Validated against current state: {alert.validation_note}",
                         data={"alert": alert.id}))
    ctx.bus.emit(db, "INCIDENT_CREATED", f"{inc.id} {inc.priority} {inc.title}", severity="critical" if inc.priority == "P1" else "high",
                 source="incident-engine", target=inc.target, data={"incident": inc.id, "priority": inc.priority, "impact": impact["counts"]},
                 correlation_id=inc.correlation_id)
    record_audit(ctx, db, actor="NEXUS", actor_type="SYSTEM", action="opened incident", reason=alert.summary, target=inc.target,
                 result=inc.priority, correlation_id=inc.correlation_id, incident_id=inc.id)
    detect_recurring(ctx, db, inc, alert)
    apply_rca(ctx, db, inc)
    maybe_plan(ctx, db, inc)
    return inc


def attach(ctx: Context, db: Session, inc: Incident, alert: Alert) -> None:
    alert.incident_id = inc.id
    alert.correlation_id = inc.correlation_id
    now = ctx.clock.now()
    extra = _impact_for(ctx, db, alert)
    inc.affected_services = sorted(set(inc.affected_services or []) | set(extra["services"]))
    inc.affected_devices = sorted(set(inc.affected_devices or []) | set(extra["devices"]))
    inc.affected_users = sorted(set(inc.affected_users or []) | set(extra["users"]))
    counts = {"devices": len(inc.affected_devices), "services": len(inc.affected_services), "users": len(inc.affected_users),
              "leases": len(set((inc.impact or {}).get("leases", [])) | set(extra["leases"])), "policies": 0}
    inc.impact = {**(inc.impact or {}), "counts": counts, "users": inc.affected_users, "services": inc.affected_services, "devices": inc.affected_devices}
    inc.updated_at = now
    db.add(IncidentEvent(incident_id=inc.id, ts=now, stage="CORRELATION", message=f"Correlated {alert.name} on {alert.target} as a symptom of {inc.id}",
                         data={"alert": alert.id}))
    ctx.bus.emit(db, "SYMPTOM_CORRELATED", f"{alert.id} {alert.name} correlated into {inc.id} (one incident, many symptoms)", source="incident-engine",
                 target=alert.target, data={"incident": inc.id, "alert": alert.id}, correlation_id=inc.correlation_id)
    if alert.name == "HighRiskDevice":
        inc.title = "Identityless device attempted administrative access" if alert.labels.get("admin_activity") else meta("HighRiskDevice")["title"].format(target=inc.target)
        t = dict(inc.triage or {})
        t["alert"] = "HighRiskDevice"
        inc.triage = t
    apply_rca(ctx, db, inc)
    maybe_plan(ctx, db, inc)


def apply_rca(ctx: Context, db: Session, inc: Incident) -> None:
    result = rca.analyze(ctx, db, inc)
    changed = result["entity"] != inc.root_cause_entity or result["confidence"] != inc.root_cause_confidence
    inc.root_cause = result["root_cause"]
    inc.root_cause_entity = result["entity"]
    inc.root_cause_kind = result["kind"]
    inc.root_cause_confidence = result["confidence"]
    inc.evidence = result["evidence"]
    t = dict(inc.triage or {})
    t["rca_candidates"] = result["candidates"]
    t["rca_score"] = result["score"]
    inc.triage = t
    # Retitle after the root cause, re-triage with the widest impact seen so far.
    root_alert = db.scalar(select(Alert).where(Alert.incident_id == inc.id, Alert.service_id == result["entity"]))
    symptoms = db.scalar(select(func.count()).select_from(Alert).where(Alert.incident_id == inc.id)) or 1
    if root_alert is not None:
        inc.title = meta(root_alert.name)["title"].format(target=root_alert.target) + (f" ({symptoms} correlated symptoms)" if symptoms > 1 else "")
        t["alert"] = root_alert.name
        inc.triage = t
        svc = db.get(Service, result["entity"])
        if svc:
            tr = triage(severity=root_alert.severity, criticality=svc.criticality, users=len(inc.affected_users or []),
                        services=len(inc.affected_services or []), risk=inc.risk, recent_change=result["kind"] == "config_change")
            if tr["priority"] < inc.priority:
                inc.priority, inc.severity = tr["priority"], tr["severity"]
    if changed:
        db.add(IncidentEvent(incident_id=inc.id, ts=ctx.clock.now(), stage="ROOT_CAUSE",
                             message=f"Root cause ({result['confidence']}): {result['root_cause']}", data={"evidence": result["evidence"]}))
        ctx.bus.emit(db, "ROOT_CAUSE_IDENTIFIED", f"{inc.id} root cause ({result['confidence']}): {result['root_cause']}", source="rca-engine",
                     target=inc.target, data={"incident": inc.id, "entity": result["entity"], "confidence": result["confidence"]},
                     correlation_id=inc.correlation_id)


def detect_recurring(ctx: Context, db: Session, inc: Incident, alert: Alert) -> None:
    since = ctx.clock.now() - timedelta(days=7)
    same = db.scalars(select(Incident).where(Incident.fingerprint == inc.fingerprint, Incident.created_at >= since).order_by(Incident.created_at)).all()
    if len(same) >= 3:
        inc.recurring = {"occurrences": len(same), "period_days": 7, "first_seen": same[0].created_at.isoformat(),
                         "incidents": [x.id for x in same],
                         "recommended_investigation": ["application configuration", "resource utilisation", "dependency failure"],
                         "note": "Recurrence is a pattern, not a root cause. NEXUS does not claim a root cause for the recurrence without evidence."}
        recs = list(inc.recommendations or [])
        recs.append(f"Recurring failure: {len(same)} occurrences in 7 days - investigate configuration, resources and dependencies")
        inc.recommendations = recs
        ctx.bus.emit(db, "RECURRING_FAILURE", f"{alert.name} on {alert.target} recurred {len(same)} times in 7 days", severity="warning",
                     source="incident-engine", target=alert.target, data={"incident": inc.id, "occurrences": len(same)}, correlation_id=inc.correlation_id)


# ------------------------------------------------------------------------------ planning
SERVICE_ACTIONS = {"nginx": "REM-SVC-RESTART-NGINX", "ssh": "REM-SVC-RESTART-SSH", "dns": "REM-SVC-RESTART-DNS", "ntp": "REM-SVC-RESTART-NTP",
                   "monitoring-agent": "REM-SVC-RESTART-MONAGENT", "docker": "REM-SVC-RESTART-DOCKER"}
CONFIG_ACTIONS = {"nginx": "REM-CFG-RESTORE-NGINX", "ssh": "REM-CFG-RESTORE-SSH", "docker": "REM-CFG-RESTORE-DOCKER", "monitoring": "REM-CFG-RESTORE-MONITORING"}


def plan_for(ctx: Context, db: Session, inc: Incident) -> tuple[str, str, dict[str, Any], dict[str, Any] | None] | None:
    entity, kind = inc.root_cause_entity or inc.target, inc.root_cause_kind
    primary = (inc.triage or {}).get("alert", "")
    if meta(primary).get("planned_by") == "drift":
        return None
    if kind == "config_change" and ":" in entity:
        device, component = entity.split(":", 1)
        if component in CONFIG_ACTIONS:
            return CONFIG_ACTIONS[component], device, {"component": component}, None
    if kind == "service_down" and "@" in entity:
        name, device = entity.split("@", 1)
        svc = db.get(Service, entity)
        if name == "docker" and svc and not svc.enabled:
            return "REM-SVC-ENABLE", device, {"service": "docker"}, None
        if name in SERVICE_ACTIONS:
            return SERVICE_ACTIONS[name], device, {}, None
        return "REM-HUMAN-INVESTIGATE", device, {}, None
    alert = db.scalar(select(Alert).where(Alert.incident_id == inc.id, Alert.name == primary).order_by(Alert.first_seen.desc())) \
        or db.scalar(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen))
    labels = alert.labels if alert else {}
    if primary == "DiskSpaceCritical":
        return "REM-DISK-ROTATE-LOGS", inc.target, {"logset": "portal" if inc.target == "APP01" else "nginx"}, None
    if primary == "HighCPU":
        return ("REM-DOCKER-RESTART-PORTAL" if inc.target == "APP01" else "REM-HUMAN-INVESTIGATE"), inc.target, {}, None
    if primary == "DHCPPoolExhausted":
        return "REM-NET-DHCP-RECLAIM", "PFSENSE", {"vlan": int(labels.get("vlan", 30))}, None
    if primary == "UnexpectedService":
        return "REM-NET-BLOCK-PORT", inc.target, {"port": int(labels.get("port", 0))}, None
    if primary == "HighRiskDevice":
        dev = db.get(Device, inc.target)
        pol = next((p for p in ctx.policy_cache.security if p.metadata.id == labels.get("policy")), None) if ctx.policy_cache else None
        if pol is None or dev is None:
            return None
        q = pol.spec.quarantine
        from nexus.core.store import get_setting

        autonomy = int(get_setting(db, "autonomy_level") or 0)
        auto = (not dev.managed) or autonomy >= q.managed_requires_level
        return "REM-NET-QUARANTINE", dev.id, {"vlan": q.target_vlan}, {"policy": pol.metadata.id, "auto_permitted": auto, "min_autonomy": q.automatic_min_autonomy}
    if primary in ("CertificateExpiring", "CertificateExpired"):
        return "REM-CERT-RENEW", inc.target, {}, None
    if primary in ("NodeDown", "RepeatedAuthFailures", "PolicyConflict", "ADAuthenticationFailures", "DHCPConflict", "FirewallUnreachable"):
        return "REM-HUMAN-INVESTIGATE", inc.target, {}, None
    return None


def maybe_plan(ctx: Context, db: Session, inc: Incident) -> dict[str, Any] | None:
    if inc.status not in ("OPEN", "INVESTIGATING"):
        return None
    planned = plan_for(ctx, db, inc)
    if planned is None:
        return None
    action_id, target, params, override = planned
    key = f"{action_id}:{target}"
    t = dict(inc.triage or {})
    if t.get("planned_for") == key:
        return None
    active = db.scalar(select(RemediationTransaction).where(RemediationTransaction.incident_id == inc.id,
                                                            RemediationTransaction.status.in_(("PLANNED", "RUNNING", "AWAITING_APPROVAL"))))
    if active:
        return None
    t["planned_for"] = key
    inc.triage = t
    from nexus.core.decision import plan_action

    evidence = list(inc.evidence or [])[:6]
    result = plan_action(ctx, db, action_id=action_id, target=target, params=params, trigger=f"{(inc.triage or {}).get('alert', inc.title)} ({inc.id})",
                         evidence=evidence, incident_id=inc.id, correlation_id=inc.correlation_id, policy_override=override,
                         root_cause_confidence=inc.root_cause_confidence)
    return result


def open_finding(ctx: Context, db: Session, *, name: str, target: str, summary: str, labels: dict[str, Any] | None = None) -> Alert | None:
    return ingest_alert(ctx, db, AlertIn(name=name, target=target, source="nexus-analytics", summary=summary, labels=labels or {}))


# ----------------------------------------------------------------------------- lifecycle
def resolve_cleared(ctx: Context, db: Session, source: str, firing: set[str]) -> list[str]:
    now = ctx.clock.now()
    cleared = []
    for alert in db.scalars(select(Alert).where(Alert.status == "FIRING", Alert.source == source)).all():
        if alert.fingerprint in firing:
            continue
        alert.status = "RESOLVED"
        alert.resolved_at = now
        cleared.append(alert.id)
        ctx.bus.emit(db, "ALERT_RESOLVED", f"{alert.id} {alert.name} {alert.target} cleared", source=source, target=alert.target,
                     data={"alert": alert.id}, correlation_id=alert.correlation_id)
        if alert.incident_id and (inc := db.get(Incident, alert.incident_id)) and inc.status in OPEN:
            still = db.scalar(select(func.count()).select_from(Alert).where(Alert.incident_id == inc.id, Alert.status == "FIRING")) or 0
            if still == 0:
                busy = db.scalar(select(RemediationTransaction).where(RemediationTransaction.incident_id == inc.id,
                                                                      RemediationTransaction.status.in_(("PLANNED", "RUNNING"))))
                if busy is None:
                    resolve_incident(ctx, db, inc.id, "all symptoms cleared and verified", actor="NEXUS")
    return cleared


def resolve_incident(ctx: Context, db: Session, incident_id: str, reason: str, actor: str = "NEXUS", status: str = "RESOLVED") -> Incident | None:
    inc = db.get(Incident, incident_id)
    if inc is None or inc.status in ("RESOLVED", "FALSE_POSITIVE"):
        return inc
    now = ctx.clock.now()
    inc.status = status
    inc.resolved_at = now
    inc.updated_at = now
    if inc.mitigated_at is None:
        inc.mitigated_at = now
    for alert in db.scalars(select(Alert).where(Alert.incident_id == inc.id, Alert.status == "FIRING", Alert.source == "nexus-analytics")):
        alert.status, alert.resolved_at = "RESOLVED", now
    cancel_pending(ctx, db, incident_id=inc.id, reason=f"{inc.id} {status.lower()}: {reason}")
    db.add(IncidentEvent(incident_id=inc.id, ts=now, stage="RESOLUTION", message=f"{status.replace('_', ' ').title()}: {reason}"))
    ctx.bus.emit(db, "INCIDENT_RESOLVED", f"{inc.id} {status.lower()}: {reason}", source="incident-engine", target=inc.target,
                 data={"incident": inc.id, "status": status, "mttr_seconds": int((now - inc.created_at).total_seconds())},
                 correlation_id=inc.correlation_id)
    record_audit(ctx, db, actor=actor, actor_type="AUTOHEAL" if actor in ("AUTOHEAL", "NEXUS") else "OPERATOR", action=f"{status.lower()} incident",
                 reason=reason, target=inc.target, result=status, correlation_id=inc.correlation_id, incident_id=inc.id)
    dev = db.get(Device, inc.target)
    if dev:
        from nexus.risk.engine import recompute_device

        recompute_device(ctx, db, dev, f"{inc.id} {status.lower()}", inc.correlation_id, evaluate_policy=False)
    ctx.runtime.snapshot_dirty = True
    return inc


def acknowledge(ctx: Context, db: Session, incident_id: str, actor: str) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise KeyError(incident_id)
    if inc.status == "OPEN":
        inc.status = "INVESTIGATING"
    inc.updated_at = ctx.clock.now()
    db.add(IncidentEvent(incident_id=inc.id, ts=ctx.clock.now(), stage="NOTE", message=f"Acknowledged by {actor}"))
    record_audit(ctx, db, actor=actor, actor_type="OPERATOR", action="acknowledged incident", reason="operator acknowledgement", target=inc.target,
                 result="SUCCESS", correlation_id=inc.correlation_id, incident_id=inc.id)
    ctx.bus.emit(db, "INCIDENT_UPDATED", f"{inc.id} acknowledged by {actor}", source="incident-engine", target=inc.target,
                 data={"incident": inc.id}, correlation_id=inc.correlation_id)
    return inc


def alert_dict(a: Alert) -> dict[str, Any]:
    return {"id": a.id, "name": a.name, "source": a.source, "severity": a.severity, "target": a.target, "service_id": a.service_id,
            "fingerprint": a.fingerprint, "labels": a.labels, "summary": a.summary, "status": a.status, "validated": a.validated,
            "validation_note": a.validation_note, "count": a.count, "incident_id": a.incident_id, "correlation_id": a.correlation_id,
            "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(), "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None}


def incident_dict(i: Incident, brief: bool = False) -> dict[str, Any]:
    d = {"id": i.id, "title": i.title, "category": i.category, "severity": i.severity, "priority": i.priority, "status": i.status, "risk": i.risk,
         "root_cause": i.root_cause, "root_cause_entity": i.root_cause_entity, "root_cause_kind": i.root_cause_kind,
         "root_cause_confidence": i.root_cause_confidence, "target": i.target, "detection_source": i.detection_source,
         "human_required": i.human_required, "correlation_id": i.correlation_id, "created_at": i.created_at.isoformat(),
         "updated_at": i.updated_at.isoformat(), "mitigated_at": i.mitigated_at.isoformat() if i.mitigated_at else None,
         "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
         "mttr_seconds": int((i.resolved_at - i.created_at).total_seconds()) if i.resolved_at else None,
         "counts": (i.impact or {}).get("counts", {}), "recurring": i.recurring or {}}
    if not brief:
        d.update({"evidence": i.evidence, "affected_users": i.affected_users, "affected_devices": i.affected_devices,
                  "affected_services": i.affected_services, "impact": i.impact, "triage": i.triage, "recommendations": i.recommendations,
                  "summary": i.summary})
    return d


def decisions_for(db: Session, incident_id: str) -> list[Decision]:
    return list(db.scalars(select(Decision).where(Decision.incident_id == incident_id).order_by(Decision.ts)))


def cancel_pending(ctx: Context, db: Session, *, incident_id: str | None = None, transaction_id: str | None = None, reason: str) -> list[str]:
    """Expire approvals whose condition cleared, so nobody approves a fix for a problem that is gone."""
    from nexus.models import Approval

    q = select(RemediationTransaction).where(RemediationTransaction.status == "AWAITING_APPROVAL")
    q = q.where(RemediationTransaction.incident_id == incident_id) if incident_id else q.where(RemediationTransaction.id == transaction_id)
    cancelled = []
    for tx in db.scalars(q).all():
        tx.status, tx.result, tx.error = "CANCELLED", "NOT_NEEDED", reason[:200]
        if tx.approval_id and (ap := db.get(Approval, tx.approval_id)) and ap.status == "PENDING":
            ap.status, ap.note, ap.decided_at = "EXPIRED", f"condition cleared: {reason}"[:500], ctx.clock.now()
        cancelled.append(tx.id)
    return cancelled

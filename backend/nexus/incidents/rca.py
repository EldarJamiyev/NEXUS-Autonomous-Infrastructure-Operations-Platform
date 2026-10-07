"""Deterministic root-cause analysis (no machine learning).

Evidence used: dependency graph (does a failing upstream explain every symptom?), observed
service state, event timing (earliest failure), recent non-NEXUS configuration changes on the
failing component, and configuration validation run through the allowlisted executor.
Confidence: HIGH >= 70 points, MEDIUM >= 45, LOW otherwise.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.dependencies.graph import ServiceGraph
from nexus.models import Alert, Certificate, Device, Event, Incident, Vlan

if TYPE_CHECKING:
    from nexus.core.context import Context

SERVICE_COMPONENT = {"nginx": "nginx", "ssh": "ssh", "docker": "docker", "monitoring-agent": "monitoring"}


def _confidence(score: int) -> str:
    return "HIGH" if score >= 70 else "MEDIUM" if score >= 45 else "LOW"


def analyze(ctx: Context, db: Session, inc: Incident) -> dict[str, Any]:
    alerts = db.scalars(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen)).all()
    graph = ServiceGraph(db)
    symptoms = [a.service_id for a in alerts if a.service_id and a.service_id in graph.services]
    if not symptoms:
        return generic(ctx, db, inc, list(alerts))
    first_ts = min(a.first_seen for a in alerts)
    candidates = set(symptoms)
    for s in symptoms:
        candidates |= {u for u in graph.upstream(s) if graph.services[u].status != "running"}
    scored = []
    for c in sorted(candidates):
        svc = graph.services[c]
        score, ev = 0, []
        if svc.status != "running":
            score += 40
            ev.append(f"{c} observed {svc.status}" + (f" ({svc.health_detail})" if svc.health_detail else ""))
        explains = [s for s in symptoms if s == c or c in graph.upstream(s)]
        if len(symptoms) > 1 and len(explains) == len(symptoms):
            score += 30
            ev.append(f"explains all {len(symptoms)} symptoms through the dependency graph ({', '.join(symptoms)})")
        elif explains:
            score += 20 if len(symptoms) == 1 else 10
        failing_up = [u for u in graph.upstream(c) if graph.services[u].status != "running"]
        if failing_up:
            score -= 25
            ev.append(f"its own dependencies are failing: {', '.join(failing_up)}")
        change = None
        component = SERVICE_COMPONENT.get(svc.name)
        if component:
            window_start = first_ts - timedelta(minutes=15)
            for e in db.scalars(select(Event).where(Event.type == "CONFIG_CHANGED", Event.target == svc.device_id, Event.ts >= window_start,
                                                    Event.ts <= first_ts + timedelta(seconds=30)).order_by(Event.ts.desc())):
                if (e.data or {}).get("component") == component and not (e.data or {}).get("by_nexus"):
                    change = e
                    break
        validation_failed = False
        if change:
            secs = max(0, int((first_ts - change.ts).total_seconds()))
            score += 20
            ev.append(f"{component} configuration changed by {change.data.get('actor')} {secs} s before the first symptom")
            if component in ("nginx", "ssh"):
                probe = ctx.probes.p_config_valid(db, svc.device_id, {"component": component}, None)
                validation_failed = not probe["passed"]
                score += 10 if validation_failed else 5
                ev.append(("validation failed: " if validation_failed else "syntax valid but differs from baseline: ") + probe["detail"])
        earliest = next((a for a in alerts if a.service_id == c), None)
        if earliest is not None and earliest.first_seen == first_ts:
            score += 10
            ev.append(f"earliest observed symptom ({earliest.first_seen.astimezone(ctx.clock.site_tz).strftime('%H:%M:%S')})")
        scored.append((score, c, ev, change, validation_failed))
    score, c, ev, change, validation_failed = max(scored, key=lambda x: x[0])
    svc = graph.services[c]
    if change is not None:
        component = SERVICE_COMPONENT[svc.name]
        return {"root_cause": f"{component.title()} configuration change on {svc.device_id}" + (" (validation failed)" if validation_failed else ""),
                "entity": f"{svc.device_id}:{component}", "kind": "config_change", "confidence": _confidence(score), "score": score,
                "evidence": ev, "candidates": [{"entity": x[1], "score": x[0]} for x in sorted(scored, reverse=True)]}
    return {"root_cause": f"{svc.display_name} on {svc.device_id} {svc.status}", "entity": c, "kind": "service_down",
            "confidence": _confidence(score), "score": score, "evidence": ev,
            "candidates": [{"entity": x[1], "score": x[0]} for x in sorted(scored, reverse=True)]}


def generic(ctx: Context, db: Session, inc: Incident, alerts: list[Alert]) -> dict[str, Any]:
    a = alerts[0] if alerts else None
    name = a.name if a else ""
    dev = db.get(Device, inc.target)
    labels = a.labels if a else {}
    ev: list[str] = [f"{x.name}: {x.summary}" for x in alerts[:5]]
    kind, cause, conf, entity = "condition", inc.title, "MEDIUM", inc.target
    if name == "DiskSpaceCritical" and dev:
        out = ctx.executor.diagnose(db, dev, "disk") if hasattr(ctx.executor, "diagnose") else ""
        ev.append(f"du -xh --max-depth=2: {out}")
        kind, cause, conf = "resource", f"Filesystem growth on {dev.id}: {out.split(' ')[1] if ' ' in out else 'unknown path'}", "HIGH" if out else "MEDIUM"
    elif name == "HighCPU" and dev:
        out = ctx.executor.diagnose(db, dev, "cpu") if hasattr(ctx.executor, "diagnose") else ""
        ev.append(f"top -bn1: {out}")
        kind, cause, conf = "resource", f"Runaway process on {dev.id}: {out}", "MEDIUM"
    elif name == "NodeDown":
        kind, cause, conf = "unreachable", f"{inc.target} does not answer ARP/ICMP; remote remediation impossible (needs console or power cycle)", "LOW"
    elif name.startswith("Certificate"):
        cert = db.get(Certificate, labels.get("certificate", ""))
        kind, cause, conf = "certificate", f"Certificate {labels.get('certificate')} expires {cert.not_after:%Y-%m-%d %H:%M} UTC" if cert else inc.title, "HIGH"
    elif name == "DHCPPoolExhausted":
        vlan = db.get(Vlan, int(labels.get("vlan", 30)))
        kind, cause, conf = "capacity", f"VLAN {vlan.id if vlan else '?'} pool {vlan.dhcp_in_use if vlan else '?'}/{vlan.dhcp_pool_size if vlan else '?'} with {vlan.dhcp_stale if vlan else '?'} stale leases", "HIGH"
    elif name == "UnexpectedService" and dev:
        out = ctx.executor.diagnose(db, dev, "ports") if hasattr(ctx.executor, "diagnose") else ""
        ev.append(f"ss -tlnp: {out}")
        kind, cause, conf = "security", f"Unapproved listener on {dev.id} TCP/{labels.get('port')} ({out})", "HIGH"
    elif name in ("HighRiskDevice", "UnknownDevice", "DHCPConflict") and dev:
        missing = [s["label"] for s in (dev.identity_signals or {}).get("signals", []) if s.get("status") is False]
        ev.append(f"identity {dev.identity_confidence}% ({dev.identity_level}); missing: {', '.join(missing) or 'none'}")
        kind, cause, conf, entity = "identity", f"{dev.id} has no establishable identity ({dev.identity_confidence}%)", "HIGH", dev.id
    elif name in ("ConfigurationDrift", "UnexpectedFirewallRule", "UnexpectedDriftAfterMaintenance"):
        kind, cause, conf = "drift", f"{inc.target} differs from Git intent - {a.summary if a else ''}", "HIGH"
        actor = db.scalar(select(Event).where(Event.type.in_(("CONFIG_CHANGED", "FIREWALL_CHANGE")), Event.target == inc.target).order_by(Event.ts.desc()))
        if actor:
            ev.append(f"last change: {actor.message}")
    elif name == "RepeatedAuthFailures":
        kind, cause, conf = "identity", f"Repeated failed logons from {inc.target} for {labels.get('user')} (password guessing or stale credentials)", "MEDIUM"
    elif name == "PolicyConflict":
        kind, cause, conf = "policy", a.summary if a else inc.title, "HIGH"
    return {"root_cause": cause[:250], "entity": entity, "kind": kind, "confidence": conf, "score": None, "evidence": ev, "candidates": []}

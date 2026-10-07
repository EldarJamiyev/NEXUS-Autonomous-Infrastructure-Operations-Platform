"""Incidents, alerts (incl. Alertmanager webhook), remediation, approvals, drift, risk, events, audit,
ChatOps, reports, daily operations, troubleshooting and runbooks."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from nexus.api.deps import Principal, current_principal, get_ctx, limited, require
from nexus.api.serializers import risk_of
from nexus.core.audit import record_audit
from nexus.core.context import Context
from nexus.events.types import phase_for
from nexus.models import (
    Alert,
    Approval,
    AuditEvent,
    ChatOpsEvent,
    Decision,
    Device,
    DriftEvent,
    Event,
    Incident,
    IncidentEvent,
    RemediationTransaction,
    Report,
    RiskEvent,
    RiskScore,
    User,
)

router = APIRouter(prefix="/api", tags=["operations"])


class NoteIn(BaseModel):
    note: str = Field("", max_length=500)


# ------------------------------------------------------------------------------ incidents
@router.get("/incidents")
async def incidents(status: str | None = None, priority: str | None = None, limit: int = 200, ctx: Context = Depends(get_ctx),
                    _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.incidents.engine import incident_dict

    with ctx.session() as db:
        q = select(Incident).order_by(Incident.created_at.desc()).limit(min(limit, 500))
        if status:
            q = q.where(Incident.status.in_(status.upper().split(",")))
        if priority:
            q = q.where(Incident.priority.in_(priority.upper().split(",")))
        return [incident_dict(i, brief=True) for i in db.scalars(q)]


@router.get("/incidents/{incident_id}")
async def incident(incident_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.drift.engine import drift_dict
    from nexus.incidents.engine import alert_dict, incident_dict
    from nexus.remediation.runner import tx_dict

    with ctx.session() as db:
        inc = db.get(Incident, incident_id.upper())
        if inc is None:
            raise KeyError(f"incident {incident_id} not found")
        alerts = db.scalars(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen)).all()
        corr = {inc.correlation_id} | {a.correlation_id for a in alerts if a.correlation_id}
        txs = db.scalars(select(RemediationTransaction).where(RemediationTransaction.incident_id == inc.id).order_by(RemediationTransaction.created_at)).all()
        corr |= {t.correlation_id for t in txs if t.correlation_id}
        events = db.scalars(select(Event).where(or_(Event.correlation_id.in_(corr), Event.target == inc.target), Event.ts >= inc.created_at - timedelta(minutes=2),
                                                Event.type != "AUTH_FAILURE").order_by(Event.ts).limit(300)).all()
        return {**incident_dict(inc), "timeline": [{"ts": e.ts.isoformat(), "stage": e.stage, "message": e.message, "data": e.data}
                                                   for e in db.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == inc.id).order_by(IncidentEvent.ts, IncidentEvent.id))],
                "alerts": [alert_dict(a) for a in alerts], "transactions": [tx_dict(t) for t in txs],
                "decisions": [decision_dict(d) for d in db.scalars(select(Decision).where(Decision.incident_id == inc.id).order_by(Decision.ts))],
                "drift": [drift_dict(d) for d in db.scalars(select(DriftEvent).where(DriftEvent.incident_id == inc.id))],
                "events": [{"id": e.id, "ts": e.ts.isoformat(), "type": e.type, "severity": e.severity, "source": e.source, "target": e.target, "user_id": e.user_id,
                            "message": e.message, "correlation_id": e.correlation_id, "phase": phase_for(e.type)} for e in events],
                "chatops": [chat_dict(m) for m in db.scalars(select(ChatOpsEvent).where(ChatOpsEvent.correlation_id.in_(corr)).order_by(ChatOpsEvent.ts))],
                "risk_history": [{"ts": r.ts.isoformat(), "entity": r.entity_id, "old": r.old_score, "new": r.new_score, "reason": r.reason}
                                 for r in db.scalars(select(RiskEvent).where(RiskEvent.entity_id == inc.target, RiskEvent.ts >= inc.created_at).order_by(RiskEvent.ts).limit(20))]}


@router.get("/incidents/{incident_id}/report")
async def incident_report(incident_id: str, format: str = "md", ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)):  # noqa: A002, ANN201
    from nexus.incidents.reports import incident_markdown, markdown_to_html

    with ctx.session() as db:
        inc = db.get(Incident, incident_id.upper())
        if inc is None:
            raise KeyError(f"incident {incident_id} not found")
        md = incident_markdown(ctx, db, inc)
    if format == "html":
        return HTMLResponse(markdown_to_html(md, f"{incident_id} report"))
    return PlainTextResponse(md, media_type="text/markdown")


class ResolveIn(BaseModel):
    reason: str = Field("resolved by operator", max_length=300)


@router.post("/incidents/{incident_id}/acknowledge")
async def ack(incident_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.incidents.engine import acknowledge, incident_dict

    with ctx.session() as db:
        return incident_dict(acknowledge(ctx, db, incident_id.upper(), p.user_id), brief=True)


@router.post("/incidents/{incident_id}/resolve")
async def resolve(incident_id: str, body: ResolveIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.incidents.engine import incident_dict, resolve_incident

    with ctx.session() as db:
        inc = resolve_incident(ctx, db, incident_id.upper(), body.reason, actor=p.user_id)
        if inc is None:
            raise KeyError(incident_id)
        return incident_dict(inc, brief=True)


@router.post("/incidents/{incident_id}/false-positive")
async def false_positive(incident_id: str, body: ResolveIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.incidents.engine import incident_dict, resolve_incident

    with ctx.session() as db:
        inc = resolve_incident(ctx, db, incident_id.upper(), body.reason or "marked false positive", actor=p.user_id, status="FALSE_POSITIVE")
        if inc is None:
            raise KeyError(incident_id)
        return incident_dict(inc, brief=True)


@router.post("/incidents/{incident_id}/remediate", dependencies=[Depends(limited("sensitive"))])
async def retry(incident_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.decision import plan_action
    from nexus.incidents.engine import plan_for

    with ctx.session() as db:
        inc = db.get(Incident, incident_id.upper())
        if inc is None:
            raise KeyError(incident_id)
        planned = plan_for(ctx, db, inc)
        if planned is None:
            raise ValueError("no automated remediation applies to this incident")
        action_id, target, params, override = planned
        return plan_action(ctx, db, action_id=action_id, target=target, params=params, trigger=f"operator retry ({inc.id})", evidence=inc.evidence,
                           incident_id=inc.id, correlation_id=inc.correlation_id, requested_by=p.user_id, policy_override=override)


# --------------------------------------------------------------------------------- alerts
@router.get("/alerts")
async def alerts(status: str | None = None, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.incidents.engine import alert_dict

    with ctx.session() as db:
        q = select(Alert).order_by(Alert.first_seen.desc()).limit(300)
        if status:
            q = q.where(Alert.status == status.upper())
        return [alert_dict(a) for a in db.scalars(q)]


@router.get("/alerts/{alert_id}")
async def alert(alert_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.incidents.engine import alert_dict

    with ctx.session() as db:
        a = db.get(Alert, alert_id.upper())
        if a is None:
            raise KeyError(alert_id)
        related = db.scalars(select(Event).where(Event.correlation_id == a.correlation_id).order_by(Event.ts).limit(100)).all()
        tx = db.scalar(select(RemediationTransaction).where(RemediationTransaction.incident_id == a.incident_id)) if a.incident_id else None
        return {**alert_dict(a), "risk": risk_of(db, "device", a.target)["score"], "related_events": [{"ts": e.ts.isoformat(), "type": e.type, "message": e.message} for e in related],
                "remediation": {"id": tx.id, "status": tx.status, "verification": tx.verification} if tx else None}


@router.post("/alerts/alertmanager", dependencies=[Depends(limited("webhook"))], tags=["integrations"])
async def alertmanager(request: Request, ctx: Context = Depends(get_ctx)) -> dict[str, Any]:
    """Prometheus Alertmanager webhook (v4). Alerts are signals: NEXUS validates them against current state and never executes alert content."""
    from nexus.incidents.engine import AlertIn, fingerprint, ingest_alert

    if ctx.settings.alertmanager_token:
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {ctx.settings.alertmanager_token}":
            raise HTTPException(status_code=401, detail="invalid webhook token")
    payload = await request.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise ValueError("not an Alertmanager webhook payload")
    accepted, resolved = [], []
    with ctx.session() as db:
        for raw in payload["alerts"][:100]:
            labels = {str(k): str(v)[:128] for k, v in (raw.get("labels") or {}).items()}
            if labels.get("source") == "nexus-self":
                continue  # rules over NEXUS's own findings exist for human routing; NEXUS already tracks them
            name = labels.get("alertname", "")[:64]
            target = (labels.get("device") or labels.get("instance", "")).split(":")[0].upper()[:64]
            if not name or not target:
                continue
            svc = labels.get("service")
            service_id = f"{svc}@{target}" if svc else None
            fp = fingerprint(name, target, service_id, labels)
            if raw.get("status") == "resolved":
                for a in db.scalars(select(Alert).where(Alert.fingerprint == fp, Alert.status == "FIRING", Alert.source == "alertmanager")):
                    a.status, a.resolved_at = "RESOLVED", ctx.clock.now()
                    resolved.append(a.id)
                continue
            sev = {"critical": "critical", "warning": "warning", "page": "critical"}.get(labels.get("severity", "warning"), "warning")
            alert_row = ingest_alert(ctx, db, AlertIn(name=name, target=target, source="alertmanager", severity=sev, service_id=service_id,
                                                      summary=str((raw.get("annotations") or {}).get("summary", ""))[:200], labels=labels))
            if alert_row:
                accepted.append({"alert": alert_row.id, "status": alert_row.status, "validated": alert_row.validated, "incident": alert_row.incident_id})
    return {"accepted": accepted, "resolved": resolved}


# ---------------------------------------------------------------------------- remediation
def decision_dict(d: Decision) -> dict[str, Any]:
    return {"id": d.id, "ts": d.ts.isoformat(), "trigger": d.trigger, "target": d.target, "action_id": d.action_id, "outcome": d.outcome, "category": d.category,
            "risk": d.risk, "confidence": d.confidence, "evidence": d.evidence, "policy": d.policy, "impact": d.impact, "safety": d.safety,
            "confidence_breakdown": d.confidence_breakdown, "reasons": d.reasons, "transaction_id": d.transaction_id, "incident_id": d.incident_id,
            "correlation_id": d.correlation_id, "result": d.result}


@router.get("/remediations")
async def remediations(status: str | None = None, limit: int = 100, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.remediation.runner import tx_dict

    with ctx.session() as db:
        q = select(RemediationTransaction).order_by(RemediationTransaction.created_at.desc()).limit(min(limit, 500))
        if status:
            q = q.where(RemediationTransaction.status.in_(status.upper().split(",")))
        return [tx_dict(t) for t in db.scalars(q)]


@router.get("/remediations/catalog")
async def catalog(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    return ctx.catalog.as_list()


@router.get("/remediations/scorecard")
async def scorecard(hours: int = 168, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.operations.daily import scorecard as sc

    with ctx.session() as db:
        return sc(ctx, db, hours=hours)


@router.get("/remediations/{tx_id}")
async def remediation(tx_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.remediation.runner import tx_dict

    with ctx.session() as db:
        tx = db.get(RemediationTransaction, tx_id.upper())
        if tx is None:
            raise KeyError(tx_id)
        d = db.get(Decision, tx.decision_id) if tx.decision_id else None
        return {**tx_dict(tx), "decision": decision_dict(d) if d else None, "action": ctx.catalog.get(tx.action_id).model_dump()}


@router.post("/remediations/{tx_id}/rollback", dependencies=[Depends(limited("sensitive"))])
async def manual_rollback(tx_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.store import get_setting, set_setting

    with ctx.session() as db:
        tx = db.get(RemediationTransaction, tx_id.upper())
        if tx is None:
            raise KeyError(tx_id)
        action = ctx.catalog.get(tx.action_id)
        if tx.status != "COMMITTED" or not action.rollback_available or not tx.backup:
            raise ValueError("only committed, reversible transactions with a backup can be rolled back")
        dev = db.get(Device, tx.target)
        if dev is None:
            raise KeyError(f"device {tx.target} no longer exists")
        step = {"op": action.rollback, "component": (tx.backup.get("config") or {}).get("component")}
        res = ctx.executor.run(db, dev, step, tx)
        tx.status, tx.rollback_status = ("ROLLED_BACK", "MANUAL") if res.exit_code == 0 else (tx.status, "FAILED")
        tx.commands = list(tx.commands or []) + [res.as_dict() | {"rollback": True, "requested_by": p.user_id}]
        comp = step["component"] or ("firewall" if action.rollback == "firewall_restore" else "network")
        until = (ctx.clock.now() + timedelta(minutes=15)).isoformat()
        sup = dict(get_setting(db, "drift_suppressions") or {})
        sup[f"{tx.target}:{comp}"] = until
        set_setting(db, "drift_suppressions", sup, ctx.clock.now())
        ctx.bus.emit(db, "ROLLBACK_COMPLETED" if res.exit_code == 0 else "ROLLBACK_FAILED", f"{tx.id} manually rolled back by {p.user_id}: {res.output[:120]}",
                     severity="high", source="console", target=tx.target, user_id=p.user_id, correlation_id=tx.correlation_id)
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action=f"rolled back {tx.action_name}", reason="manual rollback from console",
                     target=tx.target, result="SUCCESS" if res.exit_code == 0 else "FAILED", transaction_id=tx.id, correlation_id=tx.correlation_id,
                     details={"drift_accepted_until": until})
        return {"transaction": tx.id, "status": tx.status, "output": res.output, "drift_accepted_until": until}


# ------------------------------------------------------------------------------ approvals
@router.get("/approvals")
async def approvals(status: str | None = None, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        q = select(Approval).order_by(Approval.requested_at.desc()).limit(200)
        if status:
            q = q.where(Approval.status == status.upper())
        out = []
        for a in db.scalars(q):
            tx = db.get(RemediationTransaction, a.transaction_id) if a.transaction_id else None
            d = db.get(Decision, tx.decision_id) if tx and tx.decision_id else None
            out.append({"id": a.id, "kind": a.kind, "title": a.title, "target": a.target, "action_id": a.action_id, "transaction_id": a.transaction_id,
                        "lease_id": a.lease_id, "category": a.category, "risk": a.risk, "reason": a.reason, "required_role": a.required_role, "status": a.status,
                        "requested_by": a.requested_by, "requested_at": a.requested_at.isoformat(), "decided_by": a.decided_by,
                        "decided_at": a.decided_at.isoformat() if a.decided_at else None, "note": a.note, "correlation_id": a.correlation_id,
                        "confidence": d.confidence if d else None, "safety": d.safety if d else None, "evidence": d.evidence if d else [],
                        "incident_id": tx.incident_id if tx else None})
        return out


@router.post("/approvals/{approval_id}/approve", dependencies=[Depends(limited("sensitive"))])
async def approve(approval_id: str, body: NoteIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.core.decision import approve as do_approve

    with ctx.session() as db:
        a = do_approve(ctx, db, approval_id.upper(), p.user_id, body.note)
        return {"id": a.id, "status": a.status, "decided_by": a.decided_by}


@router.post("/approvals/{approval_id}/reject", dependencies=[Depends(limited("sensitive"))])
async def reject(approval_id: str, body: NoteIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.core.decision import reject as do_reject

    with ctx.session() as db:
        a = do_reject(ctx, db, approval_id.upper(), p.user_id, body.note)
        return {"id": a.id, "status": a.status, "decided_by": a.decided_by}


# ---------------------------------------------------------------------------------- drift
@router.get("/drift")
async def drift(status: str | None = None, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.drift.engine import drift_dict

    with ctx.session() as db:
        q = select(DriftEvent).order_by(DriftEvent.detected_at.desc()).limit(300)
        if status:
            q = q.where(DriftEvent.status.in_(status.upper().split(",")))
        return [drift_dict(d) for d in db.scalars(q)]


@router.post("/drift/scan", dependencies=[Depends(limited("sensitive"))])
async def drift_scan(ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    if ctx.controlplane:
        return ctx.controlplane.reconcile_once(None)
    from nexus.drift.engine import scan

    with ctx.session() as db:
        return scan(ctx, db)


@router.post("/drift/{drift_id}/remediate", dependencies=[Depends(limited("sensitive"))])
async def drift_remediate(drift_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.decision import plan_action

    with ctx.session() as db:
        d = db.get(DriftEvent, drift_id.upper())
        if d is None:
            raise KeyError(drift_id)
        if not d.remediation_action:
            raise ValueError(f"{d.classification} drift on {d.component}.{d.key} has no remediation action (report only)")
        if d.status in ("REMEDIATED", "RESOLVED_EXTERNALLY"):
            raise ValueError(f"{d.id} is already {d.status}")
        params: dict[str, Any] = {"component": d.component, "drift_ids": [d.id]}
        if d.component == "firewall":
            params["rules"] = [d.key.split(":", 1)[1]]
        if d.component == "network":
            params["vlan"] = d.desired
        out = plan_action(ctx, db, action_id=d.remediation_action, target=d.device_id, params=params, trigger=f"operator remediation of {d.id}",
                          evidence=[f"{d.component}.{d.key}: desired {d.desired!r} actual {d.actual!r}"], incident_id=d.incident_id, drift_id=d.id,
                          correlation_id=d.correlation_id, requested_by=p.user_id)
        if out["outcome"] in ("AUTOMATE", "APPROVAL_REQUIRED"):
            d.status = "REMEDIATING" if out["outcome"] == "AUTOMATE" else "APPROVAL_REQUIRED"
            d.transaction_id = out.get("transaction_id")
        return out


@router.post("/drift/{drift_id}/accept")
async def drift_accept(drift_id: str, body: NoteIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    with ctx.session() as db:
        d = db.get(DriftEvent, drift_id.upper())
        if d is None:
            raise KeyError(drift_id)
        d.status = "ACCEPTED"
        d.resolved_at = ctx.clock.now()
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action=f"accepted drift {d.id}", reason=body.note or "accepted as intended change (update Git)",
                     target=d.device_id, result="SUCCESS", correlation_id=d.correlation_id)
        return {"id": d.id, "status": d.status}


# ----------------------------------------------------------------------------------- risk
@router.get("/risk")
async def risk(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.risk.engine import global_risk, rules

    with ctx.session() as db:
        rows = db.scalars(select(RiskScore).order_by(RiskScore.score.desc())).all()
        devices = {d.id: d for d in db.scalars(select(Device))}
        users = {u.id: u for u in db.scalars(select(User))}
        out = {"global_risk": global_risk(db), "levels": rules(ctx)["levels"], "trust_rules": rules(ctx)["trust"], "devices": [], "users": [],
               "note": "Deterministic prototype rules (policies/risk-rules.yaml). Scores are explainable sums of factors, not model outputs."}
        for r in rows:
            item = {"id": r.entity_id, "score": r.score, "level": r.level, "trust": r.trust, "factors": r.factors, "updated_at": r.updated_at.isoformat()}
            if r.entity_type == "device" and r.entity_id in devices:
                d = devices[r.entity_id]
                out["devices"].append(item | {"identity": d.identity_confidence, "identity_level": d.identity_level, "kind": d.kind, "quarantined": d.quarantined})
            elif r.entity_type == "user" and r.entity_id in users:
                out["users"].append(item | {"name": users[r.entity_id].display_name})
        return out


@router.get("/risk/{entity_type}/{entity_id}/history")
async def risk_history(entity_type: str, entity_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"ts": r.ts.isoformat(), "old": r.old_score, "new": r.new_score, "reason": r.reason, "trust": r.trust}
                for r in db.scalars(select(RiskEvent).where(RiskEvent.entity_type == entity_type, RiskEvent.entity_id == entity_id).order_by(RiskEvent.ts.desc()).limit(100))]


# -------------------------------------------------------------------------- events/audit
@router.get("/events")
async def events(type: str | None = None, target: str | None = None, severity: str | None = None, correlation_id: str | None = None,  # noqa: A002
                 user: str | None = None, since: datetime | None = None, until: datetime | None = None, limit: int = 200,
                 ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        q = select(Event).order_by(Event.id.desc()).limit(min(limit, 1000))
        if type:
            q = q.where(Event.type.in_(type.upper().split(",")))
        if target:
            q = q.where(Event.target == target.upper())
        if severity:
            q = q.where(Event.severity.in_(severity.lower().split(",")))
        if correlation_id:
            q = q.where(Event.correlation_id == correlation_id.upper())
        if user:
            q = q.where(Event.user_id == user.lower())
        if since:
            q = q.where(Event.ts >= since)
        if until:
            q = q.where(Event.ts <= until)
        return [{"id": e.id, "ts": e.ts.isoformat(), "type": e.type, "severity": e.severity, "source": e.source, "target": e.target, "user_id": e.user_id,
                 "message": e.message, "data": e.data, "correlation_id": e.correlation_id, "phase": phase_for(e.type)} for e in db.scalars(q)]


@router.get("/audit")
async def audit(q: str | None = None, actor: str | None = None, target: str | None = None, result: str | None = None, actor_type: str | None = None,
                limit: int = 100, offset: int = 0, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        query = select(AuditEvent)
        if q:
            like = f"%{q}%"
            query = query.where(or_(AuditEvent.action.ilike(like), AuditEvent.reason.ilike(like), AuditEvent.target.ilike(like),
                                    AuditEvent.correlation_id.ilike(like), AuditEvent.transaction_id.ilike(like), AuditEvent.incident_id.ilike(like)))
        if actor:
            query = query.where(AuditEvent.actor == actor)
        if target:
            query = query.where(AuditEvent.target == target.upper())
        if result:
            query = query.where(AuditEvent.result == result.upper())
        if actor_type:
            query = query.where(AuditEvent.actor_type == actor_type.upper())
        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = db.scalars(query.order_by(AuditEvent.id.desc()).offset(max(0, offset)).limit(min(limit, 500))).all()
        return {"total": total, "offset": offset, "items": [{"id": a.id, "ts": a.ts.isoformat(), "actor": a.actor, "actor_type": a.actor_type, "action": a.action,
                                                             "reason": a.reason, "target": a.target, "result": a.result, "correlation_id": a.correlation_id,
                                                             "transaction_id": a.transaction_id, "incident_id": a.incident_id, "severity": a.severity}
                                                            for a in rows]}


# ------------------------------------------------------------------------------- chatops
def chat_dict(m: ChatOpsEvent) -> dict[str, Any]:
    return {"id": m.id, "ts": m.ts.isoformat(), "provider": m.provider, "kind": m.kind, "title": m.title, "body": m.body, "fields": m.fields,
            "delivery_status": m.delivery_status, "error": m.error, "correlation_id": m.correlation_id}


@router.get("/chatops")
async def chatops(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        msgs = db.scalars(select(ChatOpsEvent).order_by(ChatOpsEvent.ts.desc()).limit(100)).all()
        kinds = dict(db.execute(select(ChatOpsEvent.kind, func.count()).group_by(ChatOpsEvent.kind)).all())
        return {"provider": ctx.settings.chatops_provider, "configured": ctx.chatops.configured,
                "stats": {"messages": sum(kinds.values()), "successful_remediations": kinds.get("AUTOHEAL_EVENT", 0),
                          "failed_remediations": kinds.get("AUTOHEAL_FAILED", 0), "human_escalations": kinds.get("AUTOHEAL_FAILED", 0) + kinds.get("APPROVAL", 0),
                          "approvals": kinds.get("APPROVAL", 0), "tests": kinds.get("TEST", 0)},
                "messages": [chat_dict(m) for m in msgs]}


@router.post("/chatops/test", dependencies=[Depends(limited("sensitive"))])
async def chatops_test(ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    with ctx.session() as db:
        msg = ctx.chatops.record(db, "TEST", "NEXUS TEST NOTIFICATION", {"Requested by": p.name, "Environment": ctx.environment_label,
                                                                          "Time": ctx.clock.site_now().strftime("%H:%M:%S")})
        return chat_dict(msg)


# ------------------------------------------------------------------------------- reports
@router.get("/reports")
async def reports(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"id": r.id, "kind": r.kind, "title": r.title, "subject": r.subject, "created_at": r.created_at.isoformat()}
                for r in db.scalars(select(Report).order_by(Report.created_at.desc()).limit(100))]


@router.get("/reports/{report_id}")
async def report(report_id: str, format: str = "json", ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)):  # noqa: A002, ANN201
    from nexus.incidents.reports import markdown_to_html, report_dict

    with ctx.session() as db:
        r = db.get(Report, report_id.upper())
        if r is None:
            raise KeyError(report_id)
        if format == "html":
            return HTMLResponse(markdown_to_html(r.markdown, r.title))
        if format == "md":
            return PlainTextResponse(r.markdown, media_type="text/markdown")
        return report_dict(r)


# ---------------------------------------------------------------------------- operations
@router.get("/operations/daily")
async def daily(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.operations.daily import daily_operations

    with ctx.session() as db:
        return daily_operations(ctx, db)


@router.get("/operations/morning-brief")
async def brief(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.operations.daily import morning_brief

    with ctx.session() as db:
        return morning_brief(ctx, db)


@router.get("/operations/handover")
async def handover(format: str = "md", hours: int = 8, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)):  # noqa: A002, ANN201
    from nexus.incidents.reports import markdown_to_html
    from nexus.operations.daily import handover_markdown

    with ctx.session() as db:
        md = handover_markdown(ctx, db, hours)
    return HTMLResponse(markdown_to_html(md, "Shift handover")) if format == "html" else PlainTextResponse(md, media_type="text/markdown")


@router.post("/operations/handover")
async def save_handover(ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.incidents.reports import save_report
    from nexus.operations.daily import handover_markdown

    with ctx.session() as db:
        rep = save_report(ctx, db, "handover", f"Shift handover {ctx.clock.site_now():%Y-%m-%d %H:%M}", handover_markdown(ctx, db), subject=p.user_id)
        return {"id": rep.id, "title": rep.title}


@router.get("/troubleshooting")
async def troubleshooting(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.operations.troubleshooting import guides

    with ctx.session() as db:
        return guides(ctx, db)


# ------------------------------------------------------------------------------ runbooks
def _runbooks(ctx: Context) -> dict[str, dict[str, Any]]:
    folder: Path = ctx.settings.config_root / "runbooks"
    return {d["id"]: d for d in (yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.yaml"))) if d}


class RunbookIn(BaseModel):
    target: str | None = Field(None, max_length=64)
    action_id: str | None = Field(None, max_length=64)


@router.get("/runbooks")
async def runbooks(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    return list(_runbooks(ctx).values())


@router.post("/runbooks/{runbook_id}/diagnose")
async def runbook_diagnose(runbook_id: str, body: RunbookIn, ctx: Context = Depends(get_ctx), _: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    rb = _runbooks(ctx).get(runbook_id)
    if rb is None:
        raise KeyError(runbook_id)
    target = (body.target or rb.get("target", "")).upper()
    if target in ("", "DYNAMIC"):
        raise ValueError("this runbook needs a target device")
    with ctx.session() as db:
        results = [ctx.probes.check(db, target, d) | {"description": d.get("description", "")} for d in rb.get("diagnostics", [])]
    return {"runbook": runbook_id, "target": target, "results": results, "all_passed": all(r["passed"] for r in results), "read_only": True}


@router.post("/runbooks/{runbook_id}/execute", dependencies=[Depends(limited("sensitive"))])
async def runbook_execute(runbook_id: str, body: RunbookIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.decision import plan_action

    rb = _runbooks(ctx).get(runbook_id)
    if rb is None:
        raise KeyError(runbook_id)
    target = (body.target or rb.get("target", "")).upper()
    actions = [a["action"] for a in rb.get("actions", [])]
    action_id = body.action_id or (actions[0] if actions else None)
    if not action_id or action_id not in actions:
        raise ValueError(f"{action_id} is not part of {runbook_id}")
    params: dict[str, Any] = {"component": {"REM-CFG-RESTORE-SSH": "ssh", "REM-CFG-RESTORE-NGINX": "nginx"}.get(action_id)}
    if action_id == "REM-DISK-ROTATE-LOGS":
        params["logset"] = "portal" if target == "APP01" else "nginx"
    if action_id == "REM-NET-QUARANTINE":
        params["vlan"] = 99
    with ctx.session() as db:
        return plan_action(ctx, db, action_id=action_id, target=target, params={k: v for k, v in params.items() if v is not None},
                           trigger=f"runbook {runbook_id} executed by {p.user_id}", evidence=[f"runbook {rb['title']}"], requested_by=p.user_id)

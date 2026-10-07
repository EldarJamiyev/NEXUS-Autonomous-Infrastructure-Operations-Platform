"""Access & leases, explainability, policies, change impact, what-if, time machine, chaos lab, demo,
operator assistant and integration ingest endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from nexus.api.deps import ROLE_RANK, Principal, current_principal, get_ctx, limited, require
from nexus.core.audit import record_audit
from nexus.core.context import Context
from nexus.models import (
    ChangeRequest,
    ChaosRun,
    Decision,
    Device,
    DriftEvent,
    Incident,
    Lease,
    Policy,
    PolicyVersion,
    RiskScore,
    StateSnapshot,
)

router = APIRouter(prefix="/api", tags=["control"])


# --------------------------------------------------------------------------- access
class AccessIn(BaseModel):
    user_id: str = Field(max_length=64)
    device_id: str = Field(max_length=64)
    destination: str = Field(max_length=64)
    port: int = Field(ge=1, le=65535)
    protocol: Literal["TCP", "UDP"] = "TCP"
    reason: str = Field("", max_length=200)
    duration_minutes: int | None = Field(None, ge=1, le=1440)


@router.get("/leases")
async def leases(status: str | None = None, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.leases.engine import lease_dict

    with ctx.session() as db:
        q = select(Lease).order_by(Lease.created_at.desc()).limit(200)
        if status:
            q = q.where(Lease.status.in_(status.upper().split(",")))
        return [lease_dict(ctx, x) for x in db.scalars(q)]


@router.post("/access/request", dependencies=[Depends(limited("sensitive"))])
async def access_request(body: AccessIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.leases.engine import request_access

    if body.user_id.lower() != p.user_id and ROLE_RANK[p.role] < ROLE_RANK["ENGINEER"]:
        raise HTTPException(status_code=403, detail="you can only request access for yourself (ENGINEER+ may request on behalf of others)")
    with ctx.session() as db:
        return request_access(ctx, db, user_id=body.user_id, device_id=body.device_id, destination=body.destination, port=body.port, protocol=body.protocol,
                              reason=body.reason, duration_minutes=body.duration_minutes, requested_by=p.user_id)


@router.post("/leases/{lease_id}/revoke", dependencies=[Depends(limited("sensitive"))])
async def revoke(lease_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.leases.engine import lease_dict, revoke_lease

    with ctx.session() as db:
        return lease_dict(ctx, revoke_lease(ctx, db, lease_id.upper(), f"revoked by {p.user_id}", actor=p.user_id))


# ---------------------------------------------------------------------------- explain
@router.get("/explain/access")
async def explain_access(user: str, device: str, destination: str, port: int, protocol: str = "TCP", ctx: Context = Depends(get_ctx),
                         _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.policy.evaluator import evaluate_access

    with ctx.session() as db:
        r = evaluate_access(ctx, db, user, device, destination, port, protocol)
        return {"title": f"Why {'can' if r['decision'] == 'ALLOW' else 'can not'} {r.get('user', {}).get('name', user)} access {destination.upper()}:{port}?", **r}


@router.get("/explain/risk/{entity_type}/{entity_id}")
async def explain_risk(entity_type: str, entity_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.models import RiskEvent

    with ctx.session() as db:
        r = db.get(RiskScore, (entity_type, entity_id))
        if r is None:
            raise KeyError(f"no risk score for {entity_type} {entity_id}")
        history = db.scalars(select(RiskEvent).where(RiskEvent.entity_type == entity_type, RiskEvent.entity_id == entity_id).order_by(RiskEvent.ts.desc()).limit(10)).all()
        factors = sorted(r.factors, key=lambda f: -f["points"])
        return {"title": f"Why is {entity_id} risk {r.score}?", "score": r.score, "level": r.level, "trust": r.trust, "factors": factors,
                "narrative": f"{entity_id} scores {r.score} ({r.level}). Largest contributors: " + "; ".join(f"{f['label']} +{f['points']} ({f['evidence']})" for f in factors[:3]) + ".",
                "history": [{"ts": h.ts.isoformat(), "old": h.old_score, "new": h.new_score, "reason": h.reason} for h in history],
                "note": "Deterministic sum of configured factors (policies/risk-rules.yaml)."}


@router.get("/explain/incident/{incident_id}")
async def explain_incident(incident_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        inc = db.get(Incident, incident_id.upper())
        if inc is None:
            raise KeyError(incident_id)
        return {"title": f"Why did {inc.id} happen?", "root_cause": inc.root_cause, "confidence": inc.root_cause_confidence, "kind": inc.root_cause_kind,
                "evidence": inc.evidence, "candidates": (inc.triage or {}).get("rca_candidates", []), "triage": inc.triage,
                "narrative": f"{inc.root_cause} (confidence {inc.root_cause_confidence}). " + " ".join(f"{e}." for e in (inc.evidence or [])[:3]),
                "method": "Deterministic: dependency graph, observed state, event timing, recent changes, configuration validation. No machine learning."}


@router.get("/explain/drift/{drift_id}")
async def explain_drift(drift_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.drift.engine import drift_dict

    with ctx.session() as db:
        d = db.get(DriftEvent, drift_id.upper())
        if d is None:
            raise KeyError(drift_id)
        return {"title": f"Why is {d.id} {d.classification} drift?", **drift_dict(d),
                "narrative": f"Git intent ({d.source}) says {d.component}.{d.key} = {d.desired!r}; the host reports {d.actual!r}. "
                             f"POL-SERVER-BASELINE classifies this as {d.classification} with risk {d.risk}. Expected sha256 {d.desired_checksum[:12]}, "
                             f"actual {d.actual_checksum[:12]}: MATCH {'YES' if d.desired_checksum == d.actual_checksum else 'NO'}."}


@router.get("/explain/decision/{decision_id}")
async def explain_decision(decision_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.api.routers.operations import decision_dict

    with ctx.session() as db:
        d = db.get(Decision, decision_id.upper())
        if d is None:
            raise KeyError(decision_id)
        return {"title": f"Why did NEXUS decide {d.outcome} for {d.action_id}?", **decision_dict(d),
                "narrative": f"Trigger: {d.trigger}. {'; '.join(d.reasons)}. Automation confidence {d.confidence}% from evidence completeness: "
                             + ", ".join(f"{b['factor']} {b['points']:+d}" for b in d.confidence_breakdown) + "."}


@router.get("/explain/quarantine/{device_id}")
async def explain_quarantine(device_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        d = db.get(Device, device_id.upper())
        if d is None:
            raise KeyError(device_id)
        dec = db.scalar(select(Decision).where(Decision.target == d.id, Decision.action_id == "REM-NET-QUARANTINE").order_by(Decision.ts.desc()))
        r = db.get(RiskScore, ("device", d.id))
        return {"title": f"Why was {d.id} quarantined?" if d.quarantined else f"{d.id} is not quarantined", "quarantined": d.quarantined,
                "reason": d.quarantine_reason, "risk": r.score if r else 0, "factors": r.factors if r else [], "identity": d.identity_confidence,
                "identity_level": d.identity_level, "policy": (dec.policy or {}).get("policy") if dec else None, "confidence": dec.confidence if dec else None,
                "decision": dec.id if dec else None, "action": "Move device to VLAN 99 quarantine (isolated by FW-020)",
                "signals_missing": [s["label"] for s in (d.identity_signals or {}).get("signals", []) if s.get("status") is False]}


# --------------------------------------------------------------------------- policies
class PolicyText(BaseModel):
    content: str = Field(max_length=50_000)


class VersionIn(BaseModel):
    version: int = Field(ge=1)


@router.get("/policies")
async def policies(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        out = []
        for pol in db.scalars(select(Policy).order_by(Policy.kind, Policy.id)):
            ver = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == pol.id, PolicyVersion.version == pol.active_version))
            count = len(db.scalars(select(PolicyVersion.id).where(PolicyVersion.policy_id == pol.id)).all())
            out.append({"id": pol.id, "name": pol.name, "kind": pol.kind, "description": pol.description, "status": pol.status, "file_path": pol.file_path,
                        "active_version": pol.active_version, "versions": count, "checksum": ver.checksum if ver else None, "author": ver.author if ver else None,
                        "updated_at": ver.created_at.isoformat() if ver else None})
        return out


@router.get("/policies/compile")
async def compile_policies(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.policy.compiler import compile_policy_set

    with ctx.session() as db:
        report = compile_policy_set(ctx, db)
    ctx.runtime.last_compile = report  # type: ignore[attr-defined]
    return report


@router.get("/policies/diff")
async def policy_disk_diff(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.policy.versions import diff_against_disk

    with ctx.session() as db:
        return diff_against_disk(ctx, db)


@router.post("/policies/validate")
async def validate_policy(body: PolicyText, ctx: Context = Depends(get_ctx), _: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.policy.compiler import compile_policy_set
    from nexus.policy.schema import PolicyValidationError, parse_policy

    try:
        doc = parse_policy(body.content)
    except PolicyValidationError as exc:
        return {"ok": False, "errors": exc.messages, "stages": [{"name": "Schema validation", "status": "failed", "messages": exc.messages}]}
    with ctx.session() as db:
        return compile_policy_set(ctx, db, overrides={doc.metadata.id: body.content}) | {"policy_id": doc.metadata.id}


@router.post("/policies/simulate")
async def simulate_policy(body: PolicyText, ctx: Context = Depends(get_ctx), _: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.policy.compiler import compile_policy_set
    from nexus.policy.schema import PolicyValidationError, parse_policy

    try:
        doc = parse_policy(body.content)
    except PolicyValidationError as exc:
        return {"ok": False, "errors": exc.messages}
    with ctx.session() as db:
        before = compile_policy_set(ctx, db)
        after = compile_policy_set(ctx, db, overrides={doc.metadata.id: body.content})
    gained = sorted(set(after["impact"]["users"]) - set(before["impact"]["users"]))
    lost = sorted(set(before["impact"]["users"]) - set(after["impact"]["users"]))
    return {"policy_id": doc.metadata.id, "ok": after["ok"], "users_gaining_access": gained, "users_losing_access": lost,
            "new_conflicts": [c for c in after["conflicts"] if c not in before["conflicts"]], "new_shadowed": [s for s in after["shadowed"] if s not in before["shadowed"]],
            "risk": after["risk"], "note": "Simulation only - nothing was activated."}


@router.get("/policies/{policy_id}")
async def policy(policy_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.policy.versions import version_dict

    with ctx.session() as db:
        pol = db.get(Policy, policy_id.upper())
        if pol is None:
            raise KeyError(policy_id)
        versions = db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == pol.id).order_by(PolicyVersion.version.desc())).all()
        active = next((v for v in versions if v.version == pol.active_version), versions[0] if versions else None)
        return {"id": pol.id, "name": pol.name, "kind": pol.kind, "status": pol.status, "description": pol.description, "file_path": pol.file_path,
                "active_version": pol.active_version, "content": active.content if active else "", "versions": [version_dict(v) for v in versions]}


@router.get("/policies/{policy_id}/diff")
async def policy_diff(policy_id: str, a: int, b: int, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.policy.versions import diff_versions

    with ctx.session() as db:
        return {"policy": policy_id, "a": a, "b": b, "diff": diff_versions(db, policy_id.upper(), a, b)}


@router.post("/policies/{policy_id}/activate", dependencies=[Depends(limited("sensitive"))])
async def activate_policy(policy_id: str, body: VersionIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.policy.versions import activate, version_dict

    with ctx.session() as db:
        return version_dict(activate(ctx, db, policy_id.upper(), body.version, p.user_id))


@router.post("/policies/{policy_id}/rollback", dependencies=[Depends(limited("sensitive"))])
async def rollback_policy(policy_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.policy.versions import rollback, version_dict

    with ctx.session() as db:
        return version_dict(rollback(ctx, db, policy_id.upper(), p.user_id))


@router.post("/policies/{policy_id}/deactivate", dependencies=[Depends(limited("sensitive"))])
async def deactivate_policy(policy_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.policy.versions import set_status

    with ctx.session() as db:
        pol = set_status(ctx, db, policy_id.upper(), False, p.user_id)
        return {"id": pol.id, "status": pol.status}


@router.post("/policies/{policy_id}/enable", dependencies=[Depends(limited("sensitive"))])
async def enable_policy(policy_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.policy.versions import set_status

    with ctx.session() as db:
        pol = set_status(ctx, db, policy_id.upper(), True, p.user_id)
        return {"id": pol.id, "status": pol.status}


@router.post("/policies/apply", dependencies=[Depends(limited("sensitive"))])
async def apply_policies(ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.drift.engine import reload_baselines
    from nexus.policy.cache import refresh, sync_from_disk

    with ctx.session() as db:
        changes = sync_from_disk(ctx, db, author=p.user_id)
        refresh(ctx, db)
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action="applied policies from Git", reason=f"{len(changes)} change(s)", target="NEXUS", result="SUCCESS",
                     details={"changes": changes})
    reload_baselines(ctx)
    if ctx.controlplane:
        ctx.controlplane.reconcile_once(None)
    return {"changes": changes}


# --------------------------------------------------------------------- change impact
class ChangeIn(BaseModel):
    change_type: Literal["disable_ssh", "stop_service", "reboot", "remove_rule", "change_vlan", "remove_policy"]
    target: str = Field(max_length=64)
    title: str | None = Field(None, max_length=200)
    vlan: int | None = None


def _impact(ctx: Context, db: Any, body: ChangeIn) -> dict[str, Any]:
    from nexus.core.decision import in_change_window
    from nexus.whatif.engine import simulate

    mapping = {"disable_ssh": ("ssh_loss", {"device": body.target.upper()}), "stop_service": ("service_down", {"service": body.target}),
               "reboot": ("device_down", {"device": body.target.upper()}), "remove_rule": ("rule_removed", {"rule": body.target.upper()}),
               "remove_policy": ("policy_removed", {"policy": body.target.upper()}), "change_vlan": ("device_down", {"device": body.target.upper()})}
    scenario, params = mapping[body.change_type]
    result = simulate(ctx, db, scenario, params)
    imp = result["impact"]
    window_ok, window_text = in_change_window(ctx, db)
    level = imp["level"] if body.change_type != "change_vlan" else ("HIGH" if imp["counts"]["leases"] else "MEDIUM")
    approval = level in ("HIGH", "CRITICAL") or not window_ok
    return {"change": body.title or f"{body.change_type.replace('_', ' ')} on {body.target}", "impact_level": level, "users_affected": imp["counts"]["users"],
            "devices_affected": imp["counts"]["devices"], "services_affected": imp["counts"]["services"], "active_leases": imp["counts"]["leases"],
            "dependencies": max(0, imp["counts"]["services"] - 1), "policies": imp["policies"], "approval": "REQUIRED" if approval else "NOT REQUIRED",
            "approval_reason": ("impact " + level) if level in ("HIGH", "CRITICAL") else window_text, "window": window_text, "details": result}


@router.post("/changes/impact")
async def change_impact(body: ChangeIn, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        return _impact(ctx, db, body)


@router.get("/changes")
async def changes(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"id": c.id, "title": c.title, "change_type": c.change_type, "target": c.target, "status": c.status, "requested_by": c.requested_by,
                 "impact": {k: v for k, v in (c.impact or {}).items() if k != "details"}, "window": c.window, "approval_id": c.approval_id,
                 "created_at": c.created_at.isoformat()} for c in db.scalars(select(ChangeRequest).order_by(ChangeRequest.created_at.desc()))]


@router.post("/changes", dependencies=[Depends(limited("sensitive"))])
async def create_change(body: ChangeIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.decision import next_window
    from nexus.ids import new_id
    from nexus.models import Approval

    with ctx.session() as db:
        imp = _impact(ctx, db, body)
        now = ctx.clock.now()
        change = ChangeRequest(id=new_id(db, "change"), title=imp["change"], change_type=body.change_type, target=body.target, parameters=body.model_dump(),
                               requested_by=p.user_id, status="PENDING_APPROVAL" if imp["approval"] == "REQUIRED" else "APPROVED",
                               impact={k: v for k, v in imp.items() if k != "details"}, window=next_window(ctx, db), created_at=now, updated_at=now)
        db.add(change)
        db.flush()
        if imp["approval"] == "REQUIRED":
            a = Approval(id=new_id(db, "approval"), kind="change", title=f"Change {change.id}: {change.title}", target=body.target.upper(), change_id=change.id,
                         category="HIGH_IMPACT", risk=imp["impact_level"], reason=imp["approval_reason"], required_role="ENGINEER", status="PENDING",
                         requested_by=p.user_id, requested_at=now)
            db.add(a)
            change.approval_id = a.id
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action=f"created change request {change.id}", reason=change.title, target=body.target.upper(),
                     result=change.status)
        return {"id": change.id, "status": change.status, "approval_id": change.approval_id, "impact": change.impact}


# -------------------------------------------------------------------------- what-if
class WhatIfIn(BaseModel):
    scenario: str = Field(max_length=40)
    params: dict[str, Any] = {}


@router.get("/whatif/scenarios")
async def whatif_scenarios(_: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.whatif.engine import SCENARIOS

    return SCENARIOS


@router.post("/whatif")
async def whatif(body: WhatIfIn, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.whatif.engine import simulate

    with ctx.session() as db:
        return simulate(ctx, db, body.scenario, body.params)


# ------------------------------------------------------------------- time machine
def _parse_at(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        from datetime import UTC

        dt = dt.replace(tzinfo=UTC)
    return dt


@router.get("/timemachine/timeline")
async def timeline(hours: float = 3.0, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.timemachine.snapshots import timeline as tl

    with ctx.session() as db:
        return tl(db, ctx.clock.now() - timedelta(hours=hours)) | {"now": ctx.clock.now().isoformat()}


@router.get("/timemachine/state")
async def state_at(at: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.timemachine.snapshots import state_at as sa

    with ctx.session() as db:
        result = sa(db, _parse_at(at))
        if result is None:
            raise KeyError("no snapshots recorded yet")
        return result


@router.get("/timemachine/compare")
async def compare(a: str, b: str = "now", ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.timemachine.snapshots import capture
    from nexus.timemachine.snapshots import compare as cmp
    from nexus.timemachine.snapshots import state_at as sa

    with ctx.session() as db:
        def load(ref: str) -> tuple[dict[str, Any], str]:
            if ref == "now":
                return capture(ctx, db), ctx.clock.now().isoformat()
            if ref.isdigit():
                snap = db.get(StateSnapshot, int(ref))
                if snap is None:
                    raise KeyError(f"snapshot {ref} not found")
                return snap.data, snap.ts.isoformat()
            st = sa(db, _parse_at(ref))
            if st is None:
                raise KeyError("no snapshot at that time")
            return st["state"], st["snapshot"]["ts"]

        da, ta = load(a)
        dbb, tb = load(b)
        return {"a": ta, "b": tb, "diff": cmp(da, dbb)}


class SnapshotIn(BaseModel):
    label: str = Field("manual snapshot", max_length=100)


@router.post("/snapshots")
async def snapshot(body: SnapshotIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.timemachine.snapshots import create_snapshot

    with ctx.session() as db:
        snap = create_snapshot(ctx, db, f"manual by {p.user_id}", label=body.label, force=True)
        return {"id": snap.id, "ts": snap.ts.isoformat(), "label": snap.label, "checksum": snap.checksum}  # type: ignore[union-attr]


@router.get("/snapshots")
async def snapshots(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"id": s.id, "ts": s.ts.isoformat(), "reason": s.reason, "label": s.label, "checksum": s.checksum}
                for s in db.scalars(select(StateSnapshot).order_by(StateSnapshot.ts.desc()).limit(200))]


# ------------------------------------------------------------------------- chaos
@router.get("/chaos/scenarios")
async def chaos_scenarios(_: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.chaos.scenarios import catalog

    return catalog()


@router.get("/chaos/runs")
async def chaos_runs(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"id": r.id, "scenario": r.scenario, "title": r.title, "status": r.status, "started_at": r.started_at.isoformat(), "requested_by": r.requested_by,
                 "finished_at": r.finished_at.isoformat() if r.finished_at else None, "report_id": r.report_id}
                for r in db.scalars(select(ChaosRun).order_by(ChaosRun.started_at.desc()).limit(50))]


@router.get("/chaos/runs/{run_id}")
async def chaos_run(run_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.chaos.scenarios import run_view

    with ctx.session() as db:
        run = db.get(ChaosRun, run_id.upper())
        if run is None:
            raise KeyError(run_id)
        return run_view(ctx, db, run) | {"report_id": run.report_id}


@router.post("/chaos/runs/{run_id}/operator-fix", dependencies=[Depends(limited("sensitive"))])
async def chaos_fix(run_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.chaos.scenarios import operator_fix

    with ctx.session() as db:
        return {"run": run_id, "notes": operator_fix(ctx, db, run_id.upper(), p.user_id)}


@router.post("/chaos/{scenario}", dependencies=[Depends(limited("chaos"))])
async def chaos(scenario: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    if not ctx.settings.is_simulation:
        raise HTTPException(status_code=409, detail="Chaos Lab is only available in SIMULATION environment")
    if scenario == "blackout":
        return {"run": ctx.controlplane.start_blackout(p.user_id), "scenario": "blackout"}
    with ctx.session() as db:
        run = ctx.controlplane.start_chaos_sync(db, scenario, p.user_id)
        return {"run": run.id, "scenario": scenario, "injections": run.injections}


# --------------------------------------------------------------------------- demo
@router.post("/demo/reset", dependencies=[Depends(limited("chaos"))])
async def demo_reset(ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.app import reset_environment

    if not ctx.settings.is_simulation:
        raise HTTPException(status_code=409, detail="reset is only available in SIMULATION environment")
    ctx.controlplane.demo.stop()
    for t in list(ctx.controlplane.tasks):
        t.cancel()
    reset_environment(ctx)
    with ctx.session() as db:
        record_audit(ctx, db, actor=p.user_id, actor_type="OPERATOR", action="reset demo environment", reason="console request", target="NEXUS", result="SUCCESS")
        ctx.bus.emit(db, "SETTING_CHANGED", f"Demo environment reset by {p.user_id}", severity="notice", source="console")
    return {"status": "reset", "at": ctx.clock.now().isoformat()}


@router.post("/demo/blackout", dependencies=[Depends(limited("chaos"))])
async def demo_blackout(ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    return {"run": ctx.controlplane.start_blackout(p.user_id), "scenario": "blackout"}


@router.get("/demo/state")
async def demo_state(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    return ctx.controlplane.demo.snapshot()


@router.post("/demo/{command}", dependencies=[Depends(limited("chaos"))])
async def demo_control(command: Literal["start", "pause", "resume", "next", "stop"], ctx: Context = Depends(get_ctx),
                       p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    demo = ctx.controlplane.demo
    if command == "start":
        return demo.start()
    getattr(demo, command)()
    return demo.snapshot()


# ----------------------------------------------------------------------- copilot
class AskIn(BaseModel):
    question: str = Field(min_length=2, max_length=300)


@router.post("/copilot/ask")
async def ask(body: AskIn, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.operations.copilot import EXAMPLES
    from nexus.operations.copilot import ask as do_ask

    with ctx.session() as db:
        return do_ask(ctx, db, body.question) | {"examples": EXAMPLES}


# ------------------------------------------------------------------------ ingest
@router.post("/ingest/windows-events", tags=["integrations"], dependencies=[Depends(limited("webhook"))])
async def ingest_windows(events: list[dict[str, Any]], ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.identity.ingest import ingest_windows_event

    accepted, rejected = 0, []
    with ctx.session() as db:
        for raw in events[:500]:
            try:
                ingest_windows_event(ctx, db, raw, source="powershell")
                accepted += 1
            except ValueError as exc:
                rejected.append(str(exc))
    return {"accepted": accepted, "rejected": rejected[:20]}


class InventoryIn(BaseModel):
    users: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    computers: list[dict[str, Any]] = []


@router.post("/ingest/ad-inventory", tags=["integrations"], dependencies=[Depends(limited("webhook"))])
async def ingest_inventory(body: InventoryIn, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ADMIN"))) -> dict[str, Any]:
    from nexus.models import Group, User, UserGroup

    now = ctx.clock.now()
    counts = {"users": 0, "groups": 0, "memberships": 0, "computers": 0}
    with ctx.session() as db:
        for g in body.groups:
            gid = str(g.get("Name") or g.get("id", ""))[:64]
            if gid and db.get(Group, gid) is None:
                db.add(Group(id=gid, description=str(g.get("Description", ""))[:256], privileged="ADMIN" in gid.upper()))
                counts["groups"] += 1
        db.flush()
        for u in body.users:
            uid = str(u.get("SamAccountName") or u.get("id", "")).lower()[:64]
            if not uid:
                continue
            user = db.get(User, uid)
            if user is None:
                user = User(id=uid, display_name=str(u.get("DisplayName") or uid)[:128], email=str(u.get("Mail") or f"{uid}@example.invalid")[:128],
                            department=str(u.get("Department") or "")[:64], title=str(u.get("Title") or "")[:128], console_role="VIEWER", created_at=now,
                            ad_dn=str(u.get("DistinguishedName") or "")[:256])
                db.add(user)
                counts["users"] += 1
            user.enabled = bool(u.get("Enabled", True))
            db.flush()
            for gid in u.get("MemberOf", []) or []:
                gname = str(gid).split(",")[0].replace("CN=", "")[:64]
                if db.get(Group, gname) and db.get(UserGroup, (uid, gname)) is None:
                    db.add(UserGroup(user_id=uid, group_id=gname))
                    counts["memberships"] += 1
        for c in body.computers:
            name = str(c.get("Name") or "").upper()[:64]
            dev = db.get(Device, name)
            if dev:
                dev.ad_computer = True
                counts["computers"] += 1
        record_audit(ctx, db, actor=p.user_id, actor_type="INTEGRATION", action="imported AD inventory", reason="Get-NexusADInventory.ps1", target="DC01",
                     result="SUCCESS", details=counts)
    return counts


class ConfigReport(BaseModel):
    device: str = Field(max_length=64)
    component: Literal["ssh", "nginx", "docker", "monitoring", "services", "files", "windows", "dns", "ntp", "motd", "system"]
    actual: dict[str, Any]


@router.post("/ingest/config-report", tags=["integrations"], dependencies=[Depends(limited("webhook"))])
async def ingest_config(reports: list[ConfigReport], ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    """Host agents (ansible/roles/nexus-agent) report observed configuration; changes trigger drift reconciliation."""
    accepted = []
    with ctx.session() as db:
        for r in reports[:50]:
            if db.get(Device, r.device.upper()) is None:
                continue
            ctx.world.write_config(db, r.device.upper(), r.component, r.actual, actor=f"nexus-agent@{r.device.upper()}", reason="agent report")
            accepted.append(f"{r.device.upper()}:{r.component}")
    return {"accepted": accepted}

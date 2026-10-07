"""Decision engine: every automated action gets a decision record (trigger, evidence, policy,
risk, impact, safety, confidence, outcome). Human-in-the-loop rules:

  SAFE         automatic
  REVERSIBLE   automatic when automation confidence >= threshold
  HIGH_IMPACT  approval (unless a security policy explicitly permits it, or autonomy >= 4 inside a change window)
  CRITICAL     approval (unless emergency policy explicitly permits)

Automation confidence is evidence completeness, computed deterministically - not a model output.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.core.store import get_setting
from nexus.ids import new_id
from nexus.models import Approval, Decision, Device, Incident, IncidentEvent, RemediationTransaction, User
from nexus.remediation.catalog import CATEGORY_RANK, substitute
from nexus.remediation.executor import CommandRejected, render

if TYPE_CHECKING:
    from nexus.core.context import Context

ROLE_RANK = {"VIEWER": 0, "OPERATOR": 1, "ENGINEER": 2, "ADMIN": 3}
AUTONOMY_LEVELS = {0: "Observe", 1: "Alert", 2: "Recommend", 3: "Reversible AutoHeal", 4: "Critical AutoHeal", 5: "Autonomous Quarantine"}
FIREWALL_OPS = {"firewall_reconcile", "firewall_block", "firewall_restore", "revoke_lease"}


def in_change_window(ctx: Context, db: Session) -> tuple[bool, str]:
    windows = get_setting(db, "change_windows") or []
    now = ctx.clock.site_now()
    day = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"][now.weekday()]
    hm = now.strftime("%H:%M")
    maintenance = get_setting(db, "maintenance") or {}
    if maintenance.get("active"):
        return True, "maintenance mode active"
    for w in windows:
        if day in w["days"] and w["start"] <= hm < w["end"]:
            return True, f"inside {w['name']}"
    nxt = next_window(ctx, db)
    return False, f"outside maintenance (next: {nxt})"


def next_window(ctx: Context, db: Session) -> str:
    windows = get_setting(db, "change_windows") or []
    now = ctx.clock.site_now()
    names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    for offset in range(0, 8):
        day = now + timedelta(days=offset)
        for w in windows:
            if names[day.weekday()] in w["days"] and (offset > 0 or now.strftime("%H:%M") < w["start"]):
                return f"{day.strftime('%A').upper()} {w['start']}-{w['end']}"
    return "none scheduled"


def plan_action(ctx: Context, db: Session, *, action_id: str, target: str, params: dict[str, Any] | None = None, trigger: str,
                evidence: list[str] | None = None, incident_id: str | None = None, drift_id: str | None = None,
                correlation_id: str | None = None, requested_by: str = "AUTOHEAL", policy_override: dict[str, Any] | None = None,
                root_cause_confidence: str | None = None, alert_validated: bool = True) -> dict[str, Any]:
    action = ctx.catalog.get(action_id)
    params = dict(params or {})
    now = ctx.clock.now()
    automation = (ctx.policy_cache.automation if ctx.policy_cache else {}) or {}
    autonomy = int(get_setting(db, "autonomy_level") or 0)
    dev = db.get(Device, target)
    safety: list[dict[str, Any]] = []
    approval_reasons: list[str] = []
    hard_fail: list[str] = []
    reasons: list[str] = []

    # 1. allowlist rendering
    rendered = []
    if dev is not None:
        try:
            for step in action.execution:
                rendered.append(" ".join(render(step["op"], dev, substitute(step, params))))
            safety.append({"name": "Command allowlist", "status": "PASS", "detail": f"{len(rendered)} templated step(s), parameters validated"})
        except CommandRejected as exc:
            safety.append({"name": "Command allowlist", "status": "FAIL", "detail": str(exc)})
            hard_fail.append(str(exc))
    else:
        hard_fail.append(f"target {target} not in inventory")
    # 2. preconditions
    pre = [ctx.probes.precondition(db, target, substitute(p, params)) for p in action.preconditions] if dev else []
    failed_pre = [p for p in pre if not p["passed"]]
    safety.append({"name": "Preconditions", "status": "FAIL" if failed_pre else "PASS",
                   "detail": "; ".join(p["detail"] for p in pre) or "none required"})
    hard_fail += [f"precondition {p['check']}: {p['detail']}" for p in failed_pre]
    # 3. idempotency / duplicate remediation
    dup = db.scalar(select(RemediationTransaction).where(RemediationTransaction.target == target, RemediationTransaction.action_id == action_id,
                                                         RemediationTransaction.status.in_(("PLANNED", "RUNNING", "AWAITING_APPROVAL"))))
    safety.append({"name": "Duplicate guard", "status": "FAIL" if dup else "PASS", "detail": f"{dup.id} already in progress" if dup else "no duplicate"})
    # 4. loop guard
    limit = int(automation.get("max_per_target_action_10min", 3))
    recent = db.scalar(select(func.count()).select_from(RemediationTransaction).where(
        RemediationTransaction.target == target, RemediationTransaction.action_id == action_id,
        RemediationTransaction.created_at >= now - timedelta(minutes=10))) or 0
    if recent >= limit:
        hard_fail.append(f"loop guard: {recent} attempts in 10 min (limit {limit})")
    safety.append({"name": "Loop guard", "status": "FAIL" if recent >= limit else "PASS", "detail": f"{recent}/{limit} attempts in 10 min"})
    # 5. mass change guard
    per_minute = int(automation.get("max_automated_per_minute", 10))
    burst = db.scalar(select(func.count()).select_from(RemediationTransaction).where(
        RemediationTransaction.requested_by == "AUTOHEAL", RemediationTransaction.created_at >= now - timedelta(seconds=60))) or 0
    if burst >= per_minute:
        approval_reasons.append(f"mass-change guard: {burst} automated changes in the last minute")
    safety.append({"name": "Mass-change guard", "status": "WARN" if burst >= per_minute else "PASS", "detail": f"{burst}/{per_minute} per minute"})
    # 6. firewall availability / system mode
    if any(step["op"] in FIREWALL_OPS for step in action.execution) and not ctx.firewall.available():
        hard_fail.append("firewall API unavailable - change deferred until reconciliation")
        safety.append({"name": "Control plane", "status": "FAIL", "detail": "firewall update would be PENDING"})
    if ctx.runtime.db_degraded_until and action.category != "SAFE":
        approval_reasons.append("state store degraded - only SAFE actions run automatically")
    # 7. protected assets and change window
    rank = CATEGORY_RANK[action.category]
    protected = target in automation.get("protected_assets", [])
    if protected and rank >= 2:
        approval_reasons.append(f"{target} is a protected asset")
    window_ok, window_text = in_change_window(ctx, db)
    override = policy_override or {}
    if rank >= 2 and not window_ok and not override.get("auto_permitted"):
        approval_reasons.append(f"{action.category} change {window_text}")
    safety.append({"name": "Change window", "status": "PASS" if window_ok or rank < 2 else "WARN", "detail": window_text})

    # confidence = evidence completeness
    breakdown: list[dict[str, Any]] = [{"factor": "Catalog baseline", "points": action.base_confidence}]
    if not alert_validated:
        breakdown.append({"factor": "Alert not validated against current state", "points": -20})
    if root_cause_confidence == "MEDIUM":
        breakdown.append({"factor": "Root cause confidence MEDIUM", "points": -10})
    elif root_cause_confidence == "LOW":
        breakdown.append({"factor": "Root cause confidence LOW", "points": -25})
    if not action.verification and not action.manual_only:
        breakdown.append({"factor": "No verification probe", "points": -25})
    failures = db.scalar(select(func.count()).select_from(RemediationTransaction).where(
        RemediationTransaction.target == target, RemediationTransaction.action_id == action_id, RemediationTransaction.result == "FAILED",
        RemediationTransaction.created_at >= now - timedelta(hours=24))) or 0
    if failures:
        breakdown.append({"factor": f"{failures} failed attempt(s) in 24 h", "points": -min(30, 15 * failures)})
    confidence = max(0, min(100, sum(b["points"] for b in breakdown)))
    threshold = int(automation.get("confidence_threshold", 80))
    hi_threshold = int(automation.get("high_impact_confidence_threshold", 90))

    operator = requested_by if requested_by not in ("AUTOHEAL", "SYSTEM", "NEXUS") else None
    if action.manual_only:
        outcome = "RECOMMEND"
        reasons.append("no safe automated action exists; human action required")
    elif dup:
        outcome = "SKIPPED_DUPLICATE"
        reasons.append(f"{dup.id} is already handling {action_id} on {target}")
    elif hard_fail:
        outcome = "BLOCKED"
        reasons += hard_fail
    elif operator:
        user = db.get(User, operator)
        role = user.console_role if user else "VIEWER"
        if ROLE_RANK[role] < ROLE_RANK[action.permission]:
            outcome = "BLOCKED"
            reasons.append(f"{operator} has role {role}; {action.permission} required")
        elif approval_reasons and rank >= 2:
            outcome = "APPROVAL_REQUIRED"
            reasons += approval_reasons
        else:
            outcome = "AUTOMATE"
            reasons.append(f"operator {operator} ({role}) requested execution")
    elif autonomy <= 1:
        outcome = "OBSERVE_ONLY"
        reasons.append(f"autonomy level {autonomy} ({AUTONOMY_LEVELS[autonomy]}): record and alert only")
    elif autonomy == 2:
        outcome = "RECOMMEND"
        reasons.append("autonomy level 2 (Recommend): a human must approve execution")
    elif approval_reasons and not (override.get("auto_permitted") and rank == 2 and autonomy >= int(override.get("min_autonomy", 3))):
        outcome = "APPROVAL_REQUIRED"
        reasons += approval_reasons
    elif action.category == "SAFE":
        outcome = "AUTOMATE"
        reasons.append("SAFE action: automatic")
    elif action.category == "REVERSIBLE":
        outcome = "AUTOMATE" if confidence >= threshold else "APPROVAL_REQUIRED"
        reasons.append(f"REVERSIBLE action, confidence {confidence}% {'>=' if confidence >= threshold else '<'} {threshold}%")
    elif action.category == "HIGH_IMPACT":
        if override.get("auto_permitted") and autonomy >= int(override.get("min_autonomy", 3)):
            outcome = "AUTOMATE"
            reasons.append(f"HIGH_IMPACT permitted automatically by {override.get('policy')} at autonomy {autonomy}")
        elif autonomy >= 4 and confidence >= hi_threshold and window_ok and not protected:
            outcome = "AUTOMATE"
            reasons.append(f"autonomy {autonomy}, confidence {confidence}% inside change window")
        else:
            outcome = "APPROVAL_REQUIRED"
            reasons.append("HIGH_IMPACT action requires approval")
    else:
        emergency = automation.get("emergency_allows_critical", False) and autonomy >= 4
        outcome = "AUTOMATE" if emergency else "APPROVAL_REQUIRED"
        reasons.append("CRITICAL action: " + ("emergency policy permits automation" if emergency else "approval required"))

    impact: dict[str, Any] = {}
    if incident_id and (inc := db.get(Incident, incident_id)):
        impact = dict(inc.impact.get("counts", {})) if inc.impact else {}
    safety_card = {
        "preconditions": "FAIL" if failed_pre else "PASS",
        "policy": "PASS" if outcome in ("AUTOMATE", "APPROVAL_REQUIRED", "RECOMMEND") else "FAIL",
        "risk": action.risk, "rollback": "AVAILABLE" if action.rollback_available else "NOT REQUIRED",
        "verification": "AVAILABLE" if action.verification else "NONE",
        "approval": "REQUIRED" if outcome in ("APPROVAL_REQUIRED", "RECOMMEND") else "NOT REQUIRED",
        "decision": {"AUTOMATE": "AUTOMATE", "APPROVAL_REQUIRED": "AWAIT APPROVAL", "RECOMMEND": "HUMAN ACTION"}.get(outcome, outcome),
        "checks": safety, "commands": rendered,
    }
    decision = Decision(id=new_id(db, "decision"), ts=now, trigger=trigger[:128], target=target, action_id=action_id, outcome=outcome,
                        category=action.category, risk=action.risk, confidence=confidence, evidence=evidence or [],
                        policy={"autonomy_level": autonomy, "autonomy_name": AUTONOMY_LEVELS.get(autonomy), **override},
                        impact=impact, safety=safety_card, confidence_breakdown=breakdown, reasons=reasons, incident_id=incident_id,
                        correlation_id=correlation_id)
    db.add(decision)
    db.flush()
    ctx.bus.emit(db, "DECISION_MADE", f"{decision.id} {action.name} on {target}: {outcome} (confidence {confidence}%)",
                 severity="notice", source="decision-engine", target=target,
                 data={"decision": decision.id, "action": action_id, "outcome": outcome, "confidence": confidence, "reasons": reasons},
                 correlation_id=correlation_id)
    if incident_id:
        db.add(IncidentEvent(incident_id=incident_id, ts=now, stage="DECISION",
                             message=f"{action.name}: {outcome.replace('_', ' ')} - {reasons[0] if reasons else ''}",
                             data={"decision": decision.id, "confidence": confidence}))
    out: dict[str, Any] = {"outcome": outcome, "decision_id": decision.id, "confidence": confidence, "reasons": reasons,
                           "transaction_id": None, "approval_id": None}
    if outcome in ("AUTOMATE", "APPROVAL_REQUIRED", "RECOMMEND") and not action.manual_only:
        from nexus.remediation.runner import create_transaction

        tx = create_transaction(ctx, db, action_id=action_id, target=target, params=params, trigger=trigger, decision=decision,
                                incident_id=incident_id, drift_id=drift_id, correlation_id=correlation_id, requested_by=requested_by,
                                awaiting=outcome != "AUTOMATE")
        decision.transaction_id = tx.id
        out["transaction_id"] = tx.id
        if outcome == "AUTOMATE":
            ctx.dispatch([tx.id])
        else:
            approval = Approval(id=new_id(db, "approval"), kind="remediation", title=f"{action.name} on {target}", target=target, action_id=action_id,
                                transaction_id=tx.id, category=action.category, risk=action.risk, reason="; ".join(reasons),
                                required_role="ADMIN" if action.category == "CRITICAL" else "ENGINEER", status="PENDING",
                                requested_by=requested_by, requested_at=now, correlation_id=correlation_id)
            db.add(approval)
            tx.approval_id = approval.id
            out["approval_id"] = approval.id
            ctx.bus.emit(db, "APPROVAL_REQUESTED", f"{approval.id}: {approval.title} awaits approval ({'; '.join(reasons)})", severity="notice",
                         source="decision-engine", target=target, data={"approval_id": approval.id, "transaction": tx.id}, correlation_id=correlation_id)
            ctx.chatops.record(db, "APPROVAL", f"APPROVAL REQUIRED - {action.name}",
                               {"Target": target, "Action": action.name, "Category": action.category, "Reason": "; ".join(reasons),
                                "Approve in": f"NEXUS > Approvals > {approval.id}"}, correlation_id)
    if incident_id and outcome in ("BLOCKED", "RECOMMEND", "OBSERVE_ONLY") and (inc := db.get(Incident, incident_id)):
        inc.human_required = outcome != "OBSERVE_ONLY"
        recs = list(inc.recommendations or [])
        note = f"{action.name}: {'; '.join(reasons)}"
        if note not in recs:
            recs.append(note)
        inc.recommendations = recs
    return out


def approve(ctx: Context, db: Session, approval_id: str, actor: str, note: str = "") -> Approval:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise KeyError(approval_id)
    if approval.status != "PENDING":
        raise ValueError(f"{approval_id} is already {approval.status}")
    user = db.get(User, actor)
    role = user.console_role if user else "VIEWER"
    if ROLE_RANK.get(role, 0) < ROLE_RANK[approval.required_role]:
        raise PermissionError(f"{actor} ({role}) cannot approve; {approval.required_role} required")
    if approval.requested_by == actor:
        raise PermissionError("requesters cannot approve their own request (four-eyes rule)")
    approval.status = "APPROVED"
    approval.decided_by = actor
    approval.decided_at = ctx.clock.now()
    approval.note = note
    ctx.bus.emit(db, "APPROVAL_GRANTED", f"{approval.id} approved by {actor}: {approval.title}", severity="notice", source="approvals",
                 target=approval.target, user_id=actor, data={"approval_id": approval.id}, correlation_id=approval.correlation_id)
    from nexus.core.audit import record_audit

    record_audit(ctx, db, actor=actor, actor_type="OPERATOR", action=f"approved {approval.title}", reason=note or approval.reason,
                 target=approval.target, result="APPROVED", correlation_id=approval.correlation_id, transaction_id=approval.transaction_id)
    if approval.kind == "remediation" and approval.transaction_id:
        tx = db.get(RemediationTransaction, approval.transaction_id)
        if tx and tx.status == "AWAITING_APPROVAL":
            tx.status = "PLANNED"
            ctx.dispatch([tx.id])
    elif approval.kind == "lease" and approval.lease_id:
        from nexus.leases.engine import approve_lease
        from nexus.models import Lease

        lease = db.get(Lease, approval.lease_id)
        if lease:
            approve_lease(ctx, db, lease, actor)
    elif approval.kind == "change" and approval.change_id:
        from nexus.models import ChangeRequest

        change = db.get(ChangeRequest, approval.change_id)
        if change:
            change.status = "APPROVED"
            change.updated_at = ctx.clock.now()
    return approval


def reject(ctx: Context, db: Session, approval_id: str, actor: str, note: str = "") -> Approval:
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise KeyError(approval_id)
    if approval.status != "PENDING":
        raise ValueError(f"{approval_id} is already {approval.status}")
    approval.status = "REJECTED"
    approval.decided_by = actor
    approval.decided_at = ctx.clock.now()
    approval.note = note
    if approval.transaction_id and (tx := db.get(RemediationTransaction, approval.transaction_id)):
        tx.status = "REJECTED"
        tx.result = "REJECTED"
        tx.human_action = "REQUIRED"
    if approval.lease_id:
        from nexus.models import Lease

        lease = db.get(Lease, approval.lease_id)
        if lease and lease.status == "PENDING_APPROVAL":
            lease.status = "DENIED"
            lease.end_reason = f"approval rejected by {actor}"
    ctx.bus.emit(db, "APPROVAL_REJECTED", f"{approval.id} rejected by {actor}: {approval.title}", severity="notice", source="approvals",
                 target=approval.target, user_id=actor, data={"approval_id": approval.id}, correlation_id=approval.correlation_id)
    from nexus.core.audit import record_audit

    record_audit(ctx, db, actor=actor, actor_type="OPERATOR", action=f"rejected {approval.title}", reason=note or "rejected",
                 target=approval.target, result="REJECTED", correlation_id=approval.correlation_id)
    return approval

"""Ephemeral access leases: short-lived, session-bound, firewall-reconciled, risk-revocable."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.audit import record_audit
from nexus.firewall.base import FirewallUnavailable, RuleSpec
from nexus.ids import new_id
from nexus.models import Approval, Device, Lease, User
from nexus.policy.evaluator import evaluate_access
from nexus.risk.engine import score_of

if TYPE_CHECKING:
    from nexus.core.context import Context


def lease_dict(ctx: Context, lease: Lease) -> dict[str, Any]:
    tz = ctx.clock.site_tz
    remaining = (lease.expires_at - ctx.clock.now()).total_seconds() if lease.status == "ACTIVE" else 0
    return {"id": lease.id, "user_id": lease.user_id, "device_id": lease.device_id, "source_ip": lease.source_ip,
            "destination": lease.destination_id, "protocol": lease.protocol, "port": lease.port, "reason": lease.reason,
            "policy_id": lease.policy_id, "status": lease.status, "firewall_state": lease.firewall_state,
            "firewall_rule_id": lease.firewall_rule_id, "risk_at_grant": lease.risk_at_grant,
            "identity_confidence_at_grant": lease.identity_confidence_at_grant, "created_at": lease.created_at.isoformat(),
            "expires_at": lease.expires_at.isoformat(), "created_local": lease.created_at.astimezone(tz).strftime("%H:%M"),
            "expires_local": lease.expires_at.astimezone(tz).strftime("%H:%M"), "remaining_seconds": max(0, int(remaining)),
            "ended_at": lease.ended_at.isoformat() if lease.ended_at else None, "end_reason": lease.end_reason,
            "approval_id": lease.approval_id, "correlation_id": lease.correlation_id}


def _spec(lease: Lease) -> RuleSpec:
    return RuleSpec(action="ALLOW", source=lease.source_ip, destination=lease.destination_id, protocol=lease.protocol, port=str(lease.port),
                    description=f"Lease {lease.id} for {lease.user_id}", origin="lease", lease_id=lease.id, policy_id=lease.policy_id,
                    position=500 + int(lease.id.split("-")[-1]) % 400, rule_id=lease.firewall_rule_id, created_by="nexus-lease-engine")


def request_access(ctx: Context, db: Session, *, user_id: str, device_id: str, destination: str, port: int, protocol: str = "TCP",
                   reason: str = "", duration_minutes: int | None = None, requested_by: str = "self") -> dict[str, Any]:
    decision = evaluate_access(ctx, db, user_id, device_id, destination, port, protocol)
    corr = new_id(db, "corr")
    ctx.bus.emit(db, "ACCESS_EVALUATED", f"Access {decision['decision']}: {user_id} {device_id} -> {destination}:{port} ({decision.get('summary', '')})",
                 severity="info" if decision["decision"] == "ALLOW" else "notice", source="policy-engine", target=device_id, user_id=user_id,
                 data={"decision": decision["decision"], "policy": decision.get("policy"), "destination": destination, "port": port},
                 correlation_id=corr)
    out: dict[str, Any] = {"decision": decision["decision"], "explanation": decision, "lease": None, "approval_id": None, "correlation_id": corr}
    if decision["decision"] == "ALLOW" and decision.get("lease"):
        existing = db.get(Lease, decision["lease"]["id"])
        if existing is not None:
            out["lease"] = lease_dict(ctx, existing)
        return out
    if decision["decision"] in ("ALLOW", "APPROVAL_REQUIRED"):
        minutes = min(int(duration_minutes or decision["lease_minutes"]), int(decision.get("max_lease_minutes") or decision["lease_minutes"]))
        now = ctx.clock.now()
        lease = Lease(id=new_id(db, "lease"), user_id=user_id.lower(), device_id=device_id.upper(), source_ip=decision.get("source_ip") or "",
                      destination_id=destination.upper(), protocol=protocol, port=port, reason=reason or "Administrative access",
                      policy_id=decision["policy"], status="PENDING_APPROVAL" if decision["decision"] == "APPROVAL_REQUIRED" else "PENDING",
                      firewall_state="NONE", risk_at_grant=int(decision.get("device_risk") or 0),
                      identity_confidence_at_grant=int(decision.get("identity_confidence") or 0), created_at=now,
                      expires_at=now + timedelta(minutes=minutes), correlation_id=corr)
        db.add(lease)
        db.flush()
        if decision["decision"] == "ALLOW":
            activate_lease(ctx, db, lease, actor="SYSTEM", reason=f"policy {decision['policy']} (requested by {requested_by})")
        else:
            approval = Approval(id=new_id(db, "approval"), kind="lease", title=f"Access lease {user_id} -> {destination}:{port}",
                                target=destination.upper(), lease_id=lease.id, category="HIGH_IMPACT", risk="MEDIUM",
                                reason=next((c["detail"] for c in decision["checks"] if c["status"] == "WARN"), decision.get("summary", "")),
                                required_role="ENGINEER", status="PENDING", requested_by=user_id.lower(), requested_at=now, correlation_id=corr)
            db.add(approval)
            lease.approval_id = approval.id
            out["approval_id"] = approval.id
            ctx.bus.emit(db, "APPROVAL_REQUESTED", f"{approval.id}: {approval.title} needs approval ({approval.reason})", severity="notice",
                         source="policy-engine", target=destination.upper(), user_id=user_id, data={"approval_id": approval.id, "kind": "lease"},
                         correlation_id=corr)
        out["lease"] = lease_dict(ctx, lease)
    record_audit(ctx, db, actor=requested_by, actor_type="OPERATOR", action=f"requested access {destination}:{port}/{protocol}",
                 reason=reason or "access request", target=device_id, result=decision["decision"], correlation_id=corr,
                 details={"policy": decision.get("policy"), "summary": decision.get("summary")})
    return out


def activate_lease(ctx: Context, db: Session, lease: Lease, actor: str, reason: str) -> Lease:
    spec = _spec(lease)
    try:
        rule_id = ctx.firewall.create_rule(db, spec)
        lease.firewall_rule_id = rule_id
        spec.rule_id = rule_id
        verified = ctx.firewall.verify_rule(db, spec)
        lease.firewall_state = "APPLIED" if verified else "FAILED"
        lease.status = "ACTIVE" if verified else "PENDING"
        ctx.bus.emit(db, "LEASE_CREATED", f"{lease.id} {lease.user_id}@{lease.device_id} -> {lease.destination_id}:{lease.port} until "
                     f"{lease.expires_at.astimezone(ctx.clock.site_tz).strftime('%H:%M')}", source="lease-engine", target=lease.device_id,
                     user_id=lease.user_id, data={"lease": lease.id, "policy": lease.policy_id}, correlation_id=lease.correlation_id)
        ctx.bus.emit(db, "FIREWALL_UPDATED", f"Rule {rule_id}: ALLOW {lease.source_ip} -> {lease.destination_id}:{lease.port}/{lease.protocol}",
                     source=ctx.firewall.name, target="PFSENSE", data={"rule_id": rule_id, "lease": lease.id}, correlation_id=lease.correlation_id)
        ctx.bus.emit(db, "VERIFICATION_PASSED" if verified else "VERIFICATION_FAILED", f"Firewall rule {rule_id} {'present with expected parameters' if verified else 'not found after apply'}",
                     severity="info" if verified else "high", source="verification-engine", target="PFSENSE", correlation_id=lease.correlation_id)
        result = "SUCCESS" if verified else "FAILED"
    except FirewallUnavailable as exc:
        lease.status = "PENDING"
        lease.firewall_state = "PENDING"
        ctx.bus.emit(db, "LEASE_CREATED", f"{lease.id} recorded; firewall update PENDING ({exc})", severity="warning", source="lease-engine",
                     target=lease.device_id, user_id=lease.user_id, data={"lease": lease.id, "firewall": "PENDING"}, correlation_id=lease.correlation_id)
        result = "PENDING"
    record_audit(ctx, db, actor=actor, actor_type="SYSTEM", action="created lease", reason=reason, target=lease.device_id, result=result,
                 correlation_id=lease.correlation_id, details={"lease": lease.id, "destination": f"{lease.destination_id}:{lease.port}"})
    return lease


def revoke_lease(ctx: Context, db: Session, lease_id: str, reason: str, actor: str, actor_type: str = "OPERATOR",
                 final_status: str = "REVOKED") -> Lease:
    lease = db.get(Lease, lease_id)
    if lease is None:
        raise KeyError(lease_id)
    if lease.status not in ("ACTIVE", "PENDING", "PENDING_APPROVAL"):
        return lease
    now = ctx.clock.now()
    result = "SUCCESS"
    if lease.firewall_rule_id and lease.firewall_state in ("APPLIED", "FAILED"):
        try:
            ctx.firewall.delete_rule(db, lease.firewall_rule_id)
            gone = ctx.firewall.verify_rule(db, _spec(lease), present=False)
            lease.firewall_state = "REMOVED" if gone else "FAILED"
            ctx.bus.emit(db, "FIREWALL_RECONCILIATION", f"Removed rule {lease.firewall_rule_id} for {lease.id}; absence {'verified' if gone else 'NOT verified'}",
                         severity="info" if gone else "high", source=ctx.firewall.name, target="PFSENSE", correlation_id=lease.correlation_id)
        except FirewallUnavailable:
            lease.firewall_state = "PENDING_REMOVAL"
            result = "PENDING"
    lease.status = final_status
    lease.ended_at = now
    lease.end_reason = reason
    event = "LEASE_EXPIRED" if final_status == "EXPIRED" else "LEASE_REVOKED"
    ctx.bus.emit(db, event, f"{lease.id} {final_status.lower()}: {reason}" + (" (firewall removal PENDING)" if result == "PENDING" else ""),
                 severity="notice", source="lease-engine", target=lease.device_id, user_id=lease.user_id, data={"lease": lease.id, "reason": reason},
                 correlation_id=lease.correlation_id)
    record_audit(ctx, db, actor=actor, actor_type=actor_type, action=f"{final_status.lower()} lease {lease.id}", reason=reason, target=lease.device_id,
                 result=result, correlation_id=lease.correlation_id)
    return lease


def expire_leases(ctx: Context, db: Session) -> list[str]:
    now = ctx.clock.now()
    expired = db.scalars(select(Lease).where(Lease.status == "ACTIVE", Lease.expires_at <= now)).all()
    for lease in expired:
        revoke_lease(ctx, db, lease.id, "lease duration elapsed", actor="SYSTEM", actor_type="SYSTEM", final_status="EXPIRED")
    return [x.id for x in expired]


def apply_pending(ctx: Context, db: Session) -> int:
    if not ctx.firewall.available():
        return 0
    count = 0
    for lease in db.scalars(select(Lease).where(Lease.status == "PENDING")).all():
        activate_lease(ctx, db, lease, actor="SYSTEM", reason="reconciliation after firewall recovery")
        count += 1
    for lease in db.scalars(select(Lease).where(Lease.firewall_state == "PENDING_REMOVAL")).all():
        if lease.firewall_rule_id:
            ctx.firewall.delete_rule(db, lease.firewall_rule_id)
        lease.firewall_state = "REMOVED"
        count += 1
    return count


def approve_lease(ctx: Context, db: Session, lease: Lease, approver: str) -> Lease:
    if lease.status != "PENDING_APPROVAL":
        return lease
    if lease.expires_at <= ctx.clock.now():
        lease.status = "EXPIRED"
        return lease
    lease.status = "PENDING"
    return activate_lease(ctx, db, lease, actor=approver, reason=f"approved by {approver}")


def enforce_risk_limits(ctx: Context, db: Session, device_id: str | None = None, user_id: str | None = None) -> list[str]:
    """Revoke active leases whose source device or user now exceeds the granting policy's risk threshold."""
    cache = ctx.policy_cache
    if cache is None:
        return []
    q = select(Lease).where(Lease.status == "ACTIVE")
    if device_id:
        q = q.where(Lease.device_id == device_id)
    if user_id:
        q = q.where(Lease.user_id == user_id)
    revoked = []
    policies = {d.metadata.id: d for d in cache.access}
    for lease in db.scalars(q).all():
        doc = policies.get(lease.policy_id or "")
        if doc is None:
            continue
        dev_risk, usr_risk = score_of(db, "device", lease.device_id), score_of(db, "user", lease.user_id)
        dev = db.get(Device, lease.device_id)
        reason = None
        if dev_risk > doc.spec.conditions.max_device_risk:
            reason = f"device risk {dev_risk} exceeds {doc.metadata.id} threshold {doc.spec.conditions.max_device_risk}"
        elif usr_risk > doc.spec.conditions.max_user_risk:
            reason = f"user risk {usr_risk} exceeds {doc.metadata.id} threshold {doc.spec.conditions.max_user_risk}"
        elif dev and dev.quarantined:
            reason = "source device quarantined"
        if reason:
            revoke_lease(ctx, db, lease.id, reason, actor="NEXUS", actor_type="AUTOHEAL")
            revoked.append(lease.id)
    return revoked


def revoke_for_session_end(ctx: Context, db: Session, user_id: str, device_id: str) -> list[str]:
    ids = []
    for lease in db.scalars(select(Lease).where(Lease.user_id == user_id, Lease.device_id == device_id,
                                                Lease.status.in_(("ACTIVE", "PENDING", "PENDING_APPROVAL")))).all():
        revoke_lease(ctx, db, lease.id, "AD session ended (lease is session-bound)", actor="SYSTEM", actor_type="SYSTEM")
        ids.append(lease.id)
    return ids


def user_name(db: Session, user_id: str) -> str:
    u = db.get(User, user_id)
    return u.display_name if u else user_id

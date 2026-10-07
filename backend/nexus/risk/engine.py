"""Deterministic, explainable risk scoring with trust decay.

risk = sum(factor points), capped to 0..100. Every factor carries its points, the rule that
produced it and the evidence. Weights are prototype values from policies/risk-rules.yaml.
Trust moves slowly: penalties are applied once per distinct cause and recover +1 per clean
reconciliation cycle, so a device that misbehaved does not look pristine five seconds later.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.models import Device, DriftEvent, Event, Incident, Lease, RiskEvent, RiskScore, User, UserGroup
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context

DEFAULT_RULES: dict[str, Any] = {
    "device": {
        "criticality": {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1},
        "identity": {"UNKNOWN": 40, "SUSPICIOUS": 25, "UNCERTAIN": 10, "VERIFIED": 2, "TRUSTED": 0},
        "drift": {"CRITICAL": 30, "SECURITY": 25, "OPERATIONAL": 8, "COSMETIC": 1}, "drift_cap": 45,
        "unexpected_service": 20, "unexpected_service_cap": 30,
        "admin_port_activity_unidentified": 25,
        "open_incident": {"P1": 15, "P2": 10, "P3": 5, "P4": 2}, "incident_cap": 20,
        "dhcp_conflict_claimant": 20, "dhcp_conflict_owner": 5,
        "failed_logins": [{"min": 10, "points": 25}, {"min": 5, "points": 15}],
        "privileged_session": 8, "admin_lease": 3, "admin_lease_cap": 9, "unmanaged": 10,
        "trust_penalty_factor": 0.3, "quarantine_containment": -25,
    },
    "user": {"failed_logins": [{"min": 10, "points": 35}, {"min": 5, "points": 20}, {"min": 3, "points": 10}],
             "privileged_group": 5, "session_on_low_confidence_device": 20, "active_lease": 2, "trust_penalty_factor": 0.3},
    "levels": [{"min": 80, "level": "CRITICAL"}, {"min": 60, "level": "HIGH"}, {"min": 30, "level": "MEDIUM"}, {"min": 0, "level": "LOW"}],
    "trust": {"verified_behavior": 1, "minor_anomaly": -5, "identity_mismatch": -15, "critical_incident": -30, "initial_known": 92,
              "initial_unknown": 40, "max": 100},
    "window_minutes": 15,
}


def rules(ctx: Context) -> dict[str, Any]:
    cache = ctx.policy_cache
    return cache.risk_rules if cache and cache.risk_rules else DEFAULT_RULES


def level_for(ctx: Context, score: int) -> str:
    for lv in rules(ctx)["levels"]:
        if score >= int(lv["min"]):
            return str(lv["level"])
    return "LOW"


def _score_row(ctx: Context, db: Session, entity_type: str, entity_id: str, known: bool = True) -> RiskScore:
    row = db.get(RiskScore, (entity_type, entity_id))
    if row is None:
        tr = rules(ctx)["trust"]
        row = RiskScore(entity_type=entity_type, entity_id=entity_id, score=0, level="LOW",
                        trust=int(tr["initial_known"] if known else tr["initial_unknown"]), factors=[], trust_marks=[],
                        updated_at=ctx.clock.now())
        db.add(row)
        db.flush()
    return row


def apply_trust(ctx: Context, db: Session, entity_type: str, entity_id: str, kind: str, mark: str, known: bool = True) -> None:
    """Apply a trust adjustment once per distinct mark (e.g. 'incident:INC-0007')."""
    row = _score_row(ctx, db, entity_type, entity_id, known)
    marks = list(row.trust_marks or [])
    if mark in marks:
        return
    marks.append(mark)
    row.trust_marks = marks[-50:]
    tr = rules(ctx)["trust"]
    row.trust = int(max(0, min(int(tr["max"]), row.trust + int(tr[kind]))))


def _recent(ctx: Context) -> Any:
    return ctx.clock.now() - timedelta(minutes=int(rules(ctx)["window_minutes"]))


def device_factors(ctx: Context, db: Session, dev: Device, row: RiskScore) -> list[dict[str, Any]]:
    r = rules(ctx)["device"]
    since = _recent(ctx)
    f: list[dict[str, Any]] = []

    def add(key: str, label: str, points: int, evidence: str) -> None:
        if points:
            f.append({"key": key, "label": label, "points": int(points), "evidence": evidence})

    add("criticality", "Asset exposure baseline", r["criticality"].get(dev.criticality, 1), f"{dev.criticality} criticality asset")
    add("identity", "Identity confidence", r["identity"].get(dev.identity_level, 0),
        f"{dev.identity_confidence}% ({dev.identity_level}) - prototype heuristic")
    drift_points = 0
    drifts = db.scalars(select(DriftEvent).where(DriftEvent.device_id == dev.id, DriftEvent.status.in_(("OPEN", "APPROVAL_REQUIRED", "REMEDIATING", "FAILED")))).all()
    for d in drifts:
        drift_points += r["drift"].get(d.classification, 5)
    if drifts:
        add("drift", "Open configuration drift", min(drift_points, r["drift_cap"]),
            ", ".join(f"{d.id} {d.component}.{d.key} ({d.classification})" for d in drifts[:4]))
    unexpected = sorted(set(map(int, dev.observed_ports or [])) - set(map(int, dev.expected_ports or [])))
    if unexpected:
        add("unexpected_service", "Unexpected listening service", min(len(unexpected) * r["unexpected_service"], r["unexpected_service_cap"]),
            "ports " + ", ".join(map(str, unexpected)) + " not in baseline")
    if dev.identity_confidence < 60:
        hits = db.scalar(select(func.count()).select_from(Event).where(Event.type == "PORT_ACTIVITY", Event.target == dev.id, Event.ts >= since))
        admin_hits = [e for e in db.scalars(select(Event).where(Event.type == "PORT_ACTIVITY", Event.target == dev.id, Event.ts >= since))
                      if (e.data or {}).get("admin_port")]
        if admin_hits:
            add("admin_port_activity", "Administrative protocol attempts from unidentified device", r["admin_port_activity_unidentified"],
                f"{len(admin_hits)} attempt(s), e.g. TCP/{admin_hits[-1].data.get('port')} -> {admin_hits[-1].data.get('dst')} ({hits} flows)")
    incidents = db.scalars(select(Incident).where(Incident.target == dev.id, Incident.status.in_(("OPEN", "INVESTIGATING")))).all()
    if incidents:
        pts = sum(r["open_incident"].get(i.priority, 2) for i in incidents)
        add("open_incident", "Open incidents on this asset", min(pts, r["incident_cap"]), ", ".join(f"{i.id} {i.priority}" for i in incidents[:3]))
    conflicts = db.scalars(select(Event).where(Event.type == "DHCP_CONFLICT", Event.ts >= since)).all()
    for c in conflicts:
        if (c.data or {}).get("claimant") == dev.id:
            add("dhcp_conflict", "Claims an address owned by another device", r["dhcp_conflict_claimant"], c.message)
            break
        if (c.data or {}).get("owner") == dev.id:
            add("dhcp_conflict_owner", "Address conflict on this device's IP", r["dhcp_conflict_owner"], c.message)
            break
    failures = db.scalar(select(func.count()).select_from(Event).where(Event.type == "AUTH_FAILURE", Event.target == dev.id, Event.ts >= since)) or 0
    for tier in r["failed_logins"]:
        if failures >= tier["min"]:
            add("failed_logins", "Authentication failures from this device", tier["points"], f"{failures} failures in {rules(ctx)['window_minutes']} min")
            break
    sessions = db.scalars(select(UserSession).where(UserSession.device_id == dev.id, UserSession.active.is_(True))).all()
    for s in sessions:
        if ctx.identity.privileged(db, s.user_id):
            add("privileged_session", "Privileged account logged on", r["privileged_session"], f"{s.user_id} (admin group member)")
            break
    leases = db.scalar(select(func.count()).select_from(Lease).where(Lease.device_id == dev.id, Lease.status == "ACTIVE")) or 0
    if leases:
        add("admin_leases", "Active administrative access leases", min(leases * r["admin_lease"], r["admin_lease_cap"]), f"{leases} active lease(s)")
    if not dev.managed:
        add("unmanaged", "Not a managed asset", r["unmanaged"], "no inventory or agent enrolment")
    trust_points = round((100 - row.trust) * r["trust_penalty_factor"])
    add("trust", "Trust deficit", trust_points, f"trust {row.trust}/100 (decays on anomalies, recovers +1 per clean cycle)")
    if dev.quarantined:
        add("containment", "Contained in quarantine VLAN 99", r["quarantine_containment"], dev.quarantine_reason or "quarantined")
    return f


def user_factors(ctx: Context, db: Session, user: User, row: RiskScore) -> list[dict[str, Any]]:
    r = rules(ctx)["user"]
    since = _recent(ctx)
    f: list[dict[str, Any]] = []
    failures = db.scalar(select(func.count()).select_from(Event).where(Event.type == "AUTH_FAILURE", Event.user_id == user.id, Event.ts >= since)) or 0
    for tier in r["failed_logins"]:
        if failures >= tier["min"]:
            f.append({"key": "failed_logins", "label": "Recent authentication failures", "points": tier["points"],
                      "evidence": f"{failures} failures in {rules(ctx)['window_minutes']} min"})
            break
    if ctx.identity.privileged(db, user.id):
        groups = [g for g in ctx.identity.groups_for(db, user.id) if g.endswith("ADMIN")]
        f.append({"key": "privileged_group", "label": "Member of privileged group", "points": r["privileged_group"], "evidence": ", ".join(groups)})
    for s in db.scalars(select(UserSession).where(UserSession.user_id == user.id, UserSession.active.is_(True))):
        dev = db.get(Device, s.device_id)
        if dev and dev.identity_confidence < 60:
            f.append({"key": "low_confidence_device", "label": "Session on low-confidence device", "points": r["session_on_low_confidence_device"],
                      "evidence": f"{dev.id} at {dev.identity_confidence}%"})
            break
    leases = db.scalar(select(func.count()).select_from(Lease).where(Lease.user_id == user.id, Lease.status == "ACTIVE")) or 0
    if leases:
        f.append({"key": "active_leases", "label": "Active access leases", "points": leases * r["active_lease"], "evidence": f"{leases} lease(s)"})
    trust_points = round((100 - row.trust) * r["trust_penalty_factor"])
    if trust_points:
        f.append({"key": "trust", "label": "Trust deficit", "points": trust_points, "evidence": f"trust {row.trust}/100"})
    return f


def _store(ctx: Context, db: Session, row: RiskScore, factors: list[dict[str, Any]], reason: str, correlation_id: str | None) -> bool:
    score = int(max(0, min(100, sum(x["points"] for x in factors))))
    old = row.score
    row.factors = factors
    row.updated_at = ctx.clock.now()
    if score == old and row.level == level_for(ctx, score):
        return False
    row.score = score
    row.level = level_for(ctx, score)
    db.add(RiskEvent(ts=ctx.clock.now(), entity_type=row.entity_type, entity_id=row.entity_id, old_score=old, new_score=score,
                     reason=reason[:256], trust=row.trust, correlation_id=correlation_id))
    severity = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "warning"}.get(row.level, "info")
    ctx.bus.emit(db, "RISK_CHANGED", f"{row.entity_id} risk {old} -> {score} ({row.level}): {reason}", severity=severity,
                 target=row.entity_id if row.entity_type == "device" else None,
                 user_id=row.entity_id if row.entity_type == "user" else None,
                 data={"entity_type": row.entity_type, "old": old, "new": score, "level": row.level, "reason": reason},
                 correlation_id=correlation_id)
    return True


def recompute_device(ctx: Context, db: Session, dev: Device, reason: str, correlation_id: str | None = None,
                     evaluate_policy: bool = True) -> RiskScore:
    row = _score_row(ctx, db, "device", dev.id, known=dev.managed)
    if dev.identity_level in ("SUSPICIOUS", "UNKNOWN"):
        apply_trust(ctx, db, "device", dev.id, "identity_mismatch", f"identity:{dev.identity_level}", dev.managed)
    for inc in db.scalars(select(Incident).where(Incident.target == dev.id, Incident.priority.in_(("P1", "P2")),
                                                Incident.status.in_(("OPEN", "INVESTIGATING")), Incident.category == "SECURITY")):
        apply_trust(ctx, db, "device", dev.id, "critical_incident", f"incident:{inc.id}", dev.managed)
    changed = _store(ctx, db, row, device_factors(ctx, db, dev, row), reason, correlation_id)
    if changed and evaluate_policy:
        from nexus.leases.engine import enforce_risk_limits
        from nexus.policy.security import evaluate_security_policies

        enforce_risk_limits(ctx, db, device_id=dev.id)
        evaluate_security_policies(ctx, db, dev, correlation_id)
    return row


def recompute_user(ctx: Context, db: Session, user: User, reason: str, correlation_id: str | None = None) -> RiskScore:
    row = _score_row(ctx, db, "user", user.id)
    changed = _store(ctx, db, row, user_factors(ctx, db, user, row), reason, correlation_id)
    if changed:
        from nexus.leases.engine import enforce_risk_limits

        enforce_risk_limits(ctx, db, user_id=user.id)
    return row


def recompute_all(ctx: Context, db: Session, reason: str = "periodic reconciliation", recover_trust: bool = True) -> None:
    for dev in db.scalars(select(Device)).all():
        row = _score_row(ctx, db, "device", dev.id, known=dev.managed)
        if recover_trust:
            anomalies = {"identity", "drift", "unexpected_service", "admin_port_activity", "open_incident", "dhcp_conflict", "failed_logins"}
            if not any(x["key"] in anomalies and x["points"] > 2 for x in (row.factors or [])):
                tr = rules(ctx)["trust"]
                row.trust = min(int(tr["max"]), row.trust + int(tr["verified_behavior"]))
        recompute_device(ctx, db, dev, reason)
    for user in db.scalars(select(User)).all():
        recompute_user(ctx, db, user, reason)


def score_of(db: Session, entity_type: str, entity_id: str) -> int:
    row = db.get(RiskScore, (entity_type, entity_id))
    return row.score if row else 0


def global_risk(db: Session) -> int:
    scores = sorted((r.score for r in db.scalars(select(RiskScore).where(RiskScore.entity_type == "device"))), reverse=True)
    if not scores:
        return 0
    top = scores[:3]
    return round(0.6 * top[0] + 0.4 * (sum(top) / len(top)))


def users_in_group(db: Session, group: str) -> list[str]:
    return list(db.scalars(select(UserGroup.user_id).where(UserGroup.group_id == group)))

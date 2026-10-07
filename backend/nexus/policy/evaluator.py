"""Access decisions (identity + group + policy + risk + time + system state). The same evaluator
powers lease creation and "Why can X access Y?" explanations, so explanations are never invented."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, IpAddress, Lease, User
from nexus.models import Session as UserSession
from nexus.policy.schema import AccessPolicyDoc, Grant, Schedule
from nexus.risk.engine import score_of

if TYPE_CHECKING:
    from nexus.core.context import Context

DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def schedule_status(ctx: Context, schedule: Schedule | None) -> tuple[bool, str]:
    if schedule is None or not schedule.windows:
        return True, "no time restriction"
    now = ctx.clock.site_now()
    day, hm = DAY_NAMES[now.weekday()], now.strftime("%H:%M")
    labels = []
    for w in schedule.windows:
        label = f"{w.days[0].title()}-{w.days[-1].title()} {w.start}-{w.end}" if len(w.days) > 1 else f"{w.days[0].title()} {w.start}-{w.end}"
        labels.append(label)
        if day in w.days and w.start <= hm < w.end:
            return True, f"inside {label} (site time {day.title()} {hm})"
    return False, f"outside {', '.join(labels)} (site time {day.title()} {hm})"


def _grant_matches(grant: Grant, destination: str, port: int, protocol: str) -> bool:
    return (destination in grant.destinations or "ANY" in grant.destinations) and port in grant.ports and grant.protocol in (protocol, "ANY")


def evaluate_access(ctx: Context, db: Session, user_id: str, device_id: str, destination: str, port: int,
                    protocol: str = "TCP") -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    result: dict[str, Any] = {"user_id": user_id, "device_id": device_id, "destination": destination, "port": port, "protocol": protocol,
                              "decision": "DENY", "policy": None, "policy_threshold": None, "lease": None, "lease_minutes": None,
                              "checks": checks, "evaluated_at": ctx.clock.now().isoformat()}

    def check(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    def finish(decision: str, summary: str) -> dict[str, Any]:
        result["decision"] = decision
        result["summary"] = summary
        result["narrative"] = narrative(result)
        return result

    user = db.get(User, user_id.lower())
    dev = db.get(Device, device_id.upper())
    dst = db.get(Device, destination.upper())
    if user is None or not user.enabled:
        check("User", "FAIL", f"{user_id} not found or disabled in directory")
        return finish("DENY", "unknown or disabled user")
    result["user"] = {"id": user.id, "name": user.display_name}
    groups = ctx.identity.groups_for(db, user.id)
    result["groups"] = groups
    check("User", "PASS", f"{user.display_name} ({', '.join(groups) or 'no groups'})")
    if dev is None or dst is None:
        check("Devices", "FAIL", "source device or destination unknown")
        return finish("DENY", "unknown device")
    ip = db.scalar(select(IpAddress.address).where(IpAddress.device_id == dev.id))
    result.update({"source_ip": ip, "identity_confidence": dev.identity_confidence, "identity_level": dev.identity_level,
                   "device_risk": score_of(db, "device", dev.id), "user_risk": score_of(db, "user", user.id)})
    session = db.scalar(select(UserSession).where(UserSession.user_id == user.id, UserSession.device_id == dev.id, UserSession.active.is_(True)))
    if session is None:
        check("Session", "FAIL", f"no active AD session for {user.id} on {dev.id}")
        return finish("DENY", f"{user.id} is not authenticated on {dev.id}")
    check("Session", "PASS", f"{user.id} authenticated on {dev.id} since {session.started_at.strftime('%H:%M')} ({ip})")
    if dev.quarantined:
        check("Quarantine", "FAIL", f"{dev.id} is quarantined: {dev.quarantine_reason}")
        return finish("DENY", "source device is quarantined")
    cache = ctx.policy_cache
    for doc in cache.access:
        if not set(groups) & set(doc.spec.subjects.groups):
            continue
        for deny in doc.spec.denies:
            if (dst.id in deny.destinations or "ANY" in deny.destinations) and port in deny.ports:
                check("Explicit deny", "FAIL", f"{doc.metadata.id}: {deny.reason or 'deny rule'}")
                result["policy"] = doc.metadata.id
                return finish("DENY", f"explicitly denied by {doc.metadata.id}")
    match: tuple[AccessPolicyDoc, Grant] | None = None
    for doc in cache.access:
        if set(groups) & set(doc.spec.subjects.groups):
            grant = next((g for g in doc.spec.grants if _grant_matches(g, dst.id, port, protocol)), None)
            if grant:
                match = (doc, grant)
                break
    if match is None:
        check("Policy", "FAIL", f"no access policy grants {protocol}/{port} on {dst.id} to {', '.join(groups) or 'these groups'}")
        return finish("DENY", "no matching grant")
    doc, grant = match
    cond = doc.spec.conditions
    result.update({"policy": doc.metadata.id, "policy_threshold": cond.max_device_risk, "lease_minutes": grant.lease_minutes,
                   "max_lease_minutes": grant.max_lease_minutes or grant.lease_minutes})
    check("Policy", "PASS", f"{doc.metadata.id} grants {protocol}/{port} on {dst.id} to {', '.join(set(groups) & set(doc.spec.subjects.groups))}")
    constraints = cache.server_baseline.get("access_constraints", {})
    key = {22: "ssh_allowed_groups", 3389: "rdp_allowed_groups"}.get(port)
    if key and constraints.get(key) is not None and not set(groups) & set(constraints[key]):
        check("Baseline constraint", "FAIL", f"POL-SERVER-BASELINE {key} excludes {', '.join(groups)}")
        return finish("DENY", "server baseline constraint")
    failed = False
    if dev.identity_confidence >= cond.min_identity_confidence:
        check("Identity", "PASS", f"{dev.identity_confidence}% ({dev.identity_level}) >= {cond.min_identity_confidence}%")
    else:
        check("Identity", "FAIL", f"{dev.identity_confidence}% < required {cond.min_identity_confidence}%")
        failed = True
    if result["device_risk"] <= cond.max_device_risk:
        check("Device risk", "PASS", f"{result['device_risk']} <= threshold {cond.max_device_risk}")
    else:
        check("Device risk", "FAIL", f"{result['device_risk']} > threshold {cond.max_device_risk}")
        failed = True
    if result["user_risk"] <= cond.max_user_risk:
        check("User risk", "PASS", f"{result['user_risk']} <= threshold {cond.max_user_risk}")
    else:
        check("User risk", "FAIL", f"{result['user_risk']} > threshold {cond.max_user_risk}")
        failed = True
    if cond.source_vlans and dev.vlan_id not in cond.source_vlans:
        check("Source VLAN", "FAIL", f"VLAN {dev.vlan_id} not in {cond.source_vlans}")
        failed = True
    elif cond.source_vlans:
        check("Source VLAN", "PASS", f"VLAN {dev.vlan_id}")
    if cond.device_kinds and dev.kind not in cond.device_kinds:
        check("Device type", "FAIL", f"{dev.kind} not in {cond.device_kinds}")
        failed = True
    if failed:
        return finish("DENY", "policy conditions not met")
    existing = db.scalar(select(Lease).where(Lease.user_id == user.id, Lease.device_id == dev.id, Lease.destination_id == dst.id,
                                             Lease.port == port, Lease.status == "ACTIVE"))
    if existing:
        result["lease"] = {"id": existing.id, "expires_at": existing.expires_at.isoformat(), "firewall_state": existing.firewall_state}
        check("Lease", "PASS", f"{existing.id} ACTIVE until {existing.expires_at.astimezone(ctx.clock.site_tz).strftime('%H:%M')}")
    in_window, window = schedule_status(ctx, doc.spec.schedule)
    result["schedule"] = window
    if not ctx.firewall.available():
        check("Firewall", "FAIL", "pfSense API unavailable - new privileged leases are blocked until reconciliation")
        if existing:
            return finish("ALLOW", "existing lease preserved while firewall is degraded")
        return finish("BLOCKED", "firewall control plane unavailable")
    if existing:
        return finish("ALLOW", f"active lease {existing.id}")
    if not in_window:
        outside = doc.spec.schedule.outside if doc.spec.schedule else "approval_required"
        check("Schedule", "WARN" if outside == "approval_required" else "FAIL", window)
        return finish("APPROVAL_REQUIRED" if outside == "approval_required" else "DENY", "outside permitted hours")
    check("Schedule", "PASS", window)
    if grant.approval == "always":
        check("Approval", "WARN", f"{doc.metadata.id} requires human approval for {dst.id}:{port}")
        return finish("APPROVAL_REQUIRED", "grant requires approval")
    return finish("ALLOW", f"granted by {doc.metadata.id}")


def narrative(r: dict[str, Any]) -> str:
    who = r.get("user", {}).get("name", r["user_id"])
    target = f"{r['destination']}:{r['port']}"
    failed = [c for c in r["checks"] if c["status"] == "FAIL"]
    if r["decision"] == "ALLOW":
        lease = f" through lease {r['lease']['id']}" if r.get("lease") else ""
        return (f"{who} can access {target} from {r['device_id']}{lease}. {r['policy']} grants this to "
                f"{', '.join(r.get('groups', []))}; identity confidence is {r.get('identity_confidence')}% and device risk "
                f"{r.get('device_risk')} is within the policy threshold of {r.get('policy_threshold')}.")
    if r["decision"] == "APPROVAL_REQUIRED":
        reason = next((c["detail"] for c in r["checks"] if c["status"] == "WARN"), r.get("summary", ""))
        return f"{who} may access {target} only after human approval: {reason}."
    if r["decision"] == "BLOCKED":
        return f"Access to {target} is temporarily blocked: the firewall API is unavailable, so NEXUS will not create new privileged leases."
    reason = failed[0]["detail"] if failed else r.get("summary", "")
    return f"{who} cannot access {target} from {r['device_id']}: {reason}."

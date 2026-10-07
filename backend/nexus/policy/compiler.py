"""Network policy compiler: YAML -> schema validation -> normalization -> conflict detection ->
impact analysis -> risk analysis -> firewall rule generation -> verification."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.store import get_setting
from nexus.firewall.addressing import Resolver, evaluate, shadow_analysis
from nexus.firewall.base import RuleSpec
from nexus.models import Device, Group, IpAddress, Lease, UserGroup
from nexus.models import Session as UserSession
from nexus.policy.cache import PolicyCache, build_cache
from nexus.policy.schema import AccessPolicyDoc

if TYPE_CHECKING:
    from nexus.core.context import Context

ADMIN_PORTS = {22, 3389, 5985, 5986, 443}


def device_ips(db: Session) -> dict[str, str]:
    return {str(r.device_id): r.address for r in db.scalars(select(IpAddress).where(IpAddress.device_id.is_not(None)))}


def group_ips(ctx: Context, db: Session) -> dict[str, list[str]]:
    ips = device_ips(db)
    out: dict[str, list[str]] = {}
    for s in db.scalars(select(UserSession).where(UserSession.active.is_(True))):
        ip = ips.get(s.device_id)
        if not ip:
            continue
        for g in ctx.identity.groups_for(db, s.user_id):
            out.setdefault(g, []).append(ip)
    return out


def resolver(ctx: Context, db: Session, cache: PolicyCache | None = None, analysis: bool = False) -> Resolver:
    cache = cache or ctx.policy_cache
    aliases = dict(cache.firewall.spec.aliases) if cache and cache.firewall else {}
    groups = [g.id for g in db.scalars(select(Group))]
    return Resolver(aliases=aliases, group_ips=group_ips(ctx, db), device_ips=device_ips(db),
                    group_fallback={g: ["NET_USERS"] for g in groups}, analysis=analysis)


def _position(rule_id: str, default: int) -> int:
    m = re.search(r"(\d+)$", rule_id)
    return int(m.group(1)) if m else default


def baseline_specs(cache: PolicyCache) -> list[RuleSpec]:
    if not cache.firewall:
        return []
    return [RuleSpec(action=r.action, source=r.source, destination=r.destination, protocol=r.protocol, port=str(r.port).upper(),
                     description=r.description, origin="baseline", policy_id=cache.firewall.metadata.id,
                     position=_position(r.id, 100), rule_id=r.id) for r in cache.firewall.spec.rules]


def positions(cache: PolicyCache) -> dict[str, int]:
    base = {"quarantine": 30, "nexus_blocks": 90, "policy_denies": 200, "leases": 500}
    if cache.firewall:
        base.update(cache.firewall.spec.positions)
    return base


def policy_deny_specs(cache: PolicyCache) -> list[RuleSpec]:
    specs, pos = [], positions(cache)["policy_denies"]
    for doc in cache.access:
        for i, deny in enumerate(doc.spec.denies):
            for group in doc.spec.subjects.groups:
                for dest in deny.destinations:
                    pos += 1
                    specs.append(RuleSpec(action="DENY", source=f"GRP:{group}", destination=dest, protocol=deny.protocol,
                                          port=",".join(str(p) for p in deny.ports), description=deny.reason or f"{doc.metadata.id} deny",
                                          origin="policy", policy_id=doc.metadata.id, position=pos,
                                          rule_id=f"FW-{doc.metadata.id}-D{i + 1}{'' if len(doc.spec.subjects.groups) == 1 else '-' + group}"))
    return specs


def lease_specs(db: Session, base_position: int = 500) -> list[RuleSpec]:
    out = []
    for lease in db.scalars(select(Lease).where(Lease.status == "ACTIVE")):
        out.append(RuleSpec(action="ALLOW", source=lease.source_ip, destination=lease.destination_id, protocol=lease.protocol,
                            port=str(lease.port), description=f"Lease {lease.id} for {lease.user_id}", origin="lease",
                            lease_id=lease.id, policy_id=lease.policy_id, position=base_position + int(lease.id.split("-")[-1]) % 400,
                            rule_id=lease.firewall_rule_id))
    return out


def nexus_block_specs(db: Session) -> list[RuleSpec]:
    return [RuleSpec(**b) for b in (get_setting(db, "firewall_nexus_blocks") or [])]


def desired_firewall(ctx: Context, db: Session, cache: PolicyCache | None = None) -> list[RuleSpec]:
    cache = cache or ctx.policy_cache
    return baseline_specs(cache) + policy_deny_specs(cache) + nexus_block_specs(db) + lease_specs(db, positions(cache)["leases"])


def _overlap(a: list[Any], b: list[Any]) -> bool:
    return "ANY" in a or "ANY" in b or bool(set(a) & set(b))


def compile_policy_set(ctx: Context, db: Session, overrides: dict[str, str] | None = None) -> dict[str, Any]:
    cache = build_cache(db, overrides)
    stages: list[dict[str, Any]] = []
    errors = list(cache.errors)
    stages.append({"name": "Schema validation", "status": "failed" if errors else "passed",
                   "messages": errors or [f"{len(cache.docs)} documents valid"]})

    groups = {g.id for g in db.scalars(select(Group))}
    devices = {d.id for d in db.scalars(select(Device))}
    norm_msgs: list[str] = []
    for doc in cache.access:
        for g in doc.spec.subjects.groups:
            if g not in groups:
                errors.append(f"{doc.metadata.id}: unknown group {g}")
        for grant in doc.spec.grants:
            for dest in grant.destinations:
                if dest != "ANY" and dest not in devices:
                    errors.append(f"{doc.metadata.id}: unknown destination {dest}")
            if grant.max_lease_minutes and grant.lease_minutes > grant.max_lease_minutes:
                errors.append(f"{doc.metadata.id}: lease_minutes exceeds max_lease_minutes")
        norm_msgs.append(f"{doc.metadata.id}: {len(doc.spec.grants)} grant(s), {len(doc.spec.denies)} deny rule(s), "
                         f"subjects {', '.join(doc.spec.subjects.groups)}")
    stages.append({"name": "Normalization", "status": "failed" if len(errors) > len(cache.errors) else "passed", "messages": norm_msgs})

    conflicts: list[dict[str, Any]] = []
    constraints = cache.server_baseline.get("access_constraints", {})
    for a in cache.access:
        for grant in a.spec.grants:
            for port, key in ((22, "ssh_allowed_groups"), (3389, "rdp_allowed_groups")):
                allowed = constraints.get(key)
                if allowed is not None and port in grant.ports:
                    bad = [g for g in a.spec.subjects.groups if g not in allowed]
                    if bad:
                        conflicts.append({"kind": "BASELINE_CONSTRAINT", "blocking": True, "policies": [a.metadata.id, "POL-SERVER-BASELINE"],
                                          "detail": f"{a.metadata.id} grants TCP/{port} to {', '.join(bad)} but POL-SERVER-BASELINE "
                                                    f"{key} = {', '.join(allowed)}"})
            for b in cache.access:
                if not set(a.spec.subjects.groups) & set(b.spec.subjects.groups):
                    continue
                for deny in b.spec.denies:
                    if _overlap(grant.destinations, deny.destinations) and set(grant.ports) & set(deny.ports):
                        conflicts.append({"kind": "GRANT_DENY_OVERLAP", "blocking": False, "policies": [a.metadata.id, b.metadata.id],
                                          "detail": f"{a.metadata.id} grants and {b.metadata.id} denies ports "
                                                    f"{sorted(set(grant.ports) & set(deny.ports))}; explicit deny wins"})
    stages.append({"name": "Conflict detection", "status": "failed" if any(c["blocking"] for c in conflicts) else ("warning" if conflicts else "passed"),
                   "messages": [c["detail"] for c in conflicts] or ["no conflicts"]})

    users: set[str] = set()
    for doc in cache.access:
        for g in doc.spec.subjects.groups:
            users |= set(db.scalars(select(UserGroup.user_id).where(UserGroup.group_id == g)))
    pol_ids = [d.metadata.id for d in cache.access]
    leases = db.scalars(select(Lease).where(Lease.status == "ACTIVE", Lease.policy_id.in_(pol_ids))).all()
    impact = {"users": sorted(users), "user_count": len(users), "access_policies": len(cache.access), "active_leases": [x.id for x in leases],
              "destinations": sorted({d for doc in cache.access for g in doc.spec.grants for d in g.destinations})}
    stages.append({"name": "Impact analysis", "status": "passed",
                   "messages": [f"{len(users)} user(s) covered, {len(leases)} active lease(s) under these policies"]})

    risk_rows: list[dict[str, Any]] = []
    for doc in cache.access:
        score = 0
        notes = []
        for grant in doc.spec.grants:
            admin = sorted(set(grant.ports) & ADMIN_PORTS)
            if admin:
                score += 10 * len(admin)
                notes.append(f"administrative ports {admin}")
            if "ANY" in grant.destinations:
                score += 20
                notes.append("ANY destination")
            if grant.lease_minutes > 240:
                score += 10
                notes.append(f"long lease {grant.lease_minutes} min")
        if doc.spec.schedule is None and score:
            score += 5
            notes.append("no time restriction")
        risk_rows.append({"policy": doc.metadata.id, "score": min(100, score), "notes": notes})
    stages.append({"name": "Risk analysis", "status": "passed",
                   "messages": [f"{r['policy']}: {r['score']}" + (f" ({'; '.join(r['notes'])})" if r["notes"] else "") for r in risk_rows]})

    generated = baseline_specs(cache) + policy_deny_specs(cache)
    stages.append({"name": "Firewall rule generation", "status": "passed",
                   "messages": [f"{len(generated)} rules generated ({len(policy_deny_specs(cache))} from access-policy denies)"]})

    rules: list[dict[str, Any]] = [{"id": s.rule_id or f"GEN-{i}", "position": s.position, "action": s.action, "source": s.source, "destination": s.destination,
              "protocol": s.protocol, "port": s.port, "origin": s.origin, "enabled": True} for i, s in enumerate(generated + lease_specs(db))]
    analysis = resolver(ctx, db, cache, analysis=True)
    shadowed = shadow_analysis(analysis, rules)
    verify_msgs, verify_failed = [], False
    last = sorted(rules, key=lambda r: r["position"])[-1] if rules else None
    if last and last["action"] == "DENY" and last["source"] == "ANY" and last["destination"] == "ANY":
        verify_msgs.append("default deny is the final rule")
    else:
        verify_failed = True
        verify_msgs.append("ruleset does not end with default deny")
    mgmt = cache.firewall.spec.management_path if cache.firewall else {}
    if mgmt:
        ips = device_ips(db)
        live = resolver(ctx, db, cache)
        action, rule = evaluate(live, rules, mgmt.get("source"), ips.get(mgmt.get("destination", ""), mgmt.get("destination")),
                                mgmt.get("protocol", "TCP"), int(mgmt.get("port", 443)))
        if action == "ALLOW":
            verify_msgs.append(f"management path {mgmt.get('source')} -> {mgmt.get('destination')}:{mgmt.get('port')} preserved by {rule['id'] if rule else '?'} (lockout protection)")
        else:
            verify_failed = True
            verify_msgs.append("management path would be blocked - change rejected (lockout protection)")
    keys = [(r["action"], r["source"], r["destination"], r["protocol"], r["port"]) for r in rules]
    if len(keys) != len(set(keys)):
        verify_msgs.append("duplicate rules detected")
    verify_msgs += [s["message"] for s in shadowed]
    stages.append({"name": "Verification", "status": "failed" if verify_failed else ("warning" if shadowed else "passed"), "messages": verify_msgs})

    ok = not errors and not any(c["blocking"] for c in conflicts) and not verify_failed
    return {"ok": ok, "stages": stages, "errors": errors, "conflicts": conflicts, "shadowed": shadowed,
            "generated_rules": [s.as_dict() for s in generated], "impact": impact, "risk": risk_rows,
            "policies": sorted(cache.docs), "compiled_at": ctx.clock.now().isoformat()}


def access_policies(cache: PolicyCache) -> list[AccessPolicyDoc]:
    return list(cache.access)

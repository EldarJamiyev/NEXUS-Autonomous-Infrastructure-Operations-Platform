"""Devices, users, identity, network topology (digital twin), firewall and dependencies."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from nexus.api.deps import Principal, current_principal, get_ctx, limited, require
from nexus.api.serializers import device_brief, network_context, risk_of, user_brief
from nexus.core.context import Context
from nexus.models import (
    ConfigItem,
    Device,
    DriftEvent,
    Event,
    Group,
    Incident,
    Interface,
    Lease,
    MacAddress,
    RemediationTransaction,
    Service,
    User,
    UserGroup,
    Vlan,
)
from nexus.models import Session as UserSession

router = APIRouter(prefix="/api", tags=["inventory"])


@router.get("/devices")
async def devices(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [device_brief(db, d) for d in db.scalars(select(Device).order_by(Device.kind, Device.id))]


@router.get("/devices/{device_id}")
async def device(device_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.drift.engine import desired_config, drift_dict, normalize, render, unified_diff
    from nexus.incidents.engine import incident_dict
    from nexus.leases.engine import lease_dict

    with ctx.session() as db:
        d = db.get(Device, device_id.upper())
        if d is None:
            raise KeyError(f"device {device_id} not found")
        services = [{"id": s.id, "name": s.name, "display_name": s.display_name, "status": s.status, "enabled": s.enabled, "ports": s.ports,
                     "criticality": s.criticality, "rto": s.rto_minutes, "rpo": s.rpo_minutes, "detail": s.health_detail}
                    for s in db.scalars(select(Service).where(Service.device_id == d.id))]
        config = []
        for item in db.scalars(select(ConfigItem).where(ConfigItem.device_id == d.id)):
            if item.component in ("host_files", "switchports"):
                continue
            desired = desired_config(ctx, d.id, item.component)
            actual = normalize(item.component, item.actual)
            from nexus.drift.engine import config_matches, desired_flat

            ok, want_sum, have_sum = config_matches(ctx, db, d.id, item.component)
            want = desired_flat(item.component, desired) if desired else None
            config.append({"component": item.component, "actual": actual, "desired": want, "matches": ok if desired else None,
                           "desired_checksum": want_sum, "actual_checksum": have_sum, "native": item.actual, "updated_by": item.updated_by,
                           "updated_at": item.updated_at.isoformat(), "rendered": "\n".join(render(item.component, actual)),
                           "diff": unified_diff(item.component, {k: actual.get(k) for k in want}, want, d.id) if want and not ok else ""})
        incidents = db.scalars(select(Incident).where(Incident.target == d.id).order_by(Incident.created_at.desc()).limit(25)).all()
        events = db.scalars(select(Event).where(Event.target == d.id, Event.type != "AUTH_FAILURE").order_by(Event.id.desc()).limit(60)).all()
        txs = db.scalars(select(RemediationTransaction).where(RemediationTransaction.target == d.id).order_by(RemediationTransaction.created_at.desc())).all()
        drift = db.scalars(select(DriftEvent).where(DriftEvent.device_id == d.id).order_by(DriftEvent.detected_at.desc()).limit(30)).all()
        sessions = db.scalars(select(UserSession).where(UserSession.device_id == d.id).order_by(UserSession.started_at.desc()).limit(10)).all()
        leases = db.scalars(select(Lease).where((Lease.device_id == d.id) | (Lease.destination_id == d.id)).order_by(Lease.created_at.desc()).limit(15)).all()
        last_change = db.scalar(select(Event).where(Event.target == d.id, Event.type == "CONFIG_CHANGED").order_by(Event.ts.desc()))
        open_drift = [x for x in drift if x.status in ("OPEN", "APPROVAL_REQUIRED", "REMEDIATING", "FAILED")]
        memory = {"previous_incidents": len(incidents), "drift_events": len(drift),
                  "ssh_drift": sum(1 for x in drift if x.component == "ssh"),
                  "successful_remediations": sum(1 for t in txs if t.result == "SUCCESS"), "failed_remediations": sum(1 for t in txs if t.result == "FAILED"),
                  "last_change": last_change.ts.isoformat() if last_change else None, "last_change_by": (last_change.data or {}).get("actor") if last_change else None,
                  "current_state": "NON-COMPLIANT" if open_drift else "COMPLIANT"}
        return {**device_brief(db, d), "description": d.description, "network": network_context(db, d), "services": services,
                "risk_detail": risk_of(db, "device", d.id), "identity": {"confidence": d.identity_confidence, "level": d.identity_level,
                                                                          "signals": (d.identity_signals or {}).get("signals", []),
                                                                          "note": "Configurable prototype heuristic (policies/identity-confidence.yaml)"},
                "config": config, "drift": [drift_dict(x) for x in drift], "incidents": [incident_dict(i, brief=True) for i in incidents],
                "events": [{"id": e.id, "ts": e.ts.isoformat(), "type": e.type, "severity": e.severity, "message": e.message, "source": e.source} for e in events],
                "remediations": [{"id": t.id, "action": t.action_name, "status": t.status, "result": t.result, "created_at": t.created_at.isoformat()} for t in txs[:15]],
                "sessions": [{"user": s.user_id, "active": s.active, "since": s.started_at.isoformat(), "ended": s.ended_at.isoformat() if s.ended_at else None} for s in sessions],
                "leases": [lease_dict(ctx, x) for x in leases], "memory": memory, "quarantine_reason": d.quarantine_reason,
                "first_seen": d.first_seen.isoformat()}


@router.post("/devices/{device_id}/quarantine", dependencies=[Depends(limited("sensitive"))])
async def quarantine(device_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.decision import plan_action

    with ctx.session() as db:
        if db.get(Device, device_id.upper()) is None:
            raise KeyError(f"device {device_id} not found")
        return plan_action(ctx, db, action_id="REM-NET-QUARANTINE", target=device_id.upper(), params={"vlan": 99},
                           trigger=f"manual quarantine requested by {p.user_id}", evidence=[f"operator request by {p.name}"], requested_by=p.user_id)


@router.post("/devices/{device_id}/release", dependencies=[Depends(limited("sensitive"))])
async def release(device_id: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.core.decision import plan_action

    with ctx.session() as db:
        return plan_action(ctx, db, action_id="REM-NET-RELEASE-QUARANTINE", target=device_id.upper(), params={},
                           trigger=f"quarantine release reviewed by {p.user_id}", evidence=[f"human review by {p.name}"], requested_by=p.user_id)


@router.post("/devices/{device_id}/healthcheck")
async def healthcheck(device_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        d = db.get(Device, device_id.upper())
        if d is None:
            raise KeyError(f"device {device_id} not found")
        checks = [{"probe": "reachability", "passed": d.reachable, "detail": "ICMP/ARP response" if d.reachable else "no response"}]
        for s in db.scalars(select(Service).where(Service.device_id == d.id)):
            checks.append(ctx.probes.check(db, d.id, {"probe": "service_running", "service": s.name}) | {"service": s.id})
            for port in s.ports[:2]:
                checks.append(ctx.probes.check(db, d.id, {"probe": "tcp", "port": int(port)}) | {"service": s.id})
        return {"device": d.id, "checks": checks, "healthy": all(c["passed"] for c in checks), "at": ctx.clock.now().isoformat()}


@router.post("/devices/{device_id}/services/{service}/restart", dependencies=[Depends(limited("sensitive"))])
async def restart_service(device_id: str, service: str, ctx: Context = Depends(get_ctx), p: Principal = Depends(require("ENGINEER"))) -> dict[str, Any]:
    from nexus.core.decision import plan_action
    from nexus.incidents.engine import SERVICE_ACTIONS

    action = SERVICE_ACTIONS.get(service)
    if action is None:
        raise ValueError(f"no restart action in the catalog for {service}")
    with ctx.session() as db:
        return plan_action(ctx, db, action_id=action, target=device_id.upper(), params={}, trigger=f"manual restart of {service} by {p.user_id}",
                           evidence=[f"operator request by {p.name}"], requested_by=p.user_id)


@router.post("/devices/{device_id}/compare")
async def compare(device_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(require("OPERATOR"))) -> dict[str, Any]:
    from nexus.drift.engine import device_diffs

    with ctx.session() as db:
        diffs = device_diffs(ctx, db, device_id.upper())
        return {"device": device_id.upper(), "compliant": not diffs, "differences": diffs}


@router.get("/users")
async def users(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [user_brief(ctx, db, u) for u in db.scalars(select(User).order_by(User.id))]


@router.get("/users/{user_id}")
async def user(user_id: str, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.leases.engine import lease_dict

    with ctx.session() as db:
        u = db.get(User, user_id.lower())
        if u is None:
            raise KeyError(f"user {user_id} not found")
        sessions = db.scalars(select(UserSession).where(UserSession.user_id == u.id).order_by(UserSession.started_at.desc()).limit(15)).all()
        events = db.scalars(select(Event).where(Event.user_id == u.id).order_by(Event.id.desc()).limit(40)).all()
        leases = db.scalars(select(Lease).where(Lease.user_id == u.id).order_by(Lease.created_at.desc()).limit(15)).all()
        return {**user_brief(ctx, db, u), "ad_dn": u.ad_dn, "risk_detail": risk_of(db, "user", u.id),
                "session_history": [{"device": s.device_id, "ip": s.source_ip, "active": s.active, "since": s.started_at.isoformat(),
                                     "ended": s.ended_at.isoformat() if s.ended_at else None, "source": s.source} for s in sessions],
                "leases": [lease_dict(ctx, x) for x in leases],
                "events": [{"ts": e.ts.isoformat(), "type": e.type, "message": e.message, "severity": e.severity} for e in events],
                "workstations": [d.id for d in db.scalars(select(Device).where(Device.owner_user_id == u.id))]}


@router.get("/groups")
async def groups(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"id": g.id, "description": g.description, "privileged": g.privileged,
                 "members": list(db.scalars(select(UserGroup.user_id).where(UserGroup.group_id == g.id)))} for g in db.scalars(select(Group).order_by(Group.id))]


@router.get("/sessions")
async def sessions(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    with ctx.session() as db:
        return [{"id": s.id, "user": s.user_id, "device": s.device_id, "ip": s.source_ip, "logon_type": s.logon_type, "source": s.source,
                 "started_at": s.started_at.isoformat(), "active": s.active}
                for s in db.scalars(select(UserSession).order_by(UserSession.started_at.desc()).limit(50))]


@router.get("/identity")
async def identity(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.identity.confidence import signal_config

    weights, levels = signal_config(ctx)
    with ctx.session() as db:
        devices = []
        for d in db.scalars(select(Device).order_by(Device.kind, Device.id)):
            session = db.scalar(select(UserSession).where(UserSession.device_id == d.id, UserSession.active.is_(True)))
            devices.append({"id": d.id, "kind": d.kind, "confidence": d.identity_confidence, "level": d.identity_level, "managed": d.managed,
                            "quarantined": d.quarantined, "user": session.user_id if session else None,
                            "signals": (d.identity_signals or {}).get("signals", [])})
        chain = []
        for s in db.scalars(select(UserSession).where(UserSession.active.is_(True))):
            dv = db.get(Device, s.device_id)
            iface = db.scalar(select(Interface).where(Interface.device_id == s.device_id))
            chain.append({"user": s.user_id, "groups": ctx.identity.groups_for(db, s.user_id), "device": s.device_id, "ip": s.source_ip,
                          "mac": db.scalar(select(MacAddress.address).where(MacAddress.device_id == s.device_id)),
                          "vlan": dv.vlan_id if dv else None, "switchport": iface.id if iface else None, "confidence": dv.identity_confidence if dv else 0,
                          "leases": [x.id for x in db.scalars(select(Lease).where(Lease.user_id == s.user_id, Lease.device_id == s.device_id, Lease.status == "ACTIVE"))]})
        return {"weights": weights, "levels": [{"min": m, "level": n} for m, n in levels], "devices": devices, "chains": chain,
                "note": "Identity confidence is a configurable prototype heuristic, not a statistical model."}


def topology(ctx: Context, db: Any, include_services: bool = True) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [{"id": "internet", "type": "internet", "label": "Internet", "status": "healthy", "data": {}}]
    edges: list[dict[str, Any]] = []
    devices = {d.id: d for d in db.scalars(select(Device))}
    affected_devices: set[str] = set()
    affected_services: set[str] = set()
    root_causes: set[str] = set()
    for inc in db.scalars(select(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING", "MITIGATED")))):
        affected_devices |= set(inc.affected_devices or [])
        affected_services |= set(inc.affected_services or [])
        if inc.root_cause_entity and inc.root_cause_kind in ("service_down", "config_change", "identity", "drift", "unreachable") \
                and inc.status in ("OPEN", "INVESTIGATING"):
            root_causes.add(inc.root_cause_entity.split(":")[0] if ":" in inc.root_cause_entity else inc.root_cause_entity)

    def dnode(d: Device, ntype: str) -> dict[str, Any]:
        b = device_brief(db, d)
        return {"id": d.id, "type": ntype, "label": d.id, "status": d.status, "data": b,
                "affected": d.id in affected_devices, "root_cause": d.id in root_causes}

    if "PFSENSE" in devices:
        nodes.append(dnode(devices["PFSENSE"], "firewall"))
        edges.append({"id": "e-internet-fw", "source": "internet", "target": "PFSENSE", "kind": "wan", "label": "WAN"})
    if "SW-CORE01" in devices:
        nodes.append(dnode(devices["SW-CORE01"], "switch"))
        edges.append({"id": "e-fw-sw", "source": "PFSENSE", "target": "SW-CORE01", "kind": "trunk", "label": "Gi1/0/1 trunk"})
    for v in db.scalars(select(Vlan).order_by(Vlan.id)):
        members = [d for d in devices.values() if d.vlan_id == v.id and d.id not in ("PFSENSE", "SW-CORE01")]
        nodes.append({"id": f"vlan-{v.id}", "type": "vlan", "label": f"VLAN {v.id}", "status": "healthy" if v.status == "up" else "critical",
                      "data": {"vlan": v.id, "name": v.name, "subnet": v.subnet, "gateway": v.gateway, "purpose": v.purpose, "members": len(members)},
                      "affected": any(m.id in affected_devices for m in members)})
        edges.append({"id": f"e-sw-vlan-{v.id}", "source": "SW-CORE01", "target": f"vlan-{v.id}", "kind": "vlan", "label": v.subnet})
        for d in sorted(members, key=lambda x: x.id):
            iface = db.scalar(select(Interface).where(Interface.device_id == d.id))
            nodes.append(dnode(d, "device"))
            edges.append({"id": f"e-vlan-{d.id}", "source": f"vlan-{v.id}", "target": d.id, "kind": "access", "label": iface.name if iface else ""})
    if include_services:
        from nexus.models import Dependency

        for s in db.scalars(select(Service)):
            nodes.append({"id": s.id, "type": "service", "label": s.display_name, "status": "healthy" if s.status == "running" else "critical",
                          "data": {"service": s.name, "device": s.device_id, "criticality": s.criticality, "status": s.status, "ports": s.ports},
                          "affected": s.id in affected_services, "root_cause": s.id in root_causes})
            edges.append({"id": f"e-run-{s.id}", "source": s.device_id, "target": s.id, "kind": "runs", "label": ""})
        for dep in db.scalars(select(Dependency)):
            edges.append({"id": f"e-dep-{dep.id}", "source": dep.source_id, "target": dep.target_id, "kind": "depends", "label": dep.description})
    return {"nodes": nodes, "edges": edges, "highlights": {"affected_devices": sorted(affected_devices), "affected_services": sorted(affected_services),
                                                            "root_causes": sorted(root_causes),
                                                            "quarantined": [d.id for d in devices.values() if d.quarantined]}}


@router.get("/network")
async def network(services: bool = True, ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        topo = topology(ctx, db, services)
        topo["vlans"] = [{"id": v.id, "name": v.name, "subnet": v.subnet, "gateway": v.gateway, "status": v.status, "purpose": v.purpose}
                         for v in db.scalars(select(Vlan).order_by(Vlan.id))]
        return topo


@router.get("/network/inventory")
async def network_inventory(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.network.inventory import inventory

    with ctx.session() as db:
        return inventory(ctx, db)


@router.get("/network/health")
async def network_health(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    with ctx.session() as db:
        rows = []
        for v in db.scalars(select(Vlan).order_by(Vlan.id)):
            members = db.scalars(select(Device).where(Device.vlan_id == v.id)).all()
            lat = [float(m.metrics["latency_ms"]) for m in members if (m.metrics or {}).get("latency_ms") is not None]
            loss = [float(m.metrics.get("packet_loss") or 0) for m in members if m.metrics]
            reach = [m.reachable for m in members]
            rows.append({"vlan": v.id, "name": v.name, "devices": len(members), "availability": round(100 * sum(1 for r in reach if r) / len(reach), 1) if reach else None,
                         "latency_ms": round(sum(lat) / len(lat), 2) if lat else None, "packet_loss": round(sum(loss) / len(loss), 2) if loss else None})
        svc = db.scalars(select(Service)).all()
        return {"vlans": rows, "services_up": sum(1 for s in svc if s.status == "running"), "services_total": len(svc),
                "devices_reachable": db.scalar(select(func.count()).select_from(Device).where(Device.reachable.is_(True))),
                "devices_total": db.scalar(select(func.count()).select_from(Device)), "simulated": ctx.settings.is_simulation}


@router.get("/firewall")
async def firewall(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.core.store import get_setting
    from nexus.firewall.addressing import shadow_analysis
    from nexus.firewall.base import FirewallUnavailable
    from nexus.policy.compiler import resolver

    with ctx.session() as db:
        try:
            rules = ctx.firewall.list_rules(db)
        except FirewallUnavailable as exc:
            return {"available": False, "error": str(exc), "rules": [], "shadowed": [], "state": ctx.firewall.get_state(db)}
        return {"available": True, "rules": rules, "shadowed": shadow_analysis(resolver(ctx, db, analysis=True), rules), "state": ctx.firewall.get_state(db),
                "nexus_blocks": get_setting(db, "firewall_nexus_blocks") or [], "aliases": dict(ctx.policy_cache.firewall.spec.aliases) if ctx.policy_cache.firewall else {}}


@router.get("/dependencies")
async def dependencies(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> dict[str, Any]:
    from nexus.dependencies.graph import graph_payload, recovery_order

    with ctx.session() as db:
        payload = graph_payload(db)
        failing = [n["id"] for n in payload["nodes"] if n["status"] != "running"]
        payload["failing"] = failing
        payload["recovery_order"] = recovery_order(db, failing) if failing else []
        payload["full_recovery_order"] = recovery_order(db, [n["id"] for n in payload["nodes"]])
        return payload


@router.get("/certificates")
async def certificates(ctx: Context = Depends(get_ctx), _: Principal = Depends(current_principal)) -> list[dict[str, Any]]:
    from nexus.models import Certificate

    with ctx.session() as db:
        now = ctx.clock.now()
        out = []
        for c in db.scalars(select(Certificate)):
            days = (c.not_after - now).total_seconds() / 86400
            out.append({"id": c.id, "device": c.device_id, "service": c.service_id, "issuer": c.issuer, "not_after": c.not_after.isoformat(),
                        "days_remaining": round(days, 1), "status": "EXPIRED" if days < 0 else "EXPIRING" if days <= 14 else "VALID"})
        return sorted(out, key=lambda c: c["days_remaining"])

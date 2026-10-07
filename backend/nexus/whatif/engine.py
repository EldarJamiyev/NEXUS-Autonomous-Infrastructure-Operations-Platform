"""What-if simulator. Read-only: works on the current state and never writes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.dependencies.graph import impact_of
from nexus.firewall.addressing import evaluate
from nexus.incidents.engine import SERVICE_ACTIONS
from nexus.incidents.triage import triage
from nexus.models import Device, Incident, Lease, Service, UserGroup
from nexus.risk.engine import score_of

if TYPE_CHECKING:
    from nexus.core.context import Context

SCENARIOS = [
    {"id": "device_down", "question": "What if a device fails?", "params": ["device"]},
    {"id": "service_down", "question": "What if a service fails?", "params": ["service"]},
    {"id": "vlan_down", "question": "What if a VLAN fails?", "params": ["vlan"]},
    {"id": "firewall_api_down", "question": "What if the pfSense API becomes unavailable?", "params": []},
    {"id": "firewall_down", "question": "What if pfSense itself fails?", "params": []},
    {"id": "ssh_loss", "question": "What if a server loses SSH?", "params": ["device"]},
    {"id": "rule_removed", "question": "What if a firewall rule disappears?", "params": ["rule"]},
    {"id": "device_high_risk", "question": "What if a device becomes high risk?", "params": ["device"]},
    {"id": "policy_removed", "question": "What if a policy is removed?", "params": ["policy"]},
    {"id": "disaster", "question": "Disaster recovery lab: DC01, MON01 and APP01 down, pfSense degraded", "params": []},
]
ALERT_FOR_SERVICE = {"nginx": "NginxDown", "ssh": "SSHDown", "dns": "DNSServiceDown", "docker": "DockerDown", "monitoring-agent": "MonitoringAgentDown",
                     "ntp": "NTPClockSkew", "portal": "PortalHealthCheckFailed", "ad-ds": "ADAuthenticationFailures"}


def _current(db: Session) -> dict[str, Any]:
    return {"devices": db.scalar(select(func.count()).select_from(Device)), "services_down": db.scalar(select(func.count()).select_from(Service).where(Service.status != "running")),
            "active_leases": db.scalar(select(func.count()).select_from(Lease).where(Lease.status == "ACTIVE")),
            "open_incidents": db.scalar(select(func.count()).select_from(Incident).where(Incident.status.in_(("OPEN", "INVESTIGATING"))))}


def _responses(ctx: Context, db: Session, impact: dict[str, Any], devices_down: set[str]) -> list[dict[str, Any]]:
    out = []
    for d in sorted(devices_down):
        out.append({"alert": "NodeDown", "target": d, "nexus_action": "Human investigation (no remote path to an unreachable host)", "mode": "approval/human"})
    for sid in impact["services"]:
        svc = db.get(Service, sid)
        if svc is None or svc.device_id in devices_down:
            continue
        alert = ALERT_FOR_SERVICE.get(svc.name)
        if not alert:
            continue
        action_id = SERVICE_ACTIONS.get(svc.name)
        if action_id:
            act = ctx.catalog.get(action_id)
            out.append({"alert": alert, "target": svc.device_id, "nexus_action": act.name,
                        "mode": "automatic" if act.category == "SAFE" else "automatic if confident" if act.category == "REVERSIBLE" else "approval"})
        else:
            out.append({"alert": alert, "target": svc.device_id, "nexus_action": "correlated as symptom; fixed by remediating the root cause", "mode": "-"})
    return out


def simulate(ctx: Context, db: Session, scenario: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    params = params or {}
    devices: set[str] = set()
    services: set[str] = set()
    vlans: set[int] = set()
    api_down = False
    extra: dict[str, Any] = {}
    if scenario == "device_down":
        devices = {params["device"]}
        change = f"{params['device']} becomes unavailable"
    elif scenario == "service_down":
        services = {params["service"]}
        change = f"{params['service']} stops"
    elif scenario == "vlan_down":
        vlans = {int(params["vlan"])}
        change = f"VLAN {params['vlan']} loses connectivity"
    elif scenario == "firewall_api_down":
        api_down = True
        change = "pfSense management API stops responding (data plane keeps forwarding)"
    elif scenario == "firewall_down":
        devices = {"PFSENSE"}
        change = "pfSense fails completely (no routing between VLANs)"
    elif scenario == "ssh_loss":
        services = {f"ssh@{params['device']}"}
        change = f"SSH on {params['device']} becomes unavailable"
    elif scenario == "disaster":
        devices = {"DC01", "MON01", "APP01"}
        api_down = True
        change = "DC01, MON01 and APP01 unavailable; pfSense management degraded"
    elif scenario == "rule_removed":
        from nexus.policy.compiler import resolver

        rules = ctx.firewall.list_rules(db)
        target = next((r for r in rules if r["id"] == params["rule"]), None)
        if target is None:
            raise KeyError(f"rule {params['rule']} not found")
        remaining = [r for r in rules if r["id"] != target["id"]]
        res = resolver(ctx, db)
        flows = []
        for lease in db.scalars(select(Lease).where(Lease.status == "ACTIVE")):
            before, _ = evaluate(res, rules, lease.source_ip, res.device_ips.get(lease.destination_id), lease.protocol, lease.port)
            after, rule = evaluate(res, remaining, lease.source_ip, res.device_ips.get(lease.destination_id), lease.protocol, lease.port)
            if before != after:
                flows.append({"flow": f"{lease.source_ip} -> {lease.destination_id}:{lease.port}", "lease": lease.id, "before": before, "after": after})
        sample_port = int(str(target["port"]).split(",")[0]) if str(target["port"]).upper() != "ANY" else 22
        dst_ip = res.device_ips.get(target["destination"], target["destination"])
        src = "10.30.30.250" if target["source"].upper() == "ANY" else (res.device_ips.get(target["source"]) or target["source"])
        before, _ = evaluate(res, rules, src, dst_ip, "TCP", sample_port)
        after, rule = evaluate(res, remaining, src, dst_ip, "TCP", sample_port)
        flows.append({"flow": f"{src} -> {target['destination']}:{sample_port} (representative)", "before": before, "after": after,
                      "now_matched_by": rule["id"] if rule else "implicit deny"})
        change = f"rule {target['id']} ({target['action']} {target['source']} -> {target['destination']}:{target['port']}) removed"
        extra["flows"] = flows
        if target["origin"] == "baseline" and target["action"] == "ALLOW":
            services = {s.id for s in db.scalars(select(Service).where(Service.device_id == target["destination"], Service.consumers == "all_users"))}
    elif scenario == "device_high_risk":
        dev = db.get(Device, params["device"])
        if dev is None:
            raise KeyError(params["device"])
        hypothetical = int(params.get("risk", 85))
        policies = {d.metadata.id: d for d in ctx.policy_cache.access}
        revoked = [x.id for x in db.scalars(select(Lease).where(Lease.device_id == dev.id, Lease.status == "ACTIVE"))
                   if x.policy_id in policies and hypothetical > policies[x.policy_id].spec.conditions.max_device_risk]
        quarantine = dev.identity_level == "UNKNOWN" and hypothetical >= 80
        change = f"{dev.id} risk rises from {score_of(db, 'device', dev.id)} to {hypothetical}"
        extra["consequences"] = [f"lease {x} revoked (policy risk threshold exceeded)" for x in revoked] + \
            (["SECURITY-004 quarantine (identity UNKNOWN)"] if quarantine else ["no automatic quarantine: identity is established - risk gates access instead"]) + \
            ["new access requests from this device denied while risk exceeds policy thresholds"]
    elif scenario == "policy_removed":
        pid = params["policy"]
        doc = next((d for d in ctx.policy_cache.access if d.metadata.id == pid), None)
        if doc is None:
            raise KeyError(f"access policy {pid} not found")
        members = sorted({u for g in doc.spec.subjects.groups for u in db.scalars(select(UserGroup.user_id).where(UserGroup.group_id == g))})
        leases = [x.id for x in db.scalars(select(Lease).where(Lease.policy_id == pid, Lease.status == "ACTIVE"))]
        change = f"{pid} removed"
        extra["consequences"] = [f"{len(members)} user(s) lose grants: {', '.join(members)}", f"{len(leases)} active lease(s) would be revoked at next reconciliation"] + \
            [f"deny rule for {', '.join(doc.spec.subjects.groups)} on ports {d.ports} disappears (exposure increases)" for d in doc.spec.denies]
        extra["affected_leases"] = leases
    else:
        raise KeyError(f"unknown scenario {scenario}")
    impact = impact_of(ctx, db, services=services, devices=devices, vlans=vlans, firewall_api_down=api_down)
    if scenario == "policy_removed":
        impact["leases"] = extra.get("affected_leases", [])
        impact["counts"]["leases"] = len(impact["leases"])
    crit = "CRITICAL" if any((s := db.get(Service, sid)) and s.criticality == "CRITICAL" for sid in impact["services"]) else "HIGH" if impact["services"] else "MEDIUM"
    t = triage(severity="critical" if crit == "CRITICAL" else "high", criticality=crit, users=impact["counts"]["users"],
               services=impact["counts"]["services"], risk=0, recent_change=False)
    mode = "EMERGENCY" if t["priority"] == "P1" and impact["counts"]["services"] >= 4 else "DEGRADED" if api_down or "PFSENSE" in devices or "MON01" in devices else "NORMAL"
    return {"scenario": scenario, "question": next((s["question"] for s in SCENARIOS if s["id"] == scenario), scenario), "params": params,
            "current": _current(db), "change": change, "propagation": impact["propagation"], "impact": impact,
            "expected": {"priority": t["priority"], "impact": t["impact"], "urgency": t["urgency"], "system_mode": mode,
                         "nexus_responses": _responses(ctx, db, impact, devices | {d for v in vlans for d in impact["devices"]}),
                         **extra},
            "recovery_order": impact["recovery_order"], "read_only": True,
            "note": "Simulation only - no state was modified."}

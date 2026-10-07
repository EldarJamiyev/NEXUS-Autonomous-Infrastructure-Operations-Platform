"""Service dependency graph, impact propagation and recovery ordering (deterministic)."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Dependency, Device, Lease, Policy, Service, User
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context

LAYER = {"firewall": 0, "dhcp": 0, "dns": 1, "ntp": 2, "ad-ds": 3, "docker": 4, "postgresql": 5, "nginx": 6, "ssh": 6, "portal": 7,
         "monitoring-agent": 8, "prometheus": 8, "loki": 8, "grafana": 9}
LAYER_NAME = {0: "network", 1: "name resolution", 2: "time", 3: "identity", 4: "container runtime", 5: "database", 6: "access tier",
              7: "application", 8: "monitoring", 9: "dashboards"}
NETWORK_CORE = {"PFSENSE", "SW-CORE01"}


class ServiceGraph:
    def __init__(self, db: Session) -> None:
        self.services = {s.id: s for s in db.scalars(select(Service))}
        self.deps: dict[str, list[str]] = {sid: [] for sid in self.services}
        self.rdeps: dict[str, list[str]] = {sid: [] for sid in self.services}
        self.edge_desc: dict[tuple[str, str], str] = {}
        for d in db.scalars(select(Dependency)):
            self.deps.setdefault(d.source_id, []).append(d.target_id)
            self.rdeps.setdefault(d.target_id, []).append(d.source_id)
            self.edge_desc[(d.source_id, d.target_id)] = d.description

    def _walk(self, start: str, edges: dict[str, list[str]]) -> list[str]:
        seen: list[str] = []
        q = deque(edges.get(start, []))
        while q:
            n = q.popleft()
            if n not in seen and n != start:
                seen.append(n)
                q.extend(edges.get(n, []))
        return seen

    def upstream(self, sid: str) -> list[str]:
        return self._walk(sid, self.deps)

    def downstream(self, sid: str) -> list[str]:
        return self._walk(sid, self.rdeps)

    def related(self, a: str, b: str) -> bool:
        return a == b or b in self.upstream(a) or b in self.downstream(a)

    def on_device(self, device_id: str) -> list[str]:
        return [sid for sid, s in self.services.items() if s.device_id == device_id]


def layer_of(service_name: str) -> int:
    return LAYER.get(service_name, 6)


def impact_of(ctx: Context, db: Session, services: set[str] | None = None, devices: set[str] | None = None,
              vlans: set[int] | None = None, firewall_api_down: bool = False) -> dict[str, Any]:
    """Propagate a failure through network topology and service dependencies. Read-only."""
    graph = ServiceGraph(db)
    services, devices, vlans = set(services or []), set(devices or []), set(vlans or [])
    propagation: list[dict[str, Any]] = []
    all_devices = {d.id: d for d in db.scalars(select(Device))}
    if devices & NETWORK_CORE:
        for core in devices & NETWORK_CORE:
            propagation.append({"entity": core, "kind": "device", "reason": "network core failure isolates every VLAN"})
        devices |= {d for d, dev in all_devices.items() if dev.vlan_id is not None and d not in NETWORK_CORE}
    for vlan in sorted(vlans):
        members = {d for d, dev in all_devices.items() if dev.vlan_id == vlan}
        propagation.append({"entity": f"VLAN {vlan}", "kind": "vlan", "reason": f"{len(members)} device(s) lose connectivity"})
        devices |= members
    for d in sorted(devices):
        for sid in graph.on_device(d):
            if sid not in services:
                services.add(sid)
                propagation.append({"entity": sid, "kind": "service", "reason": f"hosted on {d}"})
    direct = set(services)
    for sid in sorted(direct):
        for down in graph.downstream(sid):
            if down not in services:
                services.add(down)
                via = next((u for u in graph.deps.get(down, []) if u in services), sid)
                propagation.append({"entity": down, "kind": "service", "reason": f"depends on {via}: {graph.edge_desc.get((down, via), '')}".rstrip(": ")})
    sessions = db.scalars(select(UserSession).where(UserSession.active.is_(True))).all()
    active_users = {s.user_id for s in sessions}
    users: set[str] = set()
    for sid in services:
        svc = graph.services.get(sid)
        if not svc:
            continue
        if svc.consumers == "all_users":
            users |= active_users
        elif svc.consumers == "operators":
            users |= {u for u in active_users if "GG-IT" in ctx.identity.groups_for(db, u)}
    users |= {s.user_id for s in sessions if s.device_id in devices}
    leases = []
    for lease in db.scalars(select(Lease).where(Lease.status == "ACTIVE")):
        dst_svc = f"ssh@{lease.destination_id}" if lease.port == 22 else None
        if lease.destination_id in devices or lease.device_id in devices or (dst_svc and dst_svc in services) or firewall_api_down:
            leases.append(lease.id)
            for s in sessions:
                if s.user_id == lease.user_id:
                    users.add(s.user_id)
    affected_devices = sorted(devices | {graph.services[s].device_id for s in direct if s in graph.services})
    policies = sorted({lease.policy_id for lease in db.scalars(select(Lease).where(Lease.id.in_(leases))) if lease.policy_id})
    if firewall_api_down:
        propagation.append({"entity": "PFSENSE API", "kind": "control-plane", "reason": "rule changes queue as PENDING; new privileged leases blocked"})
        policies = sorted({p.id for p in db.scalars(select(Policy).where(Policy.kind == "AccessPolicy"))})
    crit_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    worst = max((crit_rank.get(graph.services[s].criticality, 1) for s in services if s in graph.services), default=0)
    level = "CRITICAL" if worst == 4 and len(users) >= 2 else "HIGH" if worst >= 3 or len(users) >= 2 else "MEDIUM" if services or leases else "LOW"
    rto = [int(graph.services[s].rto_minutes or 0) for s in services if s in graph.services and graph.services[s].rto_minutes]
    return {
        "level": level,
        "devices": affected_devices, "services": sorted(services), "users": sorted(users), "leases": sorted(leases), "policies": policies,
        "counts": {"devices": len(affected_devices), "services": len(services), "users": len(users), "leases": len(leases), "policies": len(policies)},
        "user_names": [u.display_name for u in db.scalars(select(User).where(User.id.in_(users)))],
        "propagation": propagation, "tightest_rto_minutes": min(rto) if rto else None,
        "recovery_order": recovery_order(db, sorted(services), graph),
    }


def recovery_order(db: Session, services: list[str], graph: ServiceGraph | None = None) -> list[dict[str, Any]]:
    """Dependencies first (topological), ties broken by infrastructure layer."""
    graph = graph or ServiceGraph(db)
    pending = [s for s in services if s in graph.services]
    done: list[str] = []
    order: list[dict[str, Any]] = []
    while pending:
        ready = [s for s in pending if all(d in done or d not in pending for d in graph.deps.get(s, []))]
        if not ready:
            ready = pending[:]
        ready.sort(key=lambda s: (layer_of(graph.services[s].name), s))
        s = ready[0]
        pending.remove(s)
        done.append(s)
        deps = [d for d in graph.deps.get(s, []) if d in services]
        lay = layer_of(graph.services[s].name)
        reason = (f"needs {', '.join(deps)} first" if deps else f"{LAYER_NAME.get(lay, 'service')} layer has no failed dependencies")
        order.append({"order": len(order) + 1, "service": s, "name": graph.services[s].display_name, "layer": LAYER_NAME.get(lay, ""),
                      "rto_minutes": graph.services[s].rto_minutes, "rpo_minutes": graph.services[s].rpo_minutes, "reason": reason})
    return order


def graph_payload(db: Session) -> dict[str, Any]:
    graph = ServiceGraph(db)
    nodes = [{"id": s.id, "name": s.display_name, "device": s.device_id, "status": s.status, "criticality": s.criticality,
              "layer": LAYER_NAME.get(layer_of(s.name), ""), "rto": s.rto_minutes, "rpo": s.rpo_minutes, "consumers": s.consumers}
             for s in graph.services.values()]
    edges = [{"source": src, "target": dst, "description": graph.edge_desc.get((src, dst), "")}
             for src, targets in graph.deps.items() for dst in targets]
    return {"nodes": nodes, "edges": edges}

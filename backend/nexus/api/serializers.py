"""Model -> JSON helpers shared by routers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.models import Device, Incident, Interface, IpAddress, Lease, MacAddress, RiskScore, Service, User, Vlan
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context


def risk_of(db: Session, entity_type: str, entity_id: str) -> dict[str, Any]:
    r = db.get(RiskScore, (entity_type, entity_id))
    if r is None:
        return {"score": 0, "level": "LOW", "trust": 90, "factors": []}
    return {"score": r.score, "level": r.level, "trust": r.trust, "factors": r.factors, "updated_at": r.updated_at.isoformat()}


def device_brief(db: Session, d: Device) -> dict[str, Any]:
    ip = db.scalar(select(IpAddress).where(IpAddress.device_id == d.id))
    mac = db.scalar(select(MacAddress).where(MacAddress.device_id == d.id))
    services = db.scalars(select(Service).where(Service.device_id == d.id)).all()
    incidents = db.scalar(select(func.count()).select_from(Incident).where(Incident.target == d.id, Incident.status.in_(("OPEN", "INVESTIGATING")))) or 0
    risk = risk_of(db, "device", d.id)
    return {"id": d.id, "kind": d.kind, "os": d.os, "role": d.role, "vlan": d.vlan_id, "ip": ip.address if ip else None, "mac": mac.address if mac else None,
            "status": d.status, "criticality": d.criticality, "managed": d.managed, "identity_confidence": d.identity_confidence,
            "identity_level": d.identity_level, "quarantined": d.quarantined, "reachable": d.reachable, "risk": risk["score"], "risk_level": risk["level"],
            "trust": risk["trust"], "owner": d.owner_user_id, "location": d.location, "metrics": d.metrics, "last_seen": d.last_seen.isoformat(),
            "services": [{"id": s.id, "name": s.name, "status": s.status} for s in services], "open_incidents": incidents}


def user_brief(ctx: Context, db: Session, u: User) -> dict[str, Any]:
    sessions = db.scalars(select(UserSession).where(UserSession.user_id == u.id, UserSession.active.is_(True))).all()
    leases = db.scalar(select(func.count()).select_from(Lease).where(Lease.user_id == u.id, Lease.status == "ACTIVE")) or 0
    risk = risk_of(db, "user", u.id)
    return {"id": u.id, "name": u.display_name, "email": u.email, "department": u.department, "title": u.title, "enabled": u.enabled,
            "console_role": u.console_role, "groups": ctx.identity.groups_for(db, u.id), "privileged": ctx.identity.privileged(db, u.id),
            "sessions": [{"device": s.device_id, "ip": s.source_ip, "since": s.started_at.isoformat(), "source": s.source} for s in sessions],
            "active_leases": leases, "risk": risk["score"], "risk_level": risk["level"], "trust": risk["trust"]}


def network_context(db: Session, d: Device) -> dict[str, Any]:
    ip = db.scalar(select(IpAddress).where(IpAddress.device_id == d.id))
    iface = db.scalar(select(Interface).where(Interface.device_id == d.id))
    vlan = db.get(Vlan, d.vlan_id) if d.vlan_id else None
    mac = db.scalar(select(MacAddress).where(MacAddress.device_id == d.id))
    return {"ip": ip.address if ip else None, "assignment": ip.assignment if ip else None, "dhcp_hostname": ip.dhcp_hostname if ip else None,
            "mac": mac.address if mac else None, "mac_known": bool(mac and mac.known), "vendor": mac.vendor if mac else None,
            "vlan": d.vlan_id, "vlan_name": vlan.name if vlan else None, "expected_vlan": d.expected_vlan_id, "gateway": vlan.gateway if vlan else None,
            "dns_servers": ["10.20.20.10"], "dns_name": d.dns_name, "switchport": iface.id if iface else None,
            "observed_ports": d.observed_ports, "expected_ports": d.expected_ports}

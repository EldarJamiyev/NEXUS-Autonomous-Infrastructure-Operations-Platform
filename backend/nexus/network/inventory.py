"""Network administration views: IP/MAC/VLAN inventory, DHCP conflicts, DNS consistency, port anomalies."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, Interface, IpAddress, MacAddress, Service, Vlan

if TYPE_CHECKING:
    from nexus.core.context import Context


def dhcp_conflicts(db: Session) -> list[dict[str, Any]]:
    out = []
    for rec in db.scalars(select(IpAddress)):
        if rec.conflict_macs:
            out.append({"ip": rec.address, "owner": rec.device_id, "owner_mac": rec.mac, "conflicting_macs": rec.conflict_macs,
                        "vlan": rec.vlan_id, "status": "CONFLICT"})
    return out


def dns_consistency(ctx: Context, db: Session) -> list[dict[str, Any]]:
    """Compare DHCP hostname, DNS name, AD computer name and the inventory hostname."""
    dns_up = (svc := db.get(Service, "dns@DC01")) is not None and svc.status == "running"
    rows = []
    for dev in db.scalars(select(Device).order_by(Device.id)):
        ip = db.scalar(select(IpAddress).where(IpAddress.device_id == dev.id))
        dhcp = ip.dhcp_hostname if ip else None
        dns = dev.dns_name.split(".")[0].upper() if dev.dns_name else None
        ad = dev.id if dev.ad_computer else None
        names = {n.upper() for n in (dhcp, dns, ad, dev.expected_hostname) if n}
        if dev.kind == "unknown" or len(names) > 1:
            status = "IDENTITY MISMATCH"
        else:
            status = "CONSISTENT" if dns_up else "UNVERIFIABLE (DNS down)"
        rows.append({"device": dev.id, "ip": ip.address if ip else None, "dhcp_hostname": dhcp, "dns_name": dev.dns_name,
                     "ad_computer": ad, "inventory_hostname": dev.expected_hostname, "status": status})
    return rows


def port_anomalies(ctx: Context, db: Session) -> list[dict[str, Any]]:
    out = []
    for dev in db.scalars(select(Device)):
        expected = set(int(p) for p in dev.expected_ports or [])
        observed = set(int(p) for p in dev.observed_ports or [])
        for port in sorted(observed - expected):
            out.append({"device": dev.id, "port": port, "status": "UNEXPECTED SERVICE"})
        for port in sorted(expected - observed):
            if dev.reachable:
                out.append({"device": dev.id, "port": port, "status": "EXPECTED PORT CLOSED"})
    return out


def inventory(ctx: Context, db: Session) -> dict[str, Any]:
    vlans = []
    for v in db.scalars(select(Vlan).order_by(Vlan.id)):
        members = db.scalars(select(Device.id).where(Device.vlan_id == v.id)).all()
        pool = {"size": v.dhcp_pool_size, "in_use": v.dhcp_in_use, "stale": v.dhcp_stale,
                "utilization": round(100 * v.dhcp_in_use / v.dhcp_pool_size, 1) if v.dhcp_pool_size else None} if v.dhcp_enabled else None
        vlans.append({"id": v.id, "name": v.name, "subnet": v.subnet, "gateway": v.gateway, "purpose": v.purpose, "status": v.status,
                      "devices": list(members), "dhcp": pool})
    ips = [{"address": r.address, "device": r.device_id, "mac": r.mac, "vlan": r.vlan_id, "assignment": r.assignment,
            "dhcp_hostname": r.dhcp_hostname, "conflict": bool(r.conflict_macs)} for r in db.scalars(select(IpAddress).order_by(IpAddress.address))]
    macs = [{"address": m.address, "device": m.device_id, "vendor": m.vendor, "known": m.known, "interface": m.interface_id,
             "first_seen": m.first_seen.isoformat(), "last_seen": m.last_seen.isoformat()} for m in db.scalars(select(MacAddress))]
    ports = [{"id": i.id, "switch": i.switch_id, "name": i.name, "vlan": i.vlan_id, "device": i.device_id, "mode": i.mode,
              "status": i.status, "speed_mbps": i.speed_mbps} for i in db.scalars(select(Interface).order_by(Interface.name))]
    services = [{"id": s.id, "device": s.device_id, "name": s.display_name, "ports": s.ports, "status": s.status,
                 "criticality": s.criticality} for s in db.scalars(select(Service).order_by(Service.device_id))]
    gateways = []
    for v in db.scalars(select(Vlan).order_by(Vlan.id)):
        fw = db.get(Device, "PFSENSE")
        gateways.append({"vlan": v.id, "gateway": v.gateway, "reachable": bool(fw and fw.reachable) and ctx.runtime.firewall_available or bool(fw and fw.reachable),
                         "status": "up" if fw and fw.reachable and v.status == "up" else "down"})
    return {"vlans": vlans, "ips": ips, "macs": macs, "switchports": ports, "services": services, "gateways": gateways,
            "dhcp_conflicts": dhcp_conflicts(db), "dns_consistency": dns_consistency(ctx, db), "port_anomalies": port_anomalies(ctx, db)}

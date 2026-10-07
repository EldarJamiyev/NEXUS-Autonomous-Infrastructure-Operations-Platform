"""Observation ingestion: DHCP, ARP, firewall syslog, FIM (config change) and port activity.

These are the OBSERVE/NORMALIZE steps of the loop. Real deployments feed them from DHCP logs,
switch ARP/MAC tables (SNMP/LLDP), pfSense filterlog and host agents; the simulation feeds the
same functions. NEXUS never scans the network aggressively - it listens.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.ids import new_id
from nexus.models import Device, FirewallRule, Interface, IpAddress, MacAddress

if TYPE_CHECKING:
    from nexus.core.context import Context

ADMIN_PORTS = {22, 23, 135, 445, 3389, 5985, 5986}


def observe_config_change(ctx: Context, db: Session, device_id: str, component: str, before: str | None, after: str,
                          actor: str, reason: str = "") -> None:
    by_nexus = actor.lower().startswith("nexus")
    ctx.bus.emit(db, "CONFIG_CHANGED", f"{device_id} {component} configuration changed by {actor}" + (f" ({reason})" if reason else ""),
                 severity="info" if by_nexus else "notice", source=f"fim-agent@{device_id}", target=device_id,
                 data={"component": component, "before_checksum": before, "after_checksum": after, "actor": actor,
                       "reason": reason, "by_nexus": by_nexus})
    if not by_nexus:
        ctx.runtime.pending_reconcile.add(device_id)


def observe_firewall_change(ctx: Context, db: Session, rule: FirewallRule, actor: str) -> None:
    ctx.bus.emit(db, "FIREWALL_CHANGE", f"PFSENSE rule {rule.id} added by {actor}: {rule.action} {rule.source} -> "
                 f"{rule.destination}:{rule.port}/{rule.protocol}", severity="notice", source="pfsense-syslog", target="PFSENSE",
                 data={"rule_id": rule.id, "actor": actor, "action": rule.action, "source": rule.source,
                       "destination": rule.destination, "port": rule.port})
    ctx.runtime.pending_reconcile.add("PFSENSE")


def _ensure_device(ctx: Context, db: Session, mac: str, ip: str | None, interface_id: str | None, hostname: str | None,
                   vendor: str) -> tuple[Device, bool]:
    now = ctx.clock.now()
    rec = db.get(MacAddress, mac)
    if rec and rec.device_id and (dev := db.get(Device, rec.device_id)):
        rec.last_seen = now
        dev.last_seen = now
        return dev, False
    iface = db.get(Interface, interface_id) if interface_id else None
    dev_id = new_id(db, "unknown")
    dev = Device(id=dev_id, kind="unknown", os="unknown", role=f"Unidentified endpoint{f' ({hostname})' if hostname else ''}",
                 vlan_id=iface.vlan_id if iface else None, expected_vlan_id=None, criticality="LOW", status="warning",
                 managed=False, ad_computer=False, expected_hostname=None, dns_name=None, metrics={"disk": {}},
                 expected_ports=[], observed_ports=[], sim_faults={}, location=iface.name if iface else "",
                 description=f"First seen on {interface_id or 'unknown port'}; vendor OUI {vendor}", first_seen=now, last_seen=now)
    db.add(dev)
    if rec is None:
        rec = MacAddress(address=mac, device_id=dev_id, vendor=vendor, known=False, interface_id=interface_id, first_seen=now, last_seen=now)
        db.add(rec)
    else:
        rec.device_id = dev_id
    if iface:
        iface.device_id = dev_id
    db.flush()
    return dev, True


def observe_dhcp_assignment(ctx: Context, db: Session, *, mac: str, ip: str, hostname: str | None, vlan_id: int, vendor: str = "",
                            interface_id: str | None = None) -> None:
    dev, created = _ensure_device(ctx, db, mac, ip, interface_id, hostname, vendor)
    rec = db.get(IpAddress, ip)
    if rec is None:
        db.add(IpAddress(address=ip, device_id=dev.id, mac=mac, vlan_id=vlan_id, assignment="dhcp", dhcp_hostname=hostname,
                         updated_at=ctx.clock.now()))
    elif rec.mac != mac:
        _conflict(ctx, db, rec, mac, dev)
    db.flush()
    ctx.bus.emit(db, "DHCP_ASSIGNMENT", f"DHCPACK {ip} to {mac}" + (f" ({hostname})" if hostname else " (no hostname)"),
                 source="dhcpd@PFSENSE", target=dev.id, data={"mac": mac, "ip": ip, "hostname": hostname, "vlan": vlan_id})
    if created:
        _discovered(ctx, db, dev, mac, ip, vendor)


def observe_arp(ctx: Context, db: Session, *, mac: str, ip: str, interface_id: str | None, vendor: str = "") -> None:
    dev, created = _ensure_device(ctx, db, mac, ip, interface_id, None, vendor)
    rec = db.get(IpAddress, ip)
    if rec is None:
        db.add(IpAddress(address=ip, device_id=dev.id, mac=mac, vlan_id=dev.vlan_id, assignment="static", updated_at=ctx.clock.now()))
        db.flush()
    elif rec.mac != mac:
        _conflict(ctx, db, rec, mac, dev)
    ctx.bus.emit(db, "ARP_CHANGE", f"ARP {ip} is-at {mac} on {interface_id or '?'}", source="arp@SW-CORE01", target=dev.id,
                 data={"mac": mac, "ip": ip, "interface": interface_id})
    if created:
        _discovered(ctx, db, dev, mac, ip, vendor)


def _conflict(ctx: Context, db: Session, rec: IpAddress, mac: str, newcomer: Device) -> None:
    macs = list(rec.conflict_macs or [])
    if mac not in macs:
        macs.append(mac)
    rec.conflict_macs = macs
    owner = rec.device_id
    ctx.bus.emit(db, "DHCP_CONFLICT", f"IP conflict on {rec.address}: {rec.mac} ({owner}) and {mac} ({newcomer.id})", severity="high",
                 source="arp@SW-CORE01", target=newcomer.id,
                 data={"ip": rec.address, "owner": owner, "owner_mac": rec.mac, "claimant": newcomer.id, "claimant_mac": mac})
    from nexus.incidents.engine import open_finding

    open_finding(ctx, db, name="DHCPConflict", target=newcomer.id, summary=f"Duplicate address {rec.address} claimed by {newcomer.id} "
                 f"(owner {owner})", labels={"ip": rec.address, "owner": owner or "", "claimant_mac": mac})


def _discovered(ctx: Context, db: Session, dev: Device, mac: str, ip: str | None, vendor: str) -> None:
    from nexus.identity.confidence import update_identity
    from nexus.risk.engine import recompute_device

    ctx.bus.emit(db, "DEVICE_DISCOVERED", f"New device {dev.id} ({mac}, {ip or 'no IP'}) on VLAN {dev.vlan_id}",
                 severity="warning", source="discovery", target=dev.id, data={"mac": mac, "ip": ip, "vendor": vendor, "vlan": dev.vlan_id})
    update_identity(ctx, db, dev, "device discovered")
    recompute_device(ctx, db, dev, "device discovered")


def observe_port_activity(ctx: Context, db: Session, *, src_ip: str, dst_device: str, port: int, protocol: str = "TCP",
                          action: str = "BLOCK") -> None:
    rec = db.get(IpAddress, src_ip)
    src = db.get(Device, rec.device_id) if rec and rec.device_id else None
    admin = port in ADMIN_PORTS
    ctx.bus.emit(db, "PORT_ACTIVITY", f"{protocol}/{port} {action} {src_ip} -> {dst_device}" + (" (administrative protocol)" if admin else ""),
                 severity="warning" if admin else "info", source="pfsense-filterlog", target=src.id if src else src_ip,
                 data={"src_ip": src_ip, "dst": dst_device, "port": port, "protocol": protocol, "action": action, "admin_port": admin})
    if src:
        from nexus.risk.engine import recompute_device

        recompute_device(ctx, db, src, f"{protocol}/{port} activity towards {dst_device}")


def ip_of(db: Session, device_id: str) -> str | None:
    return db.scalar(select(IpAddress.address).where(IpAddress.device_id == device_id))

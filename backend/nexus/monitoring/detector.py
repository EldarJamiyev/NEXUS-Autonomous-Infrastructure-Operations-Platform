"""Simulated monitoring (stands in for Prometheus + blackbox/node exporters + Alertmanager).

Every scan observes the World through probes and agent data, raises alerts through the same
ingest pipeline Alertmanager webhooks use, and clears alerts whose condition is gone. Rule names
match prometheus/rules/nexus-alerts.yml so both sources deduplicate onto one fingerprint.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.dependencies.graph import layer_of
from nexus.incidents.engine import AlertIn, fingerprint, ingest_alert, resolve_cleared
from nexus.models import Certificate, Device, Event, Service, Vlan
from nexus.monitoring.health import update_statuses

if TYPE_CHECKING:
    from nexus.core.context import Context

SERVICE_ALERT = {"ssh": "SSHDown", "dns": "DNSServiceDown", "docker": "DockerDown", "monitoring-agent": "MonitoringAgentDown"}
SOURCE = "nexus-monitor"


def collect(ctx: Context, db: Session) -> list[AlertIn]:
    th = ctx.policy_cache.thresholds if ctx.policy_cache else {}
    world = ctx.world
    now = ctx.clock.now()
    alerts: list[AlertIn] = []
    devices = {d.id: d for d in db.scalars(select(Device))}
    for d in devices.values():
        if d.kind == "server" and d.reachable:
            d.observed_ports = world.listening_ports(db, d)
    for svc in sorted(db.scalars(select(Service)), key=lambda s: (layer_of(s.name), s.id)):
        dev = devices.get(svc.device_id)
        if dev is None or not dev.reachable:
            continue
        if svc.name == "nginx":
            ok, detail = world.tcp_reachable(db, dev.id, 443)
            if svc.status != "running" or not ok:
                alerts.append(AlertIn("NginxDown", dev.id, service_id=svc.id, summary=f"nginx {svc.status}; {detail}"))
        elif svc.name in SERVICE_ALERT and svc.status != "running":
            alerts.append(AlertIn(SERVICE_ALERT[svc.name], dev.id, service_id=svc.id, summary=f"{svc.display_name} {svc.status} on {dev.id}"))
        elif svc.name == "portal":
            code, detail = world.http_status(db, "APP01", 8080)
            if code != 200:
                alerts.append(AlertIn("PortalHealthCheckFailed", "APP01", service_id=svc.id, summary=f"portal health: {detail}"))
        elif svc.name == "ntp":
            skew = world.clock_skew(db, dev.id)
            if svc.status != "running" or skew > float(th.get("ntp_max_skew_seconds", 300)):
                alerts.append(AlertIn("NTPClockSkew", dev.id, service_id=svc.id, summary=f"W32Time {svc.status}, offset {skew:.0f}s"))
    since = now - timedelta(seconds=60)
    no_dc = [e for e in db.scalars(select(Event).where(Event.type == "AUTH_FAILURE", Event.ts >= since)) if (e.data or {}).get("status") == "0xC000005E"]
    if len(no_dc) >= int(th.get("auth_failure_burst", 3)):
        alerts.append(AlertIn("ADAuthenticationFailures", "DC01", service_id="ad-ds@DC01",
                              summary=f"{len(no_dc)} logon failures in 60 s: no logon servers available (0xC000005E)"))
    burst: dict[str, list[Event]] = {}
    for e in db.scalars(select(Event).where(Event.type == "AUTH_FAILURE", Event.ts >= now - timedelta(seconds=120))):
        if (e.data or {}).get("status") != "0xC000005E" and e.target:
            burst.setdefault(e.target, []).append(e)
    for target, evs in burst.items():
        if len(evs) >= 8:
            users = sorted({e.user_id for e in evs if e.user_id})
            alerts.append(AlertIn("RepeatedAuthFailures", target, summary=f"{len(evs)} failed logons in 2 min for {', '.join(users)}",
                                  labels={"user": ", ".join(users), "count": len(evs)}))
    for dev in devices.values():
        if dev.managed and not dev.reachable:
            alerts.append(AlertIn("NodeDown", dev.id, summary=f"{dev.id} not answering ARP/ICMP from MON01"))
            continue
        for mount, pct in ((dev.metrics or {}).get("disk", {}) or {}).items():
            if pct >= float(th.get("disk_critical_percent", 90)):
                alerts.append(AlertIn("DiskSpaceCritical", dev.id, summary=f"{mount} at {pct:.0f}% on {dev.id}", labels={"mount": mount}))
        hist = list(ctx.runtime.metric_history.get(dev.id, []))[-3:]
        if len(hist) == 3 and all((h.get("cpu") or 0) >= float(th.get("cpu_critical_percent", 92)) for h in hist):
            alerts.append(AlertIn("HighCPU", dev.id, summary=f"CPU >= {th.get('cpu_critical_percent', 92)}% for 3 consecutive samples"))
        if dev.kind == "server" and dev.managed:
            owned = {int(p) for svc in db.scalars(select(Service).where(Service.device_id == dev.id)) for p in svc.ports}
            if dev.id == "LINUX01":
                owned |= {int(p) for p in world.config(db, "LINUX01", "nginx").get("listen", []) if isinstance(p, int)}
            for port in sorted(set(dev.observed_ports or []) - set(dev.expected_ports or []) - owned):
                alerts.append(AlertIn("UnexpectedService", dev.id, summary=f"TCP/{port} listening on {dev.id} (not in baseline)", labels={"port": port}))
    for cert in db.scalars(select(Certificate)):
        days = (cert.not_after - now).total_seconds() / 86400
        if days < 0:
            alerts.append(AlertIn("CertificateExpired", cert.device_id, summary=f"{cert.id} expired {-days:.1f} days ago", labels={"certificate": cert.id}))
        elif days <= float(th.get("cert_warning_days", 14)):
            alerts.append(AlertIn("CertificateExpiring", cert.device_id, summary=f"{cert.id} expires in {days:.0f} days", labels={"certificate": cert.id}))
    for vlan in db.scalars(select(Vlan).where(Vlan.dhcp_enabled.is_(True))):
        if vlan.dhcp_pool_size and 100 * vlan.dhcp_in_use / vlan.dhcp_pool_size >= float(th.get("dhcp_pool_critical_percent", 95)):
            alerts.append(AlertIn("DHCPPoolExhausted", "PFSENSE", summary=f"VLAN {vlan.id} pool {vlan.dhcp_in_use}/{vlan.dhcp_pool_size} in use",
                                  labels={"vlan": str(vlan.id)}))
    if not ctx.firewall.available():
        alerts.append(AlertIn("FirewallUnreachable", "PFSENSE", summary="pfSense API not responding; NEXUS is preserving last known safe state"))
    return alerts


def scan(ctx: Context, db: Session) -> dict[str, Any]:
    found = collect(ctx, db)
    firing = set()
    new = []
    for a in found:
        before = a.service_id
        alert = ingest_alert(ctx, db, a)
        firing.add(fingerprint(a.name, a.target, a.service_id or before, a.labels))
        if alert is not None and alert.count == 1 and alert.status == "FIRING":
            new.append(alert.id)
    cleared = resolve_cleared(ctx, db, SOURCE, firing)
    statuses = update_statuses(ctx, db)
    ctx.runtime.detection_count += 1
    return {"firing": len(firing), "new": new, "cleared": cleared, "statuses": statuses}

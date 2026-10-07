"""Troubleshooting Center: practical guides with live NEXUS checks evaluated against current state."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, DriftEvent, Service, Vlan

if TYPE_CHECKING:
    from nexus.core.context import Context

GUIDES: list[dict[str, Any]] = [
    {"id": "no-internet", "title": "No Internet", "symptoms": ["Browsers time out", "Internal sites still work"],
     "evidence": ["Default route on client", "pfSense WAN status", "DNS forwarders on DC01"],
     "causes": ["pfSense WAN down", "DNS forwarder unreachable", "Client has APIPA address (wrong VLAN / no DHCP)"],
     "commands": ["ipconfig /all", "Test-NetConnection 1.1.1.1 -Port 443", "Resolve-DnsName example.com", "tracert 1.1.1.1"],
     "nexus_checks": ["gateway", "dns", "client_vlan"], "resolution": ["Fix WAN/upstream", "Correct switchport VLAN", "Restore DNS forwarders"],
     "verification": ["Test-NetConnection succeeds", "DNS resolves external names"]},
    {"id": "cannot-access-server", "title": "Cannot access server", "symptoms": ["Connection refused or timeout to a server port"],
     "evidence": ["Active lease for user/device/port", "Firewall rule matched", "Service listening on port"],
     "causes": ["No active lease (expired or never requested)", "Device risk above policy threshold", "Service stopped", "Host firewall dropping packets"],
     "commands": ["Test-NetConnection LINUX01 -Port 22", "ss -tlnp (on server)", "nexusctl explain access <user> <device> <server> <port>"],
     "nexus_checks": ["leases", "services"], "resolution": ["Request a lease from the Access page", "Lower risk (resolve incidents/drift)", "Restart the service"],
     "verification": ["Explain Access shows ALLOW", "TCP connect succeeds"]},
    {"id": "ad-login-failure", "title": "AD login failure", "symptoms": ["'The trust relationship failed' or 'no logon servers available'"],
     "evidence": ["Event 4625 sub-status", "DNS SRV records", "Clock skew vs DC01"],
     "causes": ["DNS failure (DCs not locatable)", "Clock skew > 5 min (Kerberos)", "Account locked (0xC0000234)", "Bad password (0xC000006A)"],
     "commands": ["nltest /dsgetdc:corp.nexus.lab", "w32tm /query /status", "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20"],
     "nexus_checks": ["dns", "ntp", "ad"], "resolution": ["Restore DNS", "Resync time", "Unlock account / reset password"],
     "verification": ["4624 logon succeeds", "nltest returns DC01"]},
    {"id": "dns-failure", "title": "DNS failure", "symptoms": ["Names do not resolve", "Logins and the portal fail at the same time"],
     "evidence": ["DNS service state on DC01", "UDP/53 reachability"], "causes": ["DNS Server service stopped", "Zone not loaded", "Firewall blocking 53"],
     "commands": ["Resolve-DnsName dc01.corp.nexus.lab -Server 10.20.20.10", "Get-Service DNS", "dcdiag /test:dns"],
     "nexus_checks": ["dns"], "resolution": ["Restart-Service DNS (NEXUS does this automatically when verified down)"],
     "verification": ["Resolve-DnsName succeeds", "Correlated AD/portal symptoms clear"]},
    {"id": "dhcp-problem", "title": "DHCP problem", "symptoms": ["Clients get 169.254.x.x", "New devices cannot join"],
     "evidence": ["DHCP pool utilisation", "Duplicate address events"], "causes": ["Pool exhausted", "Wrong VLAN on switchport", "Rogue DHCP/static IP conflict"],
     "commands": ["ipconfig /renew", "show interface status (switch)", "pfSense > Status > DHCP Leases"],
     "nexus_checks": ["dhcp_pool", "client_vlan"], "resolution": ["Reclaim stale leases", "Fix switchport VLAN", "Quarantine rogue device"],
     "verification": ["Client receives an address in the right subnet"]},
    {"id": "ssh-unavailable", "title": "SSH unavailable", "symptoms": ["ssh: connect to host port 22: Connection refused"],
     "evidence": ["sshd status", "sshd -t output", "Active lease"], "causes": ["sshd stopped", "Invalid sshd_config", "No lease / firewall"],
     "commands": ["systemctl status ssh", "sshd -t", "journalctl -u ssh -n 50"], "nexus_checks": ["ssh"],
     "resolution": ["Fix config, then restart (NEXUS restores the Git baseline when drift is the cause)"], "verification": ["TCP/22 open", "Login works"]},
    {"id": "nginx-unavailable", "title": "Nginx unavailable", "symptoms": ["Portal unreachable", "HTTP 502/connection refused"],
     "evidence": ["systemctl status nginx", "nginx -t", "Recent config change"], "causes": ["Process killed", "Bad config deploy", "Port blocked on host"],
     "commands": ["systemctl status nginx", "nginx -t", "ss -tlnp | grep -E ':(80|443)'", "curl -kI https://portal.corp.nexus.lab/healthz"],
     "nexus_checks": ["nginx"], "resolution": ["Restart (if config valid) or restore baseline config"], "verification": ["HTTP 200 on /healthz"]},
    {"id": "high-disk", "title": "High disk usage", "symptoms": ["Writes failing", "Services crash"], "evidence": ["df -h", "du of /var"],
     "causes": ["Runaway logs", "Old temporary files"], "commands": ["df -h", "du -xh --max-depth=2 /var | sort -rh | head"],
     "nexus_checks": ["disk"], "resolution": ["Rotate known logs; remove approved temporary files only"], "verification": ["Usage below 85%"]},
    {"id": "firewall-block", "title": "Firewall block", "symptoms": ["Timeouts only between specific VLANs"], "evidence": ["Matching rule (first match)", "Shadowed rules"],
     "causes": ["No allow rule/lease", "A broader rule earlier in the list", "Quarantine rule"], "commands": ["pfSense > Status > System Logs > Firewall"],
     "nexus_checks": ["firewall"], "resolution": ["Request a lease or fix rule order"], "verification": ["Policy test returns ALLOW"]},
    {"id": "unknown-device", "title": "Unknown device", "symptoms": ["New MAC on a user port", "Unidentified hostname"],
     "evidence": ["Identity confidence signals", "Port activity"], "causes": ["Personal device", "Rogue device", "New asset not yet enrolled"],
     "commands": ["show mac address-table interface Gi1/0/14", "Get-ADComputer -Filter *"], "nexus_checks": ["unknown_devices"],
     "resolution": ["Enroll the asset (AD + inventory) or remove it; release quarantine after review"], "verification": ["Identity confidence >= 80%"]},
    {"id": "config-drift", "title": "Configuration drift", "symptoms": ["Baseline compliance fails"], "evidence": ["Desired vs actual diff", "SHA-256 checksums"],
     "causes": ["Manual change", "Deploy pipeline", "Maintenance not closed"], "commands": ["git log baselines/", "nexusctl drift scan"],
     "nexus_checks": ["drift"], "resolution": ["Remediate to Git intent, or update Git if the change is intended"], "verification": ["Checksums match"]},
]


def _svc(db: Session, sid: str) -> str:
    s = db.get(Service, sid)
    return s.status if s else "absent"


def live_checks(ctx: Context, db: Session) -> dict[str, dict[str, Any]]:
    vlan30 = db.get(Vlan, 30)
    unknown = db.scalars(select(Device.id).where(Device.kind == "unknown")).all()
    drift = db.scalars(select(DriftEvent.id).where(DriftEvent.status.in_(("OPEN", "APPROVAL_REQUIRED", "FAILED")))).all()
    disks = {d.id: max(((d.metrics or {}).get("disk") or {"-": 0}).values()) for d in db.scalars(select(Device))}
    wrong_vlan = [d.id for d in db.scalars(select(Device).where(Device.kind == "workstation")) if d.vlan_id != d.expected_vlan_id and not d.quarantined]
    checks = {
        "gateway": (db.get(Device, "PFSENSE").reachable, "pfSense reachable"),  # type: ignore[union-attr]
        "dns": (_svc(db, "dns@DC01") == "running", f"DNS on DC01 is {_svc(db, 'dns@DC01')}"),
        "ntp": (ctx.world.clock_skew(db, "DC01") < 300, f"DC01 offset {ctx.world.clock_skew(db, 'DC01'):.0f}s"),
        "ad": (_svc(db, "ad-ds@DC01") == "running", f"AD DS is {_svc(db, 'ad-ds@DC01')}"),
        "ssh": (_svc(db, "ssh@LINUX01") == "running", f"ssh@LINUX01 {_svc(db, 'ssh@LINUX01')}"),
        "nginx": (_svc(db, "nginx@LINUX01") == "running", f"nginx@LINUX01 {_svc(db, 'nginx@LINUX01')}"),
        "disk": (max(disks.values()) < 85, "peak disk " + ", ".join(f"{k} {v:.0f}%" for k, v in sorted(disks.items(), key=lambda kv: -kv[1])[:2])),
        "dhcp_pool": (bool(vlan30 and vlan30.dhcp_in_use / max(vlan30.dhcp_pool_size, 1) < 0.9), f"VLAN 30 pool {vlan30.dhcp_in_use}/{vlan30.dhcp_pool_size}" if vlan30 else "-"),
        "client_vlan": (not wrong_vlan, "workstations in expected VLANs" if not wrong_vlan else f"wrong VLAN: {', '.join(wrong_vlan)}"),
        "firewall": (ctx.firewall.available(), "firewall API reachable" if ctx.firewall.available() else "firewall API unreachable"),
        "leases": (True, "see Access page for active leases"),
        "services": (True, "see Devices for service states"),
        "unknown_devices": (not unknown, f"unknown: {', '.join(unknown)}" if unknown else "no unknown devices"),
        "drift": (not drift, f"open drift: {', '.join(drift)}" if drift else "no open drift"),
    }
    return {k: {"ok": bool(v[0]), "detail": v[1]} for k, v in checks.items()}


def guides(ctx: Context, db: Session) -> list[dict[str, Any]]:
    live = live_checks(ctx, db)
    return [g | {"live": [{"check": c, **live[c]} for c in g["nexus_checks"] if c in live]} for g in GUIDES]

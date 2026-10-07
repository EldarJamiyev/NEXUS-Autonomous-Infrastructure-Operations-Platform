"""Simulated enterprise physics.

The World owns the *actual* state of the fictional infrastructure: service processes, host
configuration files, disks, switch ports, DHCP pools and faults. Chaos scenarios change the
World; NEXUS then has to *observe* those changes through its adapters (monitoring scans,
FIM/config events, DHCP/ARP/syslog observations) exactly as it would in a real network.

Rule: NEXUS engines never read `Device.sim_faults`. Only the World, the simulated executor and
the simulated probes do - they are the "laws of physics" of the simulation.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.util import sha256_of, stable_hash
from nexus.models import Certificate, ConfigItem, Device, FirewallRule, Interface, IpAddress, Service, Vlan
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context

UPSTREAM_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")
SIM_SOURCE = "simulation"


def _copy(value: Any) -> Any:
    import copy

    return copy.deepcopy(value)


class World:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------ helpers
    def now(self) -> datetime:
        return self.ctx.clock.now()

    def service(self, db: Session, service_id: str) -> Service:
        svc = db.get(Service, service_id)
        if svc is None:
            raise KeyError(f"unknown service {service_id}")
        return svc

    def config(self, db: Session, device_id: str, component: str) -> dict[str, Any]:
        item = db.get(ConfigItem, f"{device_id}:{component}")
        return _copy(item.actual) if item else {}

    def write_config(self, db: Session, device_id: str, component: str, actual: dict[str, Any], actor: str,
                     observe: bool = True, reason: str = "") -> ConfigItem:
        item = db.get(ConfigItem, f"{device_id}:{component}")
        before = item.checksum if item else None
        if item is None:
            item = ConfigItem(id=f"{device_id}:{component}", device_id=device_id, component=component, actual={},
                              checksum="", updated_at=self.now())
            db.add(item)
        item.actual = _copy(actual)
        item.checksum = sha256_of(actual)
        item.updated_at = self.now()
        item.updated_by = actor
        db.flush()
        if observe and before != item.checksum:
            # A host file-integrity agent (osquery/auditd/Wazuh in a real lab) reports the change.
            from nexus.network.discovery import observe_config_change

            observe_config_change(self.ctx, db, device_id, component, before, item.checksum, actor, reason)
        return item

    def set_config(self, db: Session, device_id: str, component: str, changes: dict[str, Any], actor: str,
                   reason: str = "") -> ConfigItem:
        current = self.config(db, device_id, component)
        current.update(changes)
        return self.write_config(db, device_id, component, current, actor, reason=reason)

    def faults(self, device: Device) -> dict[str, Any]:
        return dict(device.sim_faults or {})

    def add_fault(self, db: Session, device_id: str, key: str, value: Any) -> None:
        dev = db.get(Device, device_id)
        if dev:
            faults = self.faults(dev)
            faults[key] = value
            dev.sim_faults = faults

    def clear_fault(self, db: Session, device_id: str, key: str) -> None:
        dev = db.get(Device, device_id)
        if dev and key in (dev.sim_faults or {}):
            faults = self.faults(dev)
            faults.pop(key, None)
            dev.sim_faults = faults

    # ------------------------------------------------------------- validators
    def validate_nginx(self, db: Session, device_id: str) -> tuple[bool, str]:
        cfg = self.config(db, device_id, "nginx")
        files = set(self.config(db, device_id, "host_files").get("paths", []))
        for port in cfg.get("listen", []):
            if not isinstance(port, int) or not 0 < port < 65536:
                return False, f"nginx: [emerg] invalid listen port \"{port}\""
        upstream = str(cfg.get("upstream", ""))
        if not UPSTREAM_RE.match(upstream):
            return False, f"nginx: [emerg] invalid port in upstream \"{upstream}\" in /etc/nginx/conf.d/portal.conf:4"
        cert = cfg.get("ssl_certificate")
        if cert and cert not in files:
            return False, f"nginx: [emerg] cannot load certificate \"{cert}\": No such file or directory"
        return True, "nginx: configuration file /etc/nginx/nginx.conf test is successful"

    def validate_sshd(self, db: Session, device_id: str) -> tuple[bool, str]:
        cfg = self.config(db, device_id, "ssh")
        files = set(self.config(db, device_id, "host_files").get("paths", []))
        for key in ("PermitRootLogin", "PasswordAuthentication", "X11Forwarding"):
            if cfg.get(key) not in ("yes", "no", "prohibit-password", None):
                return False, f"/etc/ssh/sshd_config: Bad {key} value '{cfg.get(key)}'"
        port = cfg.get("Port", 22)
        if not isinstance(port, int) or not 0 < port < 65536:
            return False, f"/etc/ssh/sshd_config: Badly formatted port number '{port}'"
        host_key = cfg.get("HostKey")
        if host_key and host_key not in files:
            return False, f"sshd: no hostkeys available -- exiting ({host_key} missing)"
        return True, "sshd -t: configuration OK"

    # ---------------------------------------------------------------- services
    def stop_service(self, db: Session, service_id: str, reason: str, status: str = "stopped") -> Service:
        svc = self.service(db, service_id)
        svc.status = status
        svc.health_detail = reason
        svc.last_change = self.now()
        return svc

    def start_service(self, db: Session, service_id: str) -> tuple[int, str]:
        """Emulates `systemctl start/restart`. Returns (exit_code, output)."""
        svc = self.service(db, service_id)
        dev = db.get(Device, svc.device_id)
        if dev is None or not dev.reachable:
            return 255, f"ssh: connect to host {svc.device_id} port 22: No route to host"
        faults = self.faults(dev)
        if svc.name == "nginx":
            ok, msg = self.validate_nginx(db, svc.device_id)
            if not ok:
                svc.status = "failed"
                svc.health_detail = msg
                return 1, f"Job for nginx.service failed because the control process exited with error code.\n{msg}"
        if svc.name == "ssh":
            ok, msg = self.validate_sshd(db, svc.device_id)
            if not ok:
                svc.status = "failed"
                svc.health_detail = msg
                return 255, msg
        if faults.get("start_fails", {}).get(svc.name):
            svc.status = "failed"
            return 1, faults["start_fails"][svc.name]
        svc.status = "running"
        svc.health_detail = ""
        svc.last_change = self.now()
        return 0, ""

    def disable_service(self, db: Session, service_id: str, actor: str) -> None:
        svc = self.service(db, service_id)
        svc.enabled = False
        self.stop_service(db, service_id, "unit disabled and stopped")
        cfg = self.config(db, svc.device_id, "services")
        cfg.setdefault(svc.name, {})["enabled"] = False
        self.write_config(db, svc.device_id, "services", cfg, actor, reason=f"systemctl disable --now {svc.unit}")

    def enable_service(self, db: Session, service_id: str, actor: str) -> tuple[int, str]:
        svc = self.service(db, service_id)
        svc.enabled = True
        cfg = self.config(db, svc.device_id, "services")
        cfg.setdefault(svc.name, {})["enabled"] = True
        self.write_config(db, svc.device_id, "services", cfg, actor, reason=f"systemctl enable {svc.unit}")
        return self.start_service(db, service_id)

    # ------------------------------------------------------------- observable probes
    def listening_ports(self, db: Session, device: Device) -> list[int]:
        ports: set[int] = set()
        for svc in db.scalars(select(Service).where(Service.device_id == device.id)):
            if svc.status == "running":
                ports.update(int(p) for p in svc.ports)
        if device.id == "LINUX01":
            nginx = self.config(db, "LINUX01", "nginx")
            web = db.get(Service, "nginx@LINUX01")
            if web and web.status == "running":
                ports.difference_update({80, 443})
                ports.update(int(p) for p in nginx.get("listen", []) if isinstance(p, int))
        ports.update(int(p) for p in self.faults(device).get("extra_ports", {}))
        return sorted(ports)

    def tcp_reachable(self, db: Session, device_id: str, port: int) -> tuple[bool, str]:
        dev = db.get(Device, device_id)
        if dev is None:
            return False, "unknown host"
        if not dev.reachable:
            return False, f"{device_id} unreachable (no ARP reply)"
        if port in self.faults(dev).get("host_firewall_drop", []):
            return False, f"TCP/{port} connection timed out (packets dropped on host)"
        if port not in self.listening_ports(db, dev):
            return False, f"TCP/{port} connection refused"
        return True, f"TCP/{port} open"

    def http_status(self, db: Session, device_id: str, port: int) -> tuple[int | None, str]:
        ok, detail = self.tcp_reachable(db, device_id, port)
        if not ok:
            return None, detail
        if device_id == "LINUX01":
            return 200, "GET /healthz -> 200 OK (nginx)"
        if device_id == "APP01" and port == 8080:
            unhealthy = self.portal_blockers(db)
            if unhealthy:
                return 503, "GET /health -> 503 (" + ", ".join(unhealthy) + ")"
            return 200, "GET /health -> 200 OK"
        return 200, "200 OK"

    def portal_blockers(self, db: Session) -> list[str]:
        blockers = []
        for dep in ("ad-ds@DC01", "dns@DC01", "postgresql@APP01", "docker@APP01"):
            svc = db.get(Service, dep)
            if svc and svc.status != "running":
                blockers.append(f"{dep} {svc.status}")
        return blockers

    def dns_resolves(self, db: Session, hostname: str) -> bool:
        dns = db.get(Service, "dns@DC01")
        return bool(dns and dns.status == "running")

    def clock_skew(self, db: Session, device_id: str) -> float:
        dev = db.get(Device, device_id)
        return float(self.faults(dev).get("clock_skew_s", 0.0)) if dev else 0.0

    # ----------------------------------------------------------------- network
    def interface_for(self, db: Session, device_id: str) -> Interface | None:
        return db.scalar(select(Interface).where(Interface.device_id == device_id))

    def _free_ip(self, db: Session, vlan: Vlan, preferred_host: int | None) -> str:
        net = ipaddress.ip_network(vlan.subnet)
        used = {r.address for r in db.scalars(select(IpAddress).where(IpAddress.vlan_id == vlan.id))}
        hosts = list(net.hosts())
        if preferred_host is not None:
            candidate = str(hosts[0] + (preferred_host - 1))
            if candidate not in used and preferred_host > 1:
                return candidate
        for h in hosts[19:]:
            if str(h) not in used:
                return str(h)
        raise RuntimeError(f"DHCP pool exhausted on VLAN {vlan.id}")

    def move_to_vlan(self, db: Session, device_id: str, vlan_id: int, actor: str) -> str:
        """Change the access VLAN of the device's switch port. DHCP clients renew their address."""
        dev = db.get(Device, device_id)
        iface = self.interface_for(db, device_id)
        vlan = db.get(Vlan, vlan_id)
        if dev is None or iface is None or vlan is None:
            raise KeyError("device, interface or VLAN not found")
        old_ip = db.scalar(select(IpAddress).where(IpAddress.device_id == device_id))
        old_host = int(old_ip.address.split(".")[-1]) if old_ip and not old_ip.address.startswith("169.254") else None
        mac = old_ip.mac if old_ip else None
        if old_ip:
            db.delete(old_ip)
            db.flush()
        iface.vlan_id = vlan_id
        dev.vlan_id = vlan_id
        reserved = self.reservation(device_id)
        if vlan.dhcp_enabled and reserved and ipaddress.ip_address(reserved) in ipaddress.ip_network(vlan.subnet) \
                and db.get(IpAddress, reserved) is None:
            address = reserved
            assignment = "dhcp"
        elif vlan.dhcp_enabled:
            address = self._free_ip(db, vlan, old_host)
            assignment = "dhcp"
        else:
            address = f"169.254.{stable_hash(device_id) % 250 + 1}.{(old_host or 7) % 250 + 1}"
            assignment = "apipa"
        db.add(IpAddress(address=address, device_id=device_id, mac=mac, vlan_id=vlan_id if assignment != "apipa" else None,
                         assignment=assignment, dhcp_hostname=dev.expected_hostname if assignment == "dhcp" else None,
                         updated_at=self.now()))
        cfg = self.config(db, "SW-CORE01", "switchports")
        cfg[iface.name] = {"vlan": vlan_id, "device": device_id}
        self.write_config(db, "SW-CORE01", "switchports", cfg, actor, reason=f"interface {iface.name} switchport access vlan {vlan_id}")
        db.flush()
        return address

    def attach_endpoint(self, db: Session, mac: str, interface_name: str, ip: str | None, hostname: str | None,
                        vendor: str = "Unknown", claim_static_ip: bool = False) -> None:
        """Plug an endpoint into a switch port. NEXUS learns about it from ARP/DHCP observations."""
        from nexus.network.discovery import observe_arp, observe_dhcp_assignment

        iface = db.get(Interface, f"SW-CORE01:{interface_name}")
        if iface is None:
            raise KeyError(interface_name)
        vlan = db.get(Vlan, iface.vlan_id)
        if ip is None:
            if vlan is None:
                raise ValueError(f"{interface_name} has no VLAN to address the endpoint from")
            ip = self._free_ip(db, vlan, None)
        if not claim_static_ip and vlan is not None:
            vlan.dhcp_in_use += 1
            observe_dhcp_assignment(self.ctx, db, mac=mac, ip=ip, hostname=hostname, vlan_id=vlan.id, vendor=vendor,
                                    interface_id=iface.id)
        observe_arp(self.ctx, db, mac=mac, ip=ip, interface_id=iface.id, vendor=vendor)

    def set_reachable(self, db: Session, device_id: str, reachable: bool) -> None:
        dev = db.get(Device, device_id)
        if dev:
            dev.reachable = reachable

    def open_port(self, db: Session, device_id: str, port: int, process: str) -> None:
        dev = db.get(Device, device_id)
        if dev:
            faults = self.faults(dev)
            extra = dict(faults.get("extra_ports", {}))
            extra[str(port)] = process
            faults["extra_ports"] = extra
            dev.sim_faults = faults

    def close_port(self, db: Session, device_id: str, port: int) -> None:
        dev = db.get(Device, device_id)
        if dev:
            faults = self.faults(dev)
            extra = dict(faults.get("extra_ports", {}))
            extra.pop(str(port), None)
            faults["extra_ports"] = extra
            dev.sim_faults = faults

    def inject_firewall_rule(self, db: Session, rule_id: str, action: str, source: str, destination: str, protocol: str,
                             port: str, actor: str, position: int = 120) -> FirewallRule:
        """A change made directly on the firewall, bypassing NEXUS (unauthorized from NEXUS's point of view)."""
        from nexus.network.discovery import observe_firewall_change

        rule = FirewallRule(id=rule_id, position=position, action=action, source=source, destination=destination,
                            protocol=protocol, port=port, description="added via webConfigurator", origin="manual",
                            created_at=self.now(), created_by=actor)
        db.add(rule)
        db.flush()
        observe_firewall_change(self.ctx, db, rule, actor)
        return rule

    # ---------------------------------------------------------------- identity
    def logon(self, db: Session, user_id: str, device_id: str) -> None:
        from nexus.identity.ingest import ingest_windows_event

        ip = db.scalar(select(IpAddress.address).where(IpAddress.device_id == device_id))
        ingest_windows_event(self.ctx, db, {"EventID": 4624, "TargetUserName": user_id, "WorkstationName": device_id,
                                            "IpAddress": ip, "LogonType": 2, "Computer": "DC01"}, source=SIM_SOURCE)

    def logoff(self, db: Session, user_id: str, device_id: str) -> None:
        from nexus.identity.ingest import ingest_windows_event

        ingest_windows_event(self.ctx, db, {"EventID": 4647, "TargetUserName": user_id, "WorkstationName": device_id,
                                            "Computer": device_id}, source=SIM_SOURCE)

    def auth_failures(self, db: Session, user_id: str, device_id: str, count: int, status: str = "0xC000006A") -> None:
        from nexus.identity.ingest import ingest_windows_event

        ip = db.scalar(select(IpAddress.address).where(IpAddress.device_id == device_id))
        for _ in range(count):
            ingest_windows_event(self.ctx, db, {"EventID": 4625, "TargetUserName": user_id, "WorkstationName": device_id,
                                                "IpAddress": ip, "LogonType": 3, "Status": "0xC000006D",
                                                "SubStatus": status, "Computer": "DC01"}, source=SIM_SOURCE)

    # -------------------------------------------------------------- facilities
    def set_disk(self, db: Session, device_id: str, mount: str, pct: float) -> None:
        dev = db.get(Device, device_id)
        if dev:
            metrics = dict(dev.metrics or {})
            disks = dict(metrics.get("disk", {}))
            disks[mount] = round(pct, 1)
            metrics["disk"] = disks
            dev.metrics = metrics

    def set_certificate_expiry(self, db: Session, cert_id: str, not_after: datetime) -> None:
        cert = db.get(Certificate, cert_id)
        if cert:
            cert.not_after = not_after

    def set_dhcp_usage(self, db: Session, vlan_id: int, in_use: int, stale: int) -> None:
        vlan = db.get(Vlan, vlan_id)
        if vlan:
            vlan.dhcp_in_use = in_use
            vlan.dhcp_stale = stale

    # --------------------------------------------------------------------- tick
    BASE_CPU = {"server": 17, "workstation": 11, "firewall": 8, "switch": 6, "unknown": 4}

    def cpu_now(self, dev: Device) -> float:
        t = self.now().timestamp()
        h = stable_hash(dev.id)
        if self.faults(dev).get("cpu_hog"):
            return 95.5 + (int(t) % 4) * 0.8
        cpu = self.BASE_CPU.get(dev.kind, 10) + 6 * math.sin(t / 97 + h % 7) + 3 * math.sin(t / 23 + h % 5) + ((h + int(t / 2)) % 7) / 3
        return round(max(0.5, cpu), 1)

    def reservation(self, device_id: str) -> str | None:
        if not hasattr(self, "_reservations"):
            import yaml

            path = self.ctx.settings.config_root / "simulation" / "enterprise.yaml"
            data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else {}
            self._reservations = {d["id"]: d.get("ip") for d in data.get("devices", [])}
        return self._reservations.get(device_id)

    def tick(self, db: Session) -> dict[str, dict[str, Any]]:
        """Advance continuous signals (CPU, memory, traffic, latency) and generate fault symptoms."""
        now = self.now()
        t = now.timestamp()
        snapshot: dict[str, dict[str, Any]] = {}
        for dev in db.scalars(select(Device)):
            faults = self.faults(dev)
            metrics = dict(dev.metrics or {})
            h = stable_hash(dev.id)
            if not dev.reachable:
                metrics.update({"cpu": None, "mem": None, "latency_ms": None, "packet_loss": 100.0})
            else:
                cpu = self.cpu_now(dev)
                mem = 34 + h % 27 + 4 * math.sin(t / 180 + h % 3)
                disks = dict(metrics.get("disk", {}))
                growth = faults.get("log_growth")
                if growth and growth in disks:
                    disks[growth] = min(99.0, round(disks[growth] + 0.2, 1))
                traffic = {"firewall": 5200, "switch": 8100, "server": 1400, "workstation": 260}.get(dev.kind, 40)
                metrics.update({
                    "cpu": round(max(0.5, cpu), 1),
                    "mem": round(mem, 1),
                    "disk": disks,
                    "net_in_kbps": round(traffic * (1 + 0.35 * math.sin(t / 41 + h % 11)), 0),
                    "net_out_kbps": round(traffic * 0.62 * (1 + 0.3 * math.sin(t / 37 + h % 13)), 0),
                    "latency_ms": round(0.35 + (h % 10) / 25 + 0.15 * (1 + math.sin(t / 31 + h % 3)), 2),
                    "packet_loss": 0.0,
                })
            dev.metrics = metrics
            snapshot[dev.id] = metrics
            hist = self.ctx.runtime.metric_history.setdefault(dev.id, deque(maxlen=180))
            hist.append({"ts": now.isoformat(), "cpu": metrics.get("cpu"), "mem": metrics.get("mem"),
                         "net": metrics.get("net_in_kbps"), "latency": metrics.get("latency_ms")})
        self._symptoms(db)
        return snapshot

    def _symptoms(self, db: Session) -> None:
        """Downstream effects of failures that real systems would log (auth failures during a DNS outage)."""
        dns = db.get(Service, "dns@DC01")
        ad = db.get(Service, "ad-ds@DC01")
        if (dns and dns.status != "running") or (ad and ad.status != "running"):
            sessions = db.scalars(select(UserSession).where(UserSession.active.is_(True))).all()
            tick_no = int(self.now().timestamp() / max(self.ctx.settings.sim_tick_interval, 0.5))
            for s in sessions:
                if (stable_hash(s.user_id) + tick_no) % 3 == 0:
                    self.auth_failures(db, s.user_id, s.device_id, 1, status="0xC000005E")
        ntp = db.get(Service, "ntp@DC01")
        if ntp and ntp.status != "running":
            dc = db.get(Device, "DC01")
            if dc:
                faults = self.faults(dc)
                faults["clock_skew_s"] = round(float(faults.get("clock_skew_s", 0)) + 45.0, 1)
                dc.sim_faults = faults

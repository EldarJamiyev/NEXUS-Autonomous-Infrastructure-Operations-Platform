"""Verification and precondition probes.

Success is never inferred from an exit code: every remediation is verified by probing the
desired end state (process, port, HTTP, config checksum, firewall policy test, VLAN membership).
In simulation the probes observe the simulated World; `NetworkProbes` shows the real-lab path
(real TCP connect / HTTP GET) for the same probe names.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nexus.firewall.base import FirewallUnavailable
from nexus.models import Device, IpAddress, Lease, Service, Vlan

if TYPE_CHECKING:
    from nexus.core.context import Context

TEST_SOURCE = "10.30.30.250"  # an address in the user VLAN that holds no lease


def _r(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"probe": name, "passed": bool(passed), "detail": detail}


class Probes:
    mode = "SIMULATION"

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------- helpers
    def _ip(self, db: Session, device_id: str) -> str | None:
        return db.scalar(select(IpAddress.address).where(IpAddress.device_id == device_id))

    def _fw(self, db: Session, src: str | None, dst_device: str, port: int, protocol: str = "TCP") -> tuple[str, str]:
        from nexus.firewall.addressing import evaluate
        from nexus.policy.compiler import resolver

        rules = self.ctx.firewall.list_rules(db)
        action, rule = evaluate(resolver(self.ctx, db), rules, src, self._ip(db, dst_device) or dst_device, protocol, port)
        return action, rule["id"] if rule else "implicit deny"

    # ---------------------------------------------------------- verification
    def check(self, db: Session, target: str, spec: dict[str, Any], tx: Any = None) -> dict[str, Any]:
        name = spec["probe"]
        try:
            return getattr(self, f"p_{name}")(db, target, spec, tx)
        except FirewallUnavailable as exc:
            return _r(name, False, f"cannot verify: {exc}")
        except Exception as exc:  # noqa: BLE001 - a broken probe is a failed verification, never a pass
            return _r(name, False, f"probe error: {exc}")

    def p_service_running(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        svc = db.get(Service, f"{s['service']}@{t}")
        return _r("service_running", bool(svc and svc.status == "running"), f"{s['service']} is {svc.status if svc else 'absent'}")

    def p_service_enabled(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        svc = db.get(Service, f"{s['service']}@{t}")
        return _r("service_enabled", bool(svc and svc.enabled), f"{s['service']} {'enabled' if svc and svc.enabled else 'disabled'}")

    def p_tcp(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        ok, detail = self.ctx.world.tcp_reachable(db, t, int(s["port"]))
        return _r(f"tcp/{s['port']}", ok, detail)

    def p_http(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        code, detail = self.ctx.world.http_status(db, t, int(s["port"]))
        return _r(f"http/{s['port']}", code == int(s.get("expect", 200)), detail if code is None else f"HTTP {code} ({detail})")

    def p_config_valid(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        fn = self.ctx.world.validate_nginx if s["component"] == "nginx" else self.ctx.world.validate_sshd
        ok, msg = fn(db, t)
        return _r(f"{s['component']} syntax", ok, msg)

    def p_config_matches(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        from nexus.drift.engine import config_matches

        ok, want, have = config_matches(self.ctx, db, t, s["component"])
        return _r(f"{s['component']} = git intent", ok, f"sha256 expected {want[:12]} actual {have[:12]} match {'YES' if ok else 'NO'}")

    def p_disk_below(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        dev = db.get(Device, t)
        disks = (dev.metrics or {}).get("disk", {}) if dev else {}
        worst = max(disks.items(), key=lambda kv: kv[1]) if disks else ("-", 0)
        return _r("disk usage", worst[1] < float(s["threshold"]), f"{worst[0]} at {worst[1]:.0f}% (threshold {s['threshold']}%)")

    def p_cpu_below(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        dev = db.get(Device, t)
        cpu = self.ctx.world.cpu_now(dev) if dev else 100.0
        return _r("cpu", cpu < float(s["threshold"]), f"CPU {cpu:.0f}% (threshold {s['threshold']}%)")

    def p_dns_resolves(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        ok = self.ctx.world.dns_resolves(db, s["name"])
        return _r("dns lookup", ok, f"{s['name']} -> {self._ip(db, 'DC01') if ok else 'SERVFAIL'}")

    def p_ntp_skew_below(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        skew = self.ctx.world.clock_skew(db, t)
        return _r("ntp offset", skew < float(s["seconds"]), f"offset {skew:.1f}s")

    def p_monitoring_target_up(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        svc = db.get(Service, f"monitoring-agent@{t}")
        port = int(svc.ports[0]) if svc and svc.ports else 9100
        ok, detail = self.ctx.world.tcp_reachable(db, t, port)
        return _r("scrape target", bool(ok and svc and svc.status == "running"), f"up{{instance=\"{t}:{port}\"}} = {1 if ok else 0}")

    def p_in_vlan(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        dev = db.get(Device, t)
        want = s["vlan"]
        return _r("vlan membership", bool(dev and dev.vlan_id == want), f"{t} in VLAN {dev.vlan_id if dev else '?'} (expected {want})")

    def p_not_in_vlan(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        dev = db.get(Device, t)
        return _r("vlan membership", bool(dev and dev.vlan_id != s["vlan"]), f"{t} in VLAN {dev.vlan_id if dev else '?'}")

    def p_address_in_vlan(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        vlan = db.get(Vlan, s["vlan"])
        ip = self._ip(db, t)
        ok = bool(vlan and ip and ipaddress.ip_address(ip) in ipaddress.ip_network(vlan.subnet))
        return _r("address", ok, f"{t} has {ip or 'no address'}")

    def p_firewall_matches_desired(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        from nexus.drift.engine import firewall_diffs

        diffs = firewall_diffs(self.ctx, db)
        if diffs is None:
            return _r("ruleset = intent", False, "firewall unreachable")
        return _r("ruleset = intent", not diffs, "ruleset matches intent" if not diffs else f"{len(diffs)} difference(s) remain")

    def p_management_path(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        action, rule = self._fw(db, "10.10.10.5", "PFSENSE", 443)
        return _r("management path", action == "ALLOW", f"10.10.10.5 -> PFSENSE:443 {action} via {rule} (lockout protection)")

    def p_unauthorized_flow_denied(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        removed = [r for r in ((tx.post_state or {}).get("removed_rules", []) if tx else []) if r["action"] == "ALLOW"]
        if not removed:
            return _r("policy test", True, "no permissive rule was removed")
        r = removed[0]
        port = int(str(r["port"]).split(",")[0]) if str(r["port"]).upper() != "ANY" else 22
        src = TEST_SOURCE if str(r["source"]).upper() == "ANY" else r["source"]
        action, rule = self._fw(db, src, r["destination"], port, "TCP" if r["protocol"] == "ANY" else r["protocol"])
        return _r("policy test", action == "DENY", f"{src} -> {r['destination']}:{port} now {action} ({rule})")

    def p_policy_test(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        src = self._ip(db, t)
        action, rule = self._fw(db, src, s["destination"], int(s["port"]))
        return _r("policy test", action == s.get("expect", "DENY"), f"{t} ({src}) -> {s['destination']}:{s['port']} {action} via {rule}")

    def p_no_active_leases(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        n = db.scalar(select(func.count()).select_from(Lease).where(Lease.device_id == t, Lease.status == "ACTIVE")) or 0
        return _r("leases", n == 0, f"{n} active lease(s) from {t}")

    def p_lease_rule_absent(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        lease = db.get(Lease, s["lease"])
        rules = {r["id"] for r in self.ctx.firewall.list_rules(db)}
        ok = bool(lease and (not lease.firewall_rule_id or lease.firewall_rule_id not in rules))
        return _r("lease rule removed", ok, f"rule {lease.firewall_rule_id if lease else '?'} {'absent' if ok else 'still present'}")

    def p_port_blocked(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        action, rule = self._fw(db, TEST_SOURCE, t, int(s["port"]))
        return _r("policy test", action == "DENY", f"{TEST_SOURCE} -> {t}:{s['port']} {action} via {rule}")

    def p_dhcp_pool_below(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        vlan = db.get(Vlan, int(s["vlan"]))
        pct = round(100 * vlan.dhcp_in_use / vlan.dhcp_pool_size, 1) if vlan and vlan.dhcp_pool_size else 100.0
        return _r("dhcp pool", pct < float(s["threshold"]), f"VLAN {s['vlan']} pool at {pct}%")

    # ---------------------------------------------------------- preconditions
    def precondition(self, db: Session, target: str, spec: dict[str, Any]) -> dict[str, Any]:
        name = spec["check"]
        dev = db.get(Device, target)
        if name == "service_not_running":
            svc = db.get(Service, f"{spec['service']}@{target}")
            ok = bool(svc and svc.status != "running")
            return {"check": name, "passed": ok, "detail": f"{spec['service']} is {svc.status if svc else 'absent'}" + ("" if ok else " - nothing to restart")}
        if name == "config_valid":
            r = self.p_config_valid(db, target, spec, None)
            return {"check": name, "passed": r["passed"], "detail": r["detail"]}
        if name == "device_reachable":
            return {"check": name, "passed": bool(dev and dev.reachable), "detail": f"{target} {'reachable' if dev and dev.reachable else 'unreachable'}"}
        if name == "firewall_available":
            ok = self.ctx.firewall.available()
            return {"check": name, "passed": ok, "detail": "firewall API reachable" if ok else "firewall API unavailable"}
        if name == "disk_above":
            disks = (dev.metrics or {}).get("disk", {}) if dev else {}
            worst = max(disks.values()) if disks else 0
            return {"check": name, "passed": worst >= float(spec["threshold"]), "detail": f"peak filesystem usage {worst:.0f}%"}
        if name == "device_known":
            return {"check": name, "passed": dev is not None, "detail": "device in inventory" if dev else "unknown device"}
        if name == "device_not_quarantined":
            return {"check": name, "passed": bool(dev and not dev.quarantined), "detail": "not yet quarantined" if dev and not dev.quarantined else "already quarantined"}
        if name == "device_quarantined":
            return {"check": name, "passed": bool(dev and dev.quarantined), "detail": "quarantined" if dev and dev.quarantined else "not quarantined"}
        if name == "switchport_known":
            iface = self.ctx.world.interface_for(db, target)
            return {"check": name, "passed": iface is not None, "detail": f"connected to {iface.id}" if iface else "switch port unknown"}
        return {"check": name, "passed": False, "detail": "unknown precondition"}


class NetworkProbes(Probes):
    """Real-lab variant: TCP and HTTP probes actually connect. Other probes reuse NEXUS state."""

    mode = "REAL LAB"

    def p_tcp(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        ip = self._ip(db, t) or t
        try:
            with socket.create_connection((ip, int(s["port"])), timeout=3):
                return _r(f"tcp/{s['port']}", True, f"{ip}:{s['port']} open")
        except OSError as exc:
            return _r(f"tcp/{s['port']}", False, f"{ip}:{s['port']} {exc}")

    def p_http(self, db: Session, t: str, s: dict[str, Any], tx: Any) -> dict[str, Any]:
        import httpx

        ip = self._ip(db, t) or t
        scheme = "https" if int(s["port"]) in (443, 8443) else "http"
        try:
            resp = httpx.get(f"{scheme}://{ip}:{s['port']}/", timeout=4, verify=False)  # noqa: S501 - lab endpoints use internal CA
            return _r(f"http/{s['port']}", resp.status_code == int(s.get("expect", 200)), f"HTTP {resp.status_code}")
        except httpx.HTTPError as exc:
            return _r(f"http/{s['port']}", False, str(exc))

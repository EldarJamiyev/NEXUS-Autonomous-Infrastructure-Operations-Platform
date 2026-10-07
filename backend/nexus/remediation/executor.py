"""Command execution through a strict allowlist.

Alert content is never executed. Every step names a template; every parameter is validated
against an enum, range or pattern; commands are argv lists (no shell). The SimulatedExecutor applies
the effect to the simulated World; the optional AnsibleExecutor runs the repository playbooks.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.store import get_setting, set_setting
from nexus.firewall.base import RuleSpec
from nexus.models import Device, Lease, RemediationTransaction, Service, Vlan

if TYPE_CHECKING:
    from nexus.core.context import Context

UNITS = {"linux": {"nginx": "nginx", "ssh": "ssh", "docker": "docker", "monitoring-agent": "prometheus-node-exporter"},
         "windows": {"dns": "DNS", "ntp": "W32Time", "monitoring-agent": "windows_exporter", "ad-ds": "NTDS"}}
LOGSETS = {"nginx", "portal", "rsyslog"}
TMP_PATHS = {"/var/tmp/nexus-approved", "/var/cache/portal/tmp"}  # noqa: S108 - allowlist of approved paths, not a temp file
CONTAINERS = {"portal", "portal-db"}
WIN_SETTINGS = {"all", "smb1", "firewall", "nla", "audit", "password"}
CONFIG_PATHS = {"ssh": "/etc/ssh/sshd_config", "nginx": "/etc/nginx/conf.d/portal.conf", "docker": "/etc/docker/daemon.json",
                "monitoring": "/etc/default/prometheus-node-exporter", "services": "systemd unit state", "files": "file modes",
                "windows": "Windows security baseline"}
VALID_VLANS = {10, 20, 30, 40, 50, 99}
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/@+=-]{1,128}$")
OPS = {"service_restart", "service_reload", "service_enable", "config_test", "logrotate", "clean_tmp", "restore_config",
       "restore_backup", "w32tm_resync", "docker_restart", "win_baseline", "switchport_vlan", "firewall_reconcile",
       "firewall_restore", "firewall_block", "revoke_device_leases", "revoke_lease", "dhcp_reclaim", "network_restore"}


class CommandRejected(ValueError):
    """Raised when a step is not in the allowlist or a parameter fails validation."""


@dataclass
class ExecResult:
    op: str
    display: str
    exit_code: int
    output: str
    duration_ms: int

    def as_dict(self) -> dict[str, Any]:
        return {"op": self.op, "command": self.display, "exit_code": self.exit_code, "output": self.output, "duration_ms": self.duration_ms}


def os_family(dev: Device) -> str:
    if "windows" in (dev.os or "").lower():
        return "windows"
    if dev.kind in ("firewall", "switch"):
        return "appliance"
    return "linux"


def _token(name: str, value: Any) -> str:
    text = str(value)
    if not SAFE_TOKEN.match(text):
        raise CommandRejected(f"parameter {name}={text!r} contains characters outside the allowlist")
    return text


def render(op: str, dev: Device, params: dict[str, Any]) -> list[str]:
    """Validate and render one step to an argv list. Raises CommandRejected."""
    if op not in OPS:
        raise CommandRejected(f"operation {op!r} is not in the remediation allowlist")
    fam = os_family(dev)
    if op in ("service_restart", "service_reload", "service_enable"):
        svc = _token("service", params.get("service"))
        unit = UNITS.get(fam, {}).get(svc)
        if unit is None:
            raise CommandRejected(f"service {svc!r} is not restartable on {fam} hosts")
        if fam == "windows":
            if op != "service_restart":
                raise CommandRejected(f"{op} is not supported on Windows")
            return ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Restart-Service", "-Name", unit]
        verb = {"service_restart": ["restart"], "service_reload": ["reload"], "service_enable": ["enable", "--now"]}[op]
        return ["systemctl", *verb, unit]
    if op == "config_test":
        comp = params.get("component")
        if comp == "nginx":
            return ["nginx", "-t"]
        if comp == "ssh":
            return ["sshd", "-t"]
        raise CommandRejected(f"no syntax test for component {comp!r}")
    if op == "logrotate":
        name = params.get("name")
        if name not in LOGSETS:
            raise CommandRejected(f"log set {name!r} is not approved for rotation")
        return ["logrotate", "-f", f"/etc/logrotate.d/{name}"]
    if op == "clean_tmp":
        path, days = params.get("path"), params.get("days")
        if path not in TMP_PATHS:
            raise CommandRejected(f"path {path!r} is not an approved temporary path")
        if not isinstance(days, int) or not 1 <= days <= 90:
            raise CommandRejected("days must be an integer between 1 and 90")
        return ["find", path, "-xdev", "-type", "f", "-mtime", f"+{days}", "-delete"]
    if op in ("restore_config", "restore_backup"):
        comp = params.get("component")
        if comp not in CONFIG_PATHS:
            raise CommandRejected(f"component {comp!r} has no managed configuration")
        source = "/var/lib/nexus/baseline" if op == "restore_config" else "/var/lib/nexus/backup"
        return ["install", "-m", "0600", f"{source}/{dev.id}/{comp}", CONFIG_PATHS[comp]]
    if op == "w32tm_resync":
        if fam != "windows":
            raise CommandRejected("w32tm only runs on Windows hosts")
        return ["w32tm", "/resync", "/force"]
    if op == "docker_restart":
        container = params.get("container")
        if container not in CONTAINERS:
            raise CommandRejected(f"container {container!r} is not approved for restart")
        return ["docker", "restart", container]
    if op == "win_baseline":
        setting = params.get("setting")
        if setting not in WIN_SETTINGS:
            raise CommandRejected(f"Windows setting {setting!r} is not approved")
        return ["powershell", "-NoProfile", "-File", "C:\\nexus\\Invoke-NexusWindowsRemediation.ps1", "-Setting", setting]
    if op == "switchport_vlan":
        vlan = params.get("vlan")
        if vlan != "previous" and (not isinstance(vlan, int) or vlan not in VALID_VLANS):
            raise CommandRejected(f"VLAN {vlan!r} is not a managed VLAN")
        return ["SW-CORE01", "interface", f"<port of {dev.id}>", "switchport", "access", "vlan", str(vlan)]
    if op == "firewall_block":
        port = params.get("port")
        if not isinstance(port, int) or not 0 < port < 65536:
            raise CommandRejected("port must be an integer 1-65535")
        return ["firewall", "create-rule", "DENY", "NET_USERS", dev.id, f"TCP/{port}"]
    if op == "dhcp_reclaim":
        vlan = params.get("vlan")
        if vlan not in VALID_VLANS:
            raise CommandRejected("unknown DHCP scope")
        return ["dhcpd", "reclaim-expired", f"--scope=VLAN{vlan}"]
    if op == "revoke_lease":
        return ["lease-engine", "revoke", _token("lease", params.get("lease"))]
    return [op.replace("_", "-"), dev.id]


class CommandExecutor:
    name = "abstract"
    mode = "SIMULATION"

    def run(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> ExecResult:
        raise NotImplementedError


class SimulatedExecutor(CommandExecutor):
    """Applies allowlisted operations to the simulated World. Never touches a real host."""

    name = "simulated-executor"
    mode = "SIMULATION"

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    def run(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> ExecResult:
        op = step["op"]
        argv = render(op, dev, step)
        started = time.perf_counter()
        code, out = getattr(self, f"_{op}")(db, dev, step, tx)
        return ExecResult(op=op, display=" ".join(argv), exit_code=code, output=out, duration_ms=int((time.perf_counter() - started) * 1000) + 40)

    # -- services -------------------------------------------------------
    def _service_id(self, dev: Device, step: dict[str, Any]) -> str:
        return f"{step['service']}@{dev.id}"

    def _service_restart(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        return self.ctx.world.start_service(db, self._service_id(dev, step))

    def _service_reload(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        return self.ctx.world.start_service(db, self._service_id(dev, step))

    def _service_enable(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        code, out = self.ctx.world.enable_service(db, self._service_id(dev, step), actor="nexus-autoheal")
        return code, out or f"Created symlink /etc/systemd/system/multi-user.target.wants/{step['service']}.service"

    def _config_test(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        ok, msg = (self.ctx.world.validate_nginx if step["component"] == "nginx" else self.ctx.world.validate_sshd)(db, dev.id)
        return (0 if ok else 1), msg

    # -- capacity -------------------------------------------------------
    def _largest_mount(self, dev: Device) -> tuple[str | None, float]:
        disks = (dev.metrics or {}).get("disk", {})
        if not disks:
            return None, 0.0
        mount = max(disks, key=lambda m: disks[m])
        return mount, float(disks[mount])

    def _logrotate(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        mount, pct = self._largest_mount(dev)
        if mount is None:
            return 1, "no filesystem data"
        self.ctx.world.set_disk(db, dev.id, mount, max(31.0, pct - 39.0))
        self.ctx.world.clear_fault(db, dev.id, "log_growth")
        return 0, f"rotating pattern /var/log/{step['name']}/*.log forced from command line\ncompressed 14 files; {mount} {pct:.0f}% -> {max(31.0, pct - 39.0):.0f}%"

    def _clean_tmp(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        mount, pct = self._largest_mount(dev)
        if mount:
            self.ctx.world.set_disk(db, dev.id, mount, max(20.0, pct - 6.0))
        return 0, f"removed 312 files older than {step['days']} days under {step['path']}"

    # -- configuration --------------------------------------------------
    def _restore_config(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        from nexus.drift.engine import restored_config

        comp = step["component"]
        self.ctx.world.write_config(db, dev.id, comp, restored_config(self.ctx, db, dev.id, comp), actor="nexus-autoheal",
                                    reason=f"restore {comp} baseline ({tx.id})")
        return 0, f"{CONFIG_PATHS[comp]} written from Git intent ({tx.id})"

    def _restore_backup(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        comp = step["component"]
        backup = (tx.backup or {}).get("config", {})
        if backup.get("component") != comp:
            return 1, "no backup available for this component"
        self.ctx.world.write_config(db, dev.id, comp, backup["actual"], actor="nexus-autoheal (rollback)", reason=f"rollback {tx.id}")
        return 0, f"{CONFIG_PATHS[comp]} restored from backup sha256 {backup['checksum'][:12]}"

    def _w32tm_resync(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        svc = db.get(Service, f"ntp@{dev.id}")
        if not svc or svc.status != "running":
            return 1, "The following error occurred: The service has not been started. (0x80070426)"
        self.ctx.world.clear_fault(db, dev.id, "clock_skew_s")
        return 0, "Sending resync command to local computer\nThe command completed successfully."

    def _docker_restart(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        self.ctx.world.clear_fault(db, dev.id, "cpu_hog")
        svc = db.get(Service, f"{step['container']}@{dev.id}")
        if svc:
            svc.status = "running"
        return 0, step["container"]

    def _win_baseline(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        return self._restore_config(db, dev, {"component": "windows"}, tx)

    # -- network --------------------------------------------------------
    def _switchport_vlan(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        from nexus.identity.confidence import update_identity
        from nexus.risk.engine import recompute_device

        vlan = step["vlan"]
        if vlan == "previous":
            vlan = dev.pre_quarantine_vlan_id or (tx.backup or {}).get("network", {}).get("vlan") or 30
        before = dev.vlan_id
        if vlan == 99 and not dev.quarantined:
            dev.pre_quarantine_vlan_id = before
        address = self.ctx.world.move_to_vlan(db, dev.id, int(vlan), actor="nexus-autoheal")
        if vlan == 99:
            dev.quarantined = True
            dev.quarantine_reason = tx.trigger
            dev.status = "quarantined"
            self.ctx.bus.emit(db, "QUARANTINE_STARTED", f"{dev.id} moved to VLAN 99 quarantine ({address}); isolated by FW-020", severity="high",
                              source="autoheal", target=dev.id, data={"from_vlan": before, "address": address, "transaction": tx.id},
                              correlation_id=tx.correlation_id)
        elif dev.quarantined:
            dev.quarantined = False
            dev.quarantine_reason = None
            self.ctx.bus.emit(db, "QUARANTINE_RELEASED", f"{dev.id} released to VLAN {vlan} ({address})", severity="notice", source="autoheal",
                              target=dev.id, data={"to_vlan": vlan, "address": address}, correlation_id=tx.correlation_id)
        db.flush()
        update_identity(self.ctx, db, dev, f"switchport moved to VLAN {vlan}", tx.correlation_id)
        recompute_device(self.ctx, db, dev, f"moved to VLAN {vlan}", tx.correlation_id, evaluate_policy=False)
        return 0, f"SW-CORE01(config-if)# switchport access vlan {vlan}\n{dev.id} renewed address {address}"

    def _network_restore(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        vlan = (tx.backup or {}).get("network", {}).get("vlan")
        if vlan is None:
            return 1, "no network backup"
        if dev.quarantined and vlan != 99:
            dev.quarantined = False
            dev.quarantine_reason = None
        self.ctx.world.move_to_vlan(db, dev.id, int(vlan), actor="nexus-autoheal (rollback)")
        return 0, f"switchport access vlan {vlan} restored"

    def _revoke_device_leases(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        from nexus.leases.engine import revoke_lease

        ids = [x.id for x in db.scalars(select(Lease).where(Lease.device_id == dev.id, Lease.status.in_(("ACTIVE", "PENDING"))))]
        for lease_id in ids:
            revoke_lease(self.ctx, db, lease_id, f"source device contained ({tx.id})", actor="NEXUS", actor_type="AUTOHEAL")
        return 0, f"revoked {len(ids)} lease(s)" if ids else "no active leases"

    def _revoke_lease(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        from nexus.leases.engine import revoke_lease

        revoke_lease(self.ctx, db, step["lease"], f"revoked by {tx.id}", actor=tx.requested_by, actor_type="OPERATOR")
        return 0, f"{step['lease']} revoked"

    def _firewall_reconcile(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        from nexus.policy.compiler import desired_firewall

        result = self.ctx.firewall.apply_policy(db, desired_firewall(self.ctx, db))
        post = dict(tx.post_state or {})
        post["removed_rules"] = [r for r in (tx.backup or {}).get("firewall", []) if r["id"] in result["removed"]]
        tx.post_state = post
        return 0, f"removed {result['removed'] or 'none'}; added {result['added'] or 'none'}"

    def _firewall_restore(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        backup = (tx.backup or {}).get("firewall")
        if backup is None:
            return 1, "no firewall backup"
        self.ctx.firewall.rollback(db, backup)
        set_setting(db, "firewall_nexus_blocks", (tx.backup or {}).get("nexus_blocks", []), self.ctx.clock.now())
        return 0, f"ruleset restored from backup ({len(backup)} rules)"

    def _firewall_block(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        port = int(step["port"])
        spec = RuleSpec(action="DENY", source="NET_USERS", destination=dev.id, protocol="TCP", port=str(port),
                        description=f"Containment of unexpected service ({tx.id})", origin="nexus-block", position=90,
                        rule_id=f"FW-BLOCK-{dev.id}-{port}", created_by="nexus-autoheal")
        rule_id = self.ctx.firewall.create_rule(db, spec)
        blocks = [b for b in (get_setting(db, "firewall_nexus_blocks") or []) if b.get("rule_id") != rule_id] + [spec.as_dict()]
        set_setting(db, "firewall_nexus_blocks", blocks, self.ctx.clock.now())
        return 0, f"rule {rule_id}: DENY NET_USERS -> {dev.id}:{port}/TCP"

    def _dhcp_reclaim(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> tuple[int, str]:
        vlan = db.get(Vlan, int(step["vlan"]))
        if vlan is None:
            return 1, "unknown scope"
        reclaimed = vlan.dhcp_stale
        vlan.dhcp_in_use = max(0, vlan.dhcp_in_use - reclaimed)
        vlan.dhcp_stale = 0
        return 0, f"reclaimed {reclaimed} expired leases on VLAN {vlan.id}; pool {vlan.dhcp_in_use}/{vlan.dhcp_pool_size}"


class AnsibleExecutor(CommandExecutor):
    """OPTIONAL real-lab executor: runs ansible/playbooks/remediate.yml limited to one host.

    Only validated parameters are passed as extra vars; argv list, no shell, hard timeout.
    Requires ansible-core in the NEXUS image and an inventory (NEXUS_ANSIBLE_INVENTORY). Not used by
    the demo and not exercised in CI.
    """

    name = "ansible"
    mode = "REAL LAB"

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.root = ctx.settings.config_root / "ansible"

    def run(self, db: Session, dev: Device, step: dict[str, Any], tx: RemediationTransaction) -> ExecResult:
        argv = render(step["op"], dev, step)
        extra = [f"nexus_op={step['op']}", f"nexus_tx={tx.id}"] + [f"nexus_{k}={_token(k, v)}" for k, v in step.items() if k != "op" and v is not None]
        cmd = ["ansible-playbook", "-i", str(self.root / self.ctx.settings.ansible_inventory.split("ansible/")[-1]),
               str(self.root / "playbooks" / "remediate.yml"), "--limit", _token("host", dev.id)]
        for e in extra:
            cmd += ["-e", e]
        started = time.perf_counter()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(30, 300), check=False)  # noqa: S603
            code, out = proc.returncode, (proc.stdout + proc.stderr)[-2000:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            code, out = 124, f"ansible execution failed: {exc}"
        return ExecResult(op=step["op"], display=" ".join(argv), exit_code=code, output=out, duration_ms=int((time.perf_counter() - started) * 1000))


def _diagnose(self: SimulatedExecutor, db: Session, dev: Device, kind: str) -> str:
    """Read-only diagnostics (du / top / ss / journalctl equivalents) observed on the simulated host."""
    faults = dev.sim_faults or {}
    if kind == "disk":
        growth = faults.get("log_growth")
        return f"18G {growth}/log/portal (portal.log grew 2.1G/h)" if growth else "no single directory dominates usage"
    if kind == "cpu":
        return "PID 4121 gunicorn: portal worker 96.4% CPU, 1.9G RSS (runaway request loop)" if faults.get("cpu_hog") else "load nominal"
    if kind == "ports":
        extra = faults.get("extra_ports", {})
        return ", ".join(f"LISTEN 0.0.0.0:{p} users:(({proc}))" for p, proc in extra.items()) or "only baseline listeners"
    return "no diagnostics for this condition"


SimulatedExecutor.diagnose = _diagnose  # type: ignore[attr-defined]
AnsibleExecutor.diagnose = lambda self, db, dev, kind: "diagnostics not collected in real-lab mode (run the runbook diagnostics manually)"  # type: ignore[attr-defined]

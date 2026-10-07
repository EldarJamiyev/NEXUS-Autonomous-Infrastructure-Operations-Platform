"""Chaos Lab. Scenarios only change the simulated World and record FAILURE_INJECTED; detection,
correlation, decisions, remediation and verification are left entirely to NEXUS. Every scenario
documents: trigger, events, detection, risk, decision, action, verification, final state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.ids import new_id
from nexus.models import (
    Alert,
    Certificate,
    ChaosRun,
    Decision,
    Device,
    Event,
    Incident,
    RemediationTransaction,
    RiskEvent,
)

if TYPE_CHECKING:
    from nexus.core.context import Context

Inject = Callable[["Context", Session, ChaosRun], list[str]]


@dataclass
class Scenario:
    id: str
    title: str
    category: str
    description: str
    targets: list[str]
    expect: dict[str, str]
    inject: Inject
    followups: list[tuple[float, Inject]] = field(default_factory=list)
    operator_fix: Inject | None = None
    fix_label: str = ""
    automatic: bool = True


def _mark(ctx: Context, db: Session, run: ChaosRun, target: str, message: str) -> str:
    ctx.bus.emit(db, "FAILURE_INJECTED", f"Chaos {run.id}: {message}", severity="warning", source="chaos-lab", target=target,
                 data={"run": run.id, "scenario": run.scenario})
    return message


def _x(expect: str) -> dict[str, str]:
    keys = ["trigger", "events", "detection", "risk", "decision", "action", "verification", "final_state"]
    return dict(zip(keys, [p.strip() for p in expect.split("|")], strict=True))


# ----------------------------------------------------------------------------- injections
def kill_nginx(ctx, db, run):
    ctx.world.stop_service(db, "nginx@LINUX01", "main process killed (SIGKILL, simulated)")
    return [_mark(ctx, db, run, "LINUX01", "killed nginx master process on LINUX01")]


def fill_disk(ctx, db, run):
    ctx.world.set_disk(db, "APP01", "/var", 96.0)
    ctx.world.add_fault(db, "APP01", "log_growth", "/var")
    return [_mark(ctx, db, run, "APP01", "runaway portal log filled /var on APP01 to 96%")]


def break_ssh(ctx, db, run):
    ctx.world.set_config(db, "LINUX01", "ssh", {"PermitRootLogin": "yes"}, actor="root@LINUX01 (manual edit)", reason="vi /etc/ssh/sshd_config")
    return [_mark(ctx, db, run, "LINUX01", "PermitRootLogin yes written to sshd_config on LINUX01")]


def add_fw_rule(ctx, db, run):
    rule_id = f"FW-MAN-{run.id.split('-')[-1]}"
    ctx.world.inject_firewall_rule(db, rule_id, "ALLOW", "ANY", "LINUX01", "TCP", "22", actor="admin@PFSENSE (webConfigurator)", position=105)
    return [_mark(ctx, db, run, "PFSENSE", f"unauthorized rule {rule_id}: ALLOW ANY -> LINUX01:22")]


def unknown_device(ctx, db, run):
    mac = "02:4B:7A:31:9C:" + run.id.split("-")[-1][-2:].rjust(2, "0")
    ctx.world.attach_endpoint(db, mac, "Gi1/0/14", None, "DESKTOP-Q7M2X", vendor="locally administered (randomised MAC)")
    return [_mark(ctx, db, run, "SW-CORE01", f"unknown endpoint {mac} plugged into Gi1/0/14 (VLAN 30)")]


def _probe(dst: str, port: int) -> Inject:
    def fn(ctx, db, run):
        from nexus.models import IpAddress, MacAddress
        from nexus.network.discovery import observe_port_activity

        mac = db.scalar(select(MacAddress).where(MacAddress.interface_id == "SW-CORE01:Gi1/0/14", MacAddress.known.is_(False)).order_by(MacAddress.first_seen.desc()))
        ip = db.scalar(select(IpAddress.address).where(IpAddress.mac == mac.address)) if mac else None
        if ip:
            observe_port_activity(ctx, db, src_ip=ip, dst_device=dst, port=port, action="BLOCK")
        return [f"connection attempt TCP/{port} -> {dst}"]
    return fn


def change_vlan(ctx, db, run):
    ctx.world.move_to_vlan(db, "PC-024", 20, actor="unknown (switch CLI session)")
    return [_mark(ctx, db, run, "PC-024", "Gi1/0/12 (PC-024) moved to VLAN 20 on SW-CORE01")]


def break_dns(ctx, db, run):
    ctx.world.stop_service(db, "dns@DC01", "DNS Server service terminated unexpectedly (Event 7031)")
    return [_mark(ctx, db, run, "DC01", "DNS Server service stopped on DC01")]


def break_monitoring(ctx, db, run):
    ctx.world.stop_service(db, "monitoring-agent@APP01", "node_exporter exited (OOM killed)")
    return [_mark(ctx, db, run, "APP01", "node_exporter stopped on APP01")]


def dhcp_conflict(ctx, db, run):
    mac = "02:91:5D:0C:44:" + run.id.split("-")[-1][-2:].rjust(2, "0")
    ctx.world.attach_endpoint(db, mac, "Gi1/0/15", "10.30.30.43", None, vendor="locally administered", claim_static_ip=True)
    return [_mark(ctx, db, run, "SW-CORE01", f"device {mac} on Gi1/0/15 statically claims 10.30.30.43 (PC-024's address)")]


def fail_ad_login(ctx, db, run):
    ctx.world.auth_failures(db, "aysel", "PC-025", 12)
    return [_mark(ctx, db, run, "PC-025", "12 failed logons for aysel from PC-025 (bad password)")]


POLICY_CONFLICT_YAML = """apiVersion: nexus.omnis/v1
kind: AccessPolicy
metadata:
  id: POL-HR-EMERGENCY
  name: HR emergency server access
  owner: GG-HR
  description: Draft submitted without review - grants HR SSH to LINUX01.
spec:
  subjects:
    groups: [GG-HR]
  grants:
    - destinations: [LINUX01]
      protocol: TCP
      ports: [22]
      lease_minutes: 60
"""


def policy_conflict(ctx, db, run):
    from nexus.core.util import sha256_of
    from nexus.incidents.engine import open_finding
    from nexus.models import Policy, PolicyVersion
    from nexus.policy.compiler import compile_policy_set

    report = compile_policy_set(ctx, db, overrides={"POL-HR-EMERGENCY": POLICY_CONFLICT_YAML})
    blocking = [c for c in report["conflicts"] if c["blocking"]]
    if db.get(Policy, "POL-HR-EMERGENCY") is None:
        db.add(Policy(id="POL-HR-EMERGENCY", name="HR emergency server access", kind="AccessPolicy", description="draft", status="INACTIVE"))
        db.flush()
    version = (db.scalar(select(PolicyVersion.version).where(PolicyVersion.policy_id == "POL-HR-EMERGENCY").order_by(PolicyVersion.version.desc())) or 0) + 1
    db.add(PolicyVersion(policy_id="POL-HR-EMERGENCY", version=version, author="nigar", created_at=ctx.clock.now(), checksum=sha256_of(POLICY_CONFLICT_YAML),
                         content=POLICY_CONFLICT_YAML, status="REJECTED" if blocking else "DRAFT", note="; ".join(c["detail"] for c in blocking)[:256], source="console"))
    ctx.bus.emit(db, "POLICY_CONFLICT", f"POL-HR-EMERGENCY v{version} rejected: {blocking[0]['detail'] if blocking else 'no conflict'}", severity="warning",
                 source="policy-compiler", target="POL-HR-EMERGENCY", data={"conflicts": report["conflicts"]})
    if blocking:
        open_finding(ctx, db, name="PolicyConflict", target="POL-HR-EMERGENCY", summary=blocking[0]["detail"], labels={"policy": "POL-HR-EMERGENCY"})
    return [_mark(ctx, db, run, "POL-HR-EMERGENCY", "draft POL-HR-EMERGENCY submitted (grants GG-HR SSH to LINUX01)")]


def expire_certificate(ctx, db, run):
    ctx.world.set_certificate_expiry(db, "portal.corp.nexus.lab", ctx.clock.now() - timedelta(minutes=1))
    return [_mark(ctx, db, run, "LINUX01", "portal.corp.nexus.lab certificate notAfter moved into the past")]


def fail_remediation(ctx, db, run):
    ctx.world.set_config(db, "LINUX01", "nginx", {"listen": [80, 8443]}, actor="deploy-bot (CI pipeline)", reason="release 2026.10.2")
    ctx.world.add_fault(db, "LINUX01", "host_firewall_drop", [443])
    ctx.world.stop_service(db, "nginx@LINUX01", "stopped by deploy hook")
    return [_mark(ctx, db, run, "LINUX01", "bad deploy: nginx listen 443 -> 8443, stray nftables rule drops TCP/443, nginx stopped")]


def disconnect_firewall(ctx, db, run):
    import time

    ctx.runtime.firewall_available = False
    ctx.runtime.firewall_reconnect_at = time.time() + 60
    return [_mark(ctx, db, run, "PFSENSE", "pfSense management API unreachable (simulated); auto-reconnect in 60 s")]


def database_degraded(ctx, db, run):
    import time

    ctx.runtime.db_degraded_until = time.time() + 45
    return [_mark(ctx, db, run, "NEXUS", "state store latency degraded for 45 s (simulated)")]


def dhcp_exhaustion(ctx, db, run):
    ctx.world.set_dhcp_usage(db, 30, 62, 41)
    return [_mark(ctx, db, run, "PFSENSE", "VLAN 30 DHCP pool at 62/64 (41 expired leases never reclaimed)")]


def increase_cpu(ctx, db, run):
    ctx.world.add_fault(db, "APP01", "cpu_hog", True)
    return [_mark(ctx, db, run, "APP01", "portal worker enters a request loop (CPU ~97%)")]


def break_ntp(ctx, db, run):
    ctx.world.stop_service(db, "ntp@DC01", "W32Time stopped")
    ctx.world.add_fault(db, "DC01", "clock_skew_s", 360.0)
    return [_mark(ctx, db, run, "DC01", "W32Time stopped on DC01; clock drifting (+360 s)")]


def disable_service(ctx, db, run):
    ctx.world.disable_service(db, "docker@LINUX01", actor="admin@LINUX01 (systemctl disable --now docker)")
    return [_mark(ctx, db, run, "LINUX01", "docker disabled and stopped on LINUX01")]


def unreachable(ctx, db, run):
    ctx.world.set_reachable(db, "MON01", False)
    return [_mark(ctx, db, run, "MON01", "MON01 stops answering (hypervisor host fault, simulated)")]


def unexpected_port(ctx, db, run):
    ctx.world.open_port(db, "APP01", 3389, "xrdp")
    return [_mark(ctx, db, run, "APP01", "xrdp installed and listening on APP01 TCP/3389")]


# ----------------------------------------------------------------------- operator fixes
def fix_fail_remediation(ctx, db, run):
    ctx.world.clear_fault(db, "LINUX01", "host_firewall_drop")
    return ["operator removed the stray nftables rule dropping TCP/443 (manual, simulated); NEXUS retries remediation"]


def fix_cert(ctx, db, run):
    ctx.world.set_certificate_expiry(db, "portal.corp.nexus.lab", ctx.clock.now() + timedelta(days=365))
    return ["operator renewed portal.corp.nexus.lab via the internal CA (manual, simulated)"]


def fix_unreachable(ctx, db, run):
    ctx.world.set_reachable(db, "MON01", True)
    return ["operator power-cycled MON01 from the hypervisor console (manual, simulated)"]


def fix_firewall(ctx, db, run):
    ctx.runtime.firewall_available = True
    ctx.runtime.firewall_reconnect_at = None
    return ["pfSense management API reachable again"]


def fix_auth(ctx, db, run):
    from nexus.incidents.engine import resolve_incident

    for inc in db.scalars(select(Incident).where(Incident.target == "PC-025", Incident.status.in_(("OPEN", "INVESTIGATING")))):
        resolve_incident(ctx, db, inc.id, "user confirmed: stale credentials in a mapped drive; password reset", actor="eldar")
    return ["operator confirmed stale saved credentials on PC-025 and reset the password (manual, simulated)"]


def fix_policy(ctx, db, run):
    from nexus.incidents.engine import resolve_incident

    for inc in db.scalars(select(Incident).where(Incident.target == "POL-HR-EMERGENCY", Incident.status.in_(("OPEN", "INVESTIGATING")))):
        resolve_incident(ctx, db, inc.id, "draft withdrawn by the HR policy owner", actor="eldar")
    return ["draft POL-HR-EMERGENCY withdrawn"]


SCENARIOS: dict[str, Scenario] = {s.id: s for s in [
    Scenario("kill-nginx", "Kill Nginx", "service", "Kill the nginx master process on LINUX01.", ["LINUX01"],
             _x("SIGKILL to nginx | process exits, HTTPS stops | NginxDown via process + TCP/443 probe | portal users affected | SAFE restart, automatic | systemctl restart nginx | systemd active + TCP/443 + HTTP 200 | incident resolved, ChatOps AUTOHEAL EVENT"),
             kill_nginx),
    Scenario("fill-disk", "Fill disk", "capacity", "A runaway log fills /var on APP01.", ["APP01"],
             _x("log growth | /var reaches 96% | DiskSpaceCritical | capacity incident | SAFE log rotation | logrotate -f /etc/logrotate.d/portal | usage below 85% | resolved; no arbitrary deletion"), fill_disk),
    Scenario("break-ssh-config", "Break SSH config", "configuration", "Enable PermitRootLogin on LINUX01 by hand.", ["LINUX01"],
             _x("manual edit | FIM reports sshd_config change | drift vs Git intent (SECURITY) | LINUX01 risk rises | REVERSIBLE restore, confidence 91% | backup, write baseline, sshd -t, reload | config checksum = intent, TCP/22 open | COMPLIANT, rollback available"), break_ssh),
    Scenario("add-firewall-rule", "Add firewall rule", "security", "Someone adds ALLOW ANY -> LINUX01:22 directly on pfSense.", ["PFSENSE", "LINUX01"],
             _x("webConfigurator change | pfSense syslog | unauthorized rule vs intent (CRITICAL) | risk HIGH | REVERSIBLE rollback, confidence 94% | backup ruleset, remove rule | ruleset = intent, ANY->LINUX01:22 now DENY, management path intact | rollback verified"), add_fw_rule),
    Scenario("unknown-device", "Create unknown device", "identity", "Plug an unidentified endpoint into a user port; it probes SSH.", ["SW-CORE01"],
             _x("new MAC on Gi1/0/14 | DHCP, ARP, failed DNS/AD correlation, TCP/22 attempts | identity confidence collapses | risk becomes CRITICAL | SECURITY-004 permits automatic quarantine (unmanaged endpoint) | move port to VLAN 99, revoke leases | VLAN 99 + policy test DENY | incident mitigated"),
             unknown_device, followups=[(2.5, _probe("LINUX01", 22)), (4.0, _probe("LINUX01", 22)), (5.5, _probe("DC01", 445))]),
    Scenario("change-vlan", "Change VLAN", "network", "PC-024's switchport is moved to the server VLAN.", ["PC-024"],
             _x("switch CLI change | PC-024 falls back to APIPA | VLAN drift vs network intent + identity drop | risk rises | REVERSIBLE switchport restore | switchport access vlan 30 | device back in VLAN 30 with its reserved address | compliant"), change_vlan),
    Scenario("break-dns", "Break DNS", "service", "Stop the DNS Server service on DC01.", ["DC01"],
             _x("DNS service stops | DNS down, AD logon failures, portal 503 (alert storm) | three symptoms correlated into ONE incident | P1 | SAFE restart of a verified-down service | Restart-Service DNS | service running, TCP/53, lookups succeed | all symptoms clear"), break_dns),
    Scenario("break-monitoring", "Break monitoring", "monitoring", "node_exporter on APP01 is OOM-killed.", ["APP01"],
             _x("agent exits | scrape target down | MonitoringAgentDown | low | SAFE restart | systemctl restart prometheus-node-exporter | scrape target up | resolved"), break_monitoring),
    Scenario("dhcp-conflict", "Create DHCP conflict", "network", "A rogue device statically claims PC-024's address.", ["SW-CORE01", "PC-024"],
             _x("static IP claim | ARP shows two MACs for 10.30.30.43 | DHCP conflict + unknown identity | claimant risk CRITICAL | SECURITY-004 quarantine of the claimant | move claimant to VLAN 99 | claimant isolated | PC-024 keeps its address"), dhcp_conflict),
    Scenario("fail-ad-login", "Fail AD login", "identity", "Repeated failed logons for aysel from PC-025.", ["PC-025"],
             _x("12x Event 4625 | authentication failure burst | RepeatedAuthFailures | PC-025 risk rises above lease thresholds | no automatic account action (human) | lease from PC-025 revoked by risk gate | access re-evaluated | human required"),
             fail_ad_login, operator_fix=fix_auth, fix_label="Confirm stale credentials and close", automatic=False),
    Scenario("policy-conflict", "Create policy conflict", "policy", "A draft policy grants GG-HR SSH, violating the server baseline.", ["POL-HR-EMERGENCY"],
             _x("draft submitted | compiler runs schema/conflict checks | BASELINE_CONSTRAINT conflict | policy risk | activation blocked | none - drafts never auto-apply | conflict reported | human required"),
             policy_conflict, operator_fix=fix_policy, fix_label="Withdraw draft", automatic=False),
    Scenario("expire-certificate", "Expire certificate", "security", "The portal TLS certificate expires.", ["LINUX01"],
             _x("notAfter passes | certificate monitor | CertificateExpired | user-facing TLS errors | NEVER auto-renewed in the demo | human renews via CA | certificate valid | human required"),
             expire_certificate, operator_fix=fix_cert, fix_label="Renew certificate (manual)", automatic=False),
    Scenario("fail-remediation", "Fail remediation", "verification", "A bad deploy plus a hidden host firewall rule makes the fix fail verification.", ["LINUX01"],
             _x("bad deploy + nftables drop | config change then nginx stops | RCA: config change 0-2 s before failure | HIGH | REVERSIBLE restore baseline | restore + nginx -t + restart (exit 0) | TCP/443 still unreachable -> VERIFICATION FAILED | ROLLBACK to backup, AUTOHEAL FAILED, human required"),
             fail_remediation, operator_fix=fix_fail_remediation, fix_label="Remove stray host firewall rule and retry", automatic=False),
    Scenario("disconnect-firewall", "Disconnect firewall", "control-plane", "pfSense API becomes unreachable for 60 s.", ["PFSENSE"],
             _x("API timeout | adapter raises FirewallUnavailable | FirewallUnreachable | mode DEGRADED | preserve state, block new privileged leases | lease requests -> BLOCKED/PENDING, never fake SUCCESS | reconnect, replay PENDING | RECOVERY -> NORMAL"),
             disconnect_firewall, operator_fix=fix_firewall, fix_label="Reconnect now"),
    Scenario("database-degraded", "Database degraded", "control-plane", "NEXUS state store latency spikes for 45 s.", ["NEXUS"],
             _x("latency | self-test and mode engine | DEGRADED | automation restricted | only SAFE actions automatic, snapshots deferred | - | degradation expires | RECOVERY -> NORMAL"), database_degraded),
    Scenario("dhcp-exhaustion", "DHCP exhaustion", "capacity", "VLAN 30 pool fills with expired leases.", ["PFSENSE"],
             _x("pool 62/64 | DHCP utilisation | DHCPPoolExhausted | new devices cannot join | SAFE reclaim | dhcpd reclaim-expired | pool below 85% | resolved"), dhcp_exhaustion),
    Scenario("increase-cpu", "Increase CPU", "capacity", "A portal worker loops at ~97% CPU.", ["APP01"],
             _x("request loop | sustained CPU | HighCPU (3 samples) | portal latency | HIGH_IMPACT container restart -> APPROVAL | docker restart portal (after approval) | CPU < 80% + HTTP 200 | resolved after human approval"),
             increase_cpu, automatic=False),
    Scenario("break-ntp", "Break NTP", "service", "W32Time stops on DC01 and the clock drifts.", ["DC01"],
             _x("service stop | clock offset grows | NTPClockSkew | Kerberos at risk | SAFE restart + resync | Restart-Service W32Time; w32tm /resync | offset < 1 s | resolved"), break_ntp),
    Scenario("disable-service", "Disable a service", "configuration", "docker is disabled on LINUX01.", ["LINUX01"],
             _x("systemctl disable --now | unit disabled + stopped | DockerDown + services drift | operational | REVERSIBLE re-enable | systemctl enable --now docker | enabled + running + config = intent | resolved"), disable_service),
    Scenario("unreachable-device", "Unreachable device", "availability", "MON01 stops answering.", ["MON01"],
             _x("host fault | no ARP/ICMP | NodeDown | monitoring blind spot -> DEGRADED | no remote path: human required | operator power-cycles host | host answers | resolved"),
             unreachable, operator_fix=fix_unreachable, fix_label="Power-cycle MON01 (manual)", automatic=False),
    Scenario("unexpected-port", "Unexpected port", "security", "xrdp starts listening on APP01:3389.", ["APP01"],
             _x("package install | agent reports new listener | UnexpectedService | APP01 risk rises | REVERSIBLE containment rule | DENY NET_USERS -> APP01:3389 | policy test DENY, management path intact | mitigated, investigate why xrdp appeared"), unexpected_port),
]}

BLACKOUT_SEQUENCE = ["unknown-device", "add-firewall-rule", "break-ssh-config", "break-dns", "break-monitoring", "unexpected-port", "dhcp-conflict",
                     "policy-conflict", "kill-nginx"]


def catalog() -> list[dict[str, Any]]:
    return [{"id": s.id, "title": s.title, "category": s.category, "description": s.description, "targets": s.targets, "expect": s.expect,
             "operator_fix": s.fix_label or None, "automatic": s.automatic} for s in SCENARIOS.values()] + [{
        "id": "blackout", "title": "Run blackout", "category": "showcase", "targets": ["*"], "operator_fix": None, "automatic": False,
        "description": "Inject nine faults at once and watch NEXUS detect, correlate, prioritise and remediate them.",
        "expect": _x("nine simultaneous faults | dozens of events | correlated incidents (DNS alert storm becomes one) | EMERGENCY mode | dependency-ordered decisions | restarts, rollbacks, quarantine, containment | per-action verification | final incident report")}]


def start(ctx: Context, db: Session, scenario_id: str, actor: str) -> tuple[ChaosRun, Scenario]:
    sc = SCENARIOS.get(scenario_id)
    if sc is None:
        raise KeyError(f"unknown scenario {scenario_id}")
    run = ChaosRun(id=new_id(db, "chaos"), scenario=sc.id, title=sc.title, status="INJECTING", targets=list(sc.targets), injections=[],
                   requested_by=actor, started_at=ctx.clock.now())
    db.add(run)
    db.flush()
    run.injections = sc.inject(ctx, db, run)
    run.status = "OBSERVING"
    return run, sc


def run_followup(ctx: Context, db: Session, run_id: str, fn: Inject) -> None:
    run = db.get(ChaosRun, run_id)
    if run:
        run.injections = list(run.injections or []) + fn(ctx, db, run)


def operator_fix(ctx: Context, db: Session, run_id: str, actor: str) -> list[str]:
    run = db.get(ChaosRun, run_id)
    if run is None:
        raise KeyError(run_id)
    sc = SCENARIOS.get(run.scenario)
    if sc is None or sc.operator_fix is None:
        raise ValueError("this scenario has no manual fix")
    notes = sc.operator_fix(ctx, db, run)
    from nexus.core.audit import record_audit

    record_audit(ctx, db, actor=actor, actor_type="OPERATOR", action=f"manual fix for {run.scenario}", reason="; ".join(notes), target=",".join(run.targets),
                 result="SUCCESS", details={"run": run.id, "simulated": True})
    run.injections = list(run.injections or []) + [f"[operator] {n}" for n in notes]
    if run.scenario == "fail-remediation":
        from nexus.core.decision import approve, plan_action
        from nexus.incidents.engine import plan_for

        pending = db.scalar(select(RemediationTransaction).where(RemediationTransaction.target == "LINUX01", RemediationTransaction.status == "AWAITING_APPROVAL",
                                                                 RemediationTransaction.action_id.in_(("REM-CFG-RESTORE-NGINX", "REM-SVC-RESTART-NGINX"))))
        if pending and pending.approval_id:
            approve(ctx, db, pending.approval_id, actor, note="host firewall fixed manually; retry approved")
            notes.append(f"approved pending {pending.id} after the manual fix")
        else:
            for inc in db.scalars(select(Incident).where(Incident.target == "LINUX01", Incident.status.in_(("OPEN", "INVESTIGATING"))).order_by(Incident.created_at.desc())):
                planned = plan_for(ctx, db, inc)
                if planned and planned[0] in ("REM-CFG-RESTORE-NGINX", "REM-SVC-RESTART-NGINX"):
                    action_id, target, params, override = planned
                    plan_action(ctx, db, action_id=action_id, target=target, params=params, trigger=f"operator retry after manual fix ({inc.id})",
                                evidence=inc.evidence, incident_id=inc.id, correlation_id=inc.correlation_id, requested_by=actor)
                    notes.append(f"retry planned on {inc.id}")
                    break
    return notes


def run_view(ctx: Context, db: Session, run: ChaosRun) -> dict[str, Any]:
    start_ts = run.started_at
    targets = set(run.targets)
    devices = set(db.scalars(select(Device.id).where(Device.first_seen >= start_ts, Device.kind == "unknown")))
    scope = targets | devices
    alerts = db.scalars(select(Alert).where(Alert.first_seen >= start_ts).order_by(Alert.first_seen)).all()
    incidents = db.scalars(select(Incident).where(Incident.created_at >= start_ts).order_by(Incident.created_at)).all()
    incidents = [i for i in incidents if i.target in scope or set(i.affected_devices or []) & scope] or incidents[:3]
    inc_ids = {i.id for i in incidents}
    alerts = [a for a in alerts if a.target in scope or a.incident_id in inc_ids]
    decisions = db.scalars(select(Decision).where(Decision.ts >= start_ts).order_by(Decision.ts)).all()
    decisions = [d for d in decisions if d.target in scope or d.incident_id in inc_ids]
    txs = db.scalars(select(RemediationTransaction).where(RemediationTransaction.created_at >= start_ts).order_by(RemediationTransaction.created_at)).all()
    txs = [t for t in txs if t.target in scope or t.incident_id in inc_ids]
    risks = db.scalars(select(RiskEvent).where(RiskEvent.ts >= start_ts).order_by(RiskEvent.ts)).all()
    risks = [r for r in risks if r.entity_id in scope][-6:]
    events = db.scalars(select(Event).where(Event.ts >= start_ts).order_by(Event.ts).limit(400)).all()
    events = [e for e in events if (e.target in scope) or (e.correlation_id and any(e.correlation_id == i.correlation_id for i in incidents)) or e.source == "chaos-lab"]
    first_alert = alerts[0].first_seen if alerts else None
    tx_done = [t for t in txs if t.status in ("COMMITTED", "ROLLED_BACK", "FAILED", "SKIPPED")]
    stage = lambda done, detail: {"done": bool(done), "detail": detail}  # noqa: E731
    final = [i.status for i in incidents]
    human = any(i.human_required for i in incidents) or any(t.status == "AWAITING_APPROVAL" for t in txs)
    settled = bool(incidents) and all(s in ("RESOLVED", "MITIGATED") for s in final)
    if run.status == "OBSERVING" and (settled or (human and not any(t.status in ("PLANNED", "RUNNING") for t in txs))):
        run.status = "COMPLETED" if settled else "HUMAN_REQUIRED"
        run.finished_at = run.finished_at or ctx.clock.now()
    elif run.status == "HUMAN_REQUIRED" and settled:
        run.status = "COMPLETED"
        run.finished_at = ctx.clock.now()
    return {
        "id": run.id, "scenario": run.scenario, "title": run.title, "status": run.status, "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None, "injections": run.injections, "requested_by": run.requested_by,
        "detection_seconds": round((first_alert - start_ts).total_seconds(), 1) if first_alert else None,
        "stages": {
            "trigger": stage(True, "; ".join(run.injections[:2])),
            "detection": stage(alerts, f"{alerts[0].name} after {(first_alert - start_ts).total_seconds():.1f} s" if first_alert else "waiting for monitoring"),
            "incident": stage(incidents, ", ".join(f"{i.id} {i.priority}" for i in incidents) or "-"),
            "root_cause": stage(any(i.root_cause for i in incidents), "; ".join(f"{i.root_cause} ({i.root_cause_confidence})" for i in incidents if i.root_cause) or "-"),
            "risk": stage(risks, "; ".join(f"{r.entity_id} {r.old_score}->{r.new_score}" for r in risks) or "no change"),
            "decision": stage(decisions, "; ".join(f"{d.action_id}: {d.outcome}" for d in decisions) or "-"),
            "action": stage(txs, "; ".join(f"{t.id} {t.action_name} [{t.status}]" for t in txs) or "-"),
            "verification": stage(tx_done, "; ".join(f"{t.id} {'PASSED' if t.result == 'SUCCESS' else t.result}" for t in tx_done) or "-"),
            "final_state": stage(run.status in ("COMPLETED", "HUMAN_REQUIRED"), ", ".join(f"{i.id} {s}" for i, s in zip(incidents, final, strict=False)) or "-"),
        },
        "human_required": human, "incidents": [i.id for i in incidents], "transactions": [t.id for t in txs],
        "events": [{"ts": e.ts.isoformat(), "type": e.type, "message": e.message, "severity": e.severity, "target": e.target} for e in events[-60:]],
        "operator_fix": (SCENARIOS[run.scenario].fix_label if run.scenario in SCENARIOS else None),
    }


def certificate_days(db: Session, cert_id: str, now: Any) -> float:
    cert = db.get(Certificate, cert_id)
    return (cert.not_after - now).total_seconds() / 86400 if cert else 0.0

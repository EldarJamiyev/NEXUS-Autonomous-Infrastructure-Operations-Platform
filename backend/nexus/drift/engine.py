"""Configuration drift: GIT INTENT (baselines/*.yaml) vs ACTUAL STATE (host agents, firewall, switch).

Pipeline per device: load desired -> load actual -> NORMALIZE native config into semantic keys ->
diff -> classify (POL-SERVER-BASELINE) -> record DriftEvent with SHA-256 evidence and a real
unified diff -> open an incident for SECURITY/CRITICAL drift -> ask the decision engine for a fix.
"""

from __future__ import annotations

import copy
import difflib
import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.store import get_setting
from nexus.core.util import sha256_of
from nexus.firewall.base import FirewallUnavailable, rule_key
from nexus.ids import new_id
from nexus.models import ConfigItem, Device, DriftEvent, Interface, RemediationTransaction

if TYPE_CHECKING:
    from nexus.core.context import Context

ACTIVE = ("OPEN", "APPROVAL_REQUIRED", "REMEDIATING", "FAILED", "EXPECTED")
NATIVE: dict[str, dict[str, tuple[str, str]]] = {
    "ssh": {"permit_root_login": ("PermitRootLogin", "yesno"), "password_authentication": ("PasswordAuthentication", "yesno"),
            "port": ("Port", "int"), "max_auth_tries": ("MaxAuthTries", "int"), "x11_forwarding": ("X11Forwarding", "yesno")},
    "docker": {"live_restore": ("live-restore", "bool"), "log_max_size": ("log-opts.max-size", "str")},
}


# --------------------------------------------------------------------------- intent
def load_baselines(config_root: Path) -> dict[str, Any]:
    folder = config_root / "baselines"
    docs = {p.stem: yaml.safe_load(p.read_text(encoding="utf-8")) or {} for p in sorted(folder.glob("*.yaml"))}
    templates = {d.get("name"): d for d in docs.values() if d.get("kind") == "HostBaseline" and d.get("name")}
    hosts: dict[str, dict[str, Any]] = {}
    network: dict[str, Any] = {}
    for stem, doc in docs.items():
        if doc.get("kind") == "NetworkBaseline":
            network = doc
            continue
        server = doc.get("server")
        if not server:
            continue
        merged: dict[str, Any] = {}
        parent = templates.get(doc.get("inherits"))
        for source in ([parent] if parent else []) + [doc]:
            for k, v in source.items():
                if k in ("apiVersion", "kind", "name", "server", "inherits"):
                    continue
                merged[k] = {**merged.get(k, {}), **v} if isinstance(v, dict) and isinstance(merged.get(k), dict) else copy.deepcopy(v)
        merged["_file"] = f"baselines/{stem}.yaml"
        hosts[server] = merged
    return {"hosts": hosts, "network": network}


def baselines(ctx: Context) -> dict[str, Any]:
    cached = getattr(ctx, "_baselines", None)
    if cached is None:
        cached = load_baselines(ctx.settings.config_root)
        ctx._baselines = cached  # type: ignore[attr-defined]
    return cached


def reload_baselines(ctx: Context) -> None:
    ctx._baselines = load_baselines(ctx.settings.config_root)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------- normalization
def _get(d: dict[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _set(d: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def _to_semantic(value: Any, kind: str) -> Any:
    if kind == "yesno":
        return str(value).lower() == "yes"
    if kind == "int":
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if kind == "bool":
        return bool(value)
    return value


def _to_native(value: Any, kind: str) -> Any:
    if kind == "yesno":
        return "yes" if value else "no"
    return value


def normalize(component: str, actual: dict[str, Any]) -> dict[str, Any]:
    if component in NATIVE:
        return {sem: _to_semantic(_get(actual, native), kind) for sem, (native, kind) in NATIVE[component].items()}
    if component == "services":
        return {f"{name}.enabled": bool(spec.get("enabled")) for name, spec in actual.items() if isinstance(spec, dict)}
    if component == "nginx":
        out = {k: v for k, v in actual.items()}
        if isinstance(out.get("listen"), list):
            out["listen"] = sorted(out["listen"], key=str)
        return out
    return dict(actual)


def desired_flat(component: str, desired: Any) -> dict[str, Any]:
    if component == "services":
        return {f"{name}.enabled": bool(spec.get("enabled", True)) for name, spec in desired.items()}
    if component == "nginx" and isinstance(desired.get("listen"), list):
        desired = {**desired, "listen": sorted(desired["listen"], key=str)}
    return dict(desired)


def denormalize(component: str, desired: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Apply desired semantic values to a native config (what 'restore baseline' writes)."""
    out = copy.deepcopy(actual)
    if component in NATIVE:
        for sem, (native, kind) in NATIVE[component].items():
            if sem in desired:
                _set(out, native, _to_native(desired[sem], kind))
        return out
    if component == "services":
        for name, spec in desired.items():
            out.setdefault(name, {})["enabled"] = bool(spec.get("enabled", True))
        return out
    for k, v in desired.items():
        out[k] = copy.deepcopy(v)
    return out


def render(component: str, values: dict[str, Any]) -> list[str]:
    """Render semantic config in its native file syntax so diffs read like the real files."""
    if component == "ssh":
        return [f"{NATIVE['ssh'][k][0]} {_to_native(v, NATIVE['ssh'][k][1])}" for k, v in sorted(values.items()) if k in NATIVE["ssh"]]
    if component == "nginx":
        lines = [f"listen {p};" for p in values.get("listen", [])]
        lines += [f"{k} {v};" for k, v in sorted(values.items()) if k != "listen"]
        return lines
    if component == "firewall":
        return [f"{r['id']}: {r['action']} {r['source']} -> {r['destination']}:{r['port']}/{r['protocol']}" for r in values.get("rules", [])]
    return [f"{k}: {v}" for k, v in sorted(values.items())]


def unified_diff(component: str, actual: dict[str, Any], desired: dict[str, Any], device: str) -> str:
    a, b = render(component, actual), render(component, desired)
    return "\n".join(difflib.unified_diff(a, b, fromfile=f"{device}:{component} (actual)", tofile=f"{device}:{component} (git intent)", lineterm=""))


def desired_config(ctx: Context, device_id: str, component: str) -> dict[str, Any] | None:
    host = baselines(ctx)["hosts"].get(device_id, {})
    value = host.get(component)
    return value if isinstance(value, dict) else None


def restored_config(ctx: Context, db: Session, device_id: str, component: str) -> dict[str, Any]:
    item = db.get(ConfigItem, f"{device_id}:{component}")
    desired = desired_config(ctx, device_id, component) or {}
    return denormalize(component, desired, item.actual if item else {})


def config_matches(ctx: Context, db: Session, device_id: str, component: str) -> tuple[bool, str, str]:
    desired = desired_config(ctx, device_id, component)
    item = db.get(ConfigItem, f"{device_id}:{component}")
    if desired is None or item is None:
        return True, "", ""
    want = desired_flat(component, desired)
    have = normalize(component, item.actual)
    sub = {k: have.get(k) for k in want}
    return sub == want, sha256_of(want), sha256_of(sub)


# ------------------------------------------------------------------------------ diffing
def device_diffs(ctx: Context, db: Session, device_id: str) -> list[dict[str, Any]]:
    host = baselines(ctx)["hosts"].get(device_id)
    if not host:
        return []
    diffs = []
    for component, desired in host.items():
        if component.startswith("_") or component == "firewall" or not isinstance(desired, dict):
            continue
        item = db.get(ConfigItem, f"{device_id}:{component}")
        if item is None:
            continue
        want = desired_flat(component, desired)
        have = normalize(component, item.actual)
        for key, value in want.items():
            if have.get(key) != value:
                diffs.append({"device": device_id, "component": component, "key": key, "desired": value, "actual": have.get(key),
                              "desired_checksum": sha256_of(want), "actual_checksum": sha256_of({k: have.get(k) for k in want}),
                              "diff": unified_diff(component, {k: have.get(k) for k in want}, want, device_id),
                              "source": host.get("_file", "baselines/")})
    return diffs


def vlan_diffs(ctx: Context, db: Session) -> list[dict[str, Any]]:
    intent = baselines(ctx)["network"].get("switchports", {})
    diffs = []
    for port, spec in intent.items():
        iface = db.get(Interface, f"SW-CORE01:{port}")
        dev = db.get(Device, spec.get("device"))
        if iface is None or dev is None or dev.quarantined:
            continue
        if iface.vlan_id != spec.get("vlan"):
            want, have = {"vlan": spec.get("vlan")}, {"vlan": iface.vlan_id}
            diffs.append({"device": dev.id, "component": "network", "key": "vlan", "desired": spec.get("vlan"), "actual": iface.vlan_id,
                          "desired_checksum": sha256_of(want), "actual_checksum": sha256_of(have),
                          "diff": "\n".join(difflib.unified_diff([f"interface {port}", f" switchport access vlan {iface.vlan_id}"],
                                                                 [f"interface {port}", f" switchport access vlan {spec.get('vlan')}"],
                                                                 fromfile="SW-CORE01 (running-config)", tofile="baselines/network.yaml", lineterm="")),
                          "source": "baselines/network.yaml"})
    return diffs


def firewall_diffs(ctx: Context, db: Session) -> list[dict[str, Any]] | None:
    from nexus.policy.compiler import desired_firewall

    try:
        actual = [r for r in ctx.firewall.list_rules(db) if r.get("enabled", True)]
    except FirewallUnavailable:
        return None
    desired = desired_firewall(ctx, db)
    desired_keys = {s.key(): s for s in desired}
    actual_keys = {rule_key(r): r for r in actual}
    want_rules = [{"id": s.rule_id or "(dynamic)", "action": s.action, "source": s.source, "destination": s.destination, "port": s.port, "protocol": s.protocol} for s in desired]
    diffs = []
    for key, r in actual_keys.items():
        if key not in desired_keys:
            text = unified_diff("firewall", {"rules": [r]}, {"rules": []}, "PFSENSE")
            diffs.append({"device": "PFSENSE", "component": "firewall", "key": f"unauthorized_rule:{r['id']}", "rule": r,
                          "desired": None, "actual": {k: r[k] for k in ("id", "action", "source", "destination", "protocol", "port", "created_by")},
                          "desired_checksum": sha256_of(want_rules), "actual_checksum": sha256_of(sorted(map(str, actual_keys))), "diff": text,
                          "source": "policies/firewall-baseline.yaml + active leases"})
    for key, s in desired_keys.items():
        if key not in actual_keys and s.origin in ("baseline", "policy"):
            text = unified_diff("firewall", {"rules": []}, {"rules": [{"id": s.rule_id, "action": s.action, "source": s.source, "destination": s.destination, "port": s.port, "protocol": s.protocol}]}, "PFSENSE")
            diffs.append({"device": "PFSENSE", "component": "firewall", "key": f"missing_rule:{s.rule_id}", "desired": s.as_dict(), "actual": None,
                          "desired_checksum": sha256_of(want_rules), "actual_checksum": sha256_of(sorted(map(str, actual_keys))), "diff": text,
                          "source": "policies/firewall-baseline.yaml"})
    return diffs


def classify(ctx: Context, component: str, key: str, diff: dict[str, Any] | None = None) -> tuple[str, int, str | None]:
    rules = (ctx.policy_cache.server_baseline if ctx.policy_cache else {}).get("drift_classification", [])
    probe = f"{component}.{key}"
    for rule in rules:
        if fnmatch.fnmatch(probe, rule["match"]):
            cls, risk = rule["class"], int(rule["risk"])
            if component == "firewall" and key.startswith("unauthorized_rule") and diff:
                r = diff.get("rule", {})
                broad = str(r.get("source", "")).upper() == "ANY"
                admin = any(p in str(r.get("port", "")) for p in ("22", "3389", "ANY"))
                risk = 85 if broad and admin else 70 if broad or admin else 55
            return cls, risk, rule.get("action")
    return "OPERATIONAL", 20, None


# --------------------------------------------------------------------------- reconcile
def scan(ctx: Context, db: Session, device_ids: set[str] | None = None) -> dict[str, Any]:
    """Compare intent vs reality, maintain DriftEvents, open incidents, plan remediation."""
    hosts = set(baselines(ctx)["hosts"])
    targets = (device_ids & (hosts | {"PFSENSE"} | {d.id for d in db.scalars(select(Device))})) if device_ids else hosts
    diffs: list[dict[str, Any]] = []
    scanned_devices: set[str] = set()
    for device_id in sorted(targets):
        diffs += device_diffs(ctx, db, device_id)
        scanned_devices.add(device_id)
    firewall_known = True
    if device_ids is None or "PFSENSE" in device_ids:
        fw = firewall_diffs(ctx, db)
        if fw is None:
            firewall_known = False
        else:
            diffs += fw
    vlan_scope = device_ids is None or bool(device_ids & {d.id for d in db.scalars(select(Device).where(Device.kind == "workstation"))})
    if vlan_scope:
        diffs += vlan_diffs(ctx, db)
    maintenance = get_setting(db, "maintenance") or {}
    now = ctx.clock.now()
    seen: set[tuple[str, str, str]] = set()
    new, cleared = [], []
    for d in diffs:
        ident = (d["device"], d["component"], d["key"])
        seen.add(ident)
        existing = db.scalar(select(DriftEvent).where(DriftEvent.device_id == d["device"], DriftEvent.component == d["component"],
                                                      DriftEvent.key == d["key"], DriftEvent.status.in_(ACTIVE)))
        if existing:
            existing.actual = d["actual"]
            existing.actual_checksum = d["actual_checksum"]
            existing.diff = d["diff"]
            continue
        cls, risk, action = classify(ctx, d["component"], d["key"], d)
        expected = bool(maintenance.get("active"))
        drift = DriftEvent(id=new_id(db, "drift"), device_id=d["device"], component=d["component"], key=d["key"], desired=d["desired"],
                           actual=d["actual"], classification=cls, risk=risk, status="EXPECTED" if expected else "OPEN",
                           remediation_action=action, desired_checksum=d["desired_checksum"], actual_checksum=d["actual_checksum"],
                           diff=d["diff"], source=d["source"], during_maintenance=expected, correlation_id=new_id(db, "corr"), detected_at=now)
        db.add(drift)
        db.flush()
        new.append(drift)
        ctx.bus.emit(db, "DRIFT_DETECTED", f"{drift.id} {drift.device_id} {drift.component}.{drift.key}: desired {d['desired']!r}, actual {d['actual']!r} "
                     f"({cls}{', expected during maintenance' if expected else ''})", severity="high" if cls in ("SECURITY", "CRITICAL") else "warning",
                     source="drift-engine", target=drift.device_id,
                     data={"drift": drift.id, "class": cls, "risk": risk, "component": drift.component, "key": drift.key,
                           "desired_checksum": drift.desired_checksum, "actual_checksum": drift.actual_checksum}, correlation_id=drift.correlation_id)
    for drift in db.scalars(select(DriftEvent).where(DriftEvent.status.in_(ACTIVE))).all():
        ident = (drift.device_id, drift.component, drift.key)
        in_scope = drift.device_id in scanned_devices or (drift.component == "firewall" and firewall_known and (device_ids is None or "PFSENSE" in device_ids)) \
            or (drift.component == "network" and vlan_scope)
        if in_scope and ident not in seen and drift.status != "REMEDIATING":
            drift.status = "RESOLVED_EXTERNALLY" if drift.status != "EXPECTED" else "ACCEPTED"
            drift.resolved_at = now
            cleared.append(drift.id)
            if drift.transaction_id:
                from nexus.incidents.engine import cancel_pending

                cancel_pending(ctx, db, transaction_id=drift.transaction_id, reason=f"{drift.id} cleared")
            ctx.bus.emit(db, "DRIFT_REMEDIATED", f"{drift.id} cleared: {drift.device_id} {drift.component}.{drift.key} matches intent again",
                         source="drift-engine", target=drift.device_id, data={"drift": drift.id, "by": "external change"}, correlation_id=drift.correlation_id)
            if drift.incident_id:
                from nexus.incidents.engine import resolve_incident

                resolve_incident(ctx, db, drift.incident_id, "configuration matches intent again", actor="NEXUS")
    planned = plan_open_drift(ctx, db)
    for dev_id in {x.device_id for x in new}:
        dev = db.get(Device, dev_id)
        if dev:
            from nexus.risk.engine import recompute_device

            recompute_device(ctx, db, dev, "configuration drift detected", evaluate_policy=False)
    return {"new": [x.id for x in new], "cleared": cleared, "planned": planned, "firewall_observed": firewall_known}


def plan_open_drift(ctx: Context, db: Session) -> list[str]:
    from nexus.core.decision import plan_action
    from nexus.incidents.engine import open_finding

    groups: dict[tuple[str, str], list[DriftEvent]] = {}
    for drift in db.scalars(select(DriftEvent).where(DriftEvent.status == "OPEN").order_by(DriftEvent.detected_at)):
        groups.setdefault((drift.device_id, drift.component), []).append(drift)
    tx_ids: list[str] = []
    incident_classes = set((ctx.policy_cache.server_baseline if ctx.policy_cache else {}).get("incident_classes", ["SECURITY", "CRITICAL"]))
    suppressions = get_setting(db, "drift_suppressions") or {}
    now_iso = ctx.clock.now().isoformat()
    for (device_id, component), drifts in groups.items():
        until = suppressions.get(f"{device_id}:{component}")
        if until and until > now_iso:
            for x in drifts:
                x.status = "ACCEPTED"
                x.source = f"{x.source} (operator rollback; accepted until {until[11:19]} UTC)"
            continue
        lead = max(drifts, key=lambda x: x.risk)
        if lead.classification in incident_classes and not lead.incident_id:
            name = "UnexpectedFirewallRule" if component == "firewall" else "ConfigurationDrift"
            if component == "firewall" and isinstance(lead.actual, dict):
                r = lead.actual
                summary = f"unauthorized rule {r.get('id')}: {r.get('action')} {r.get('source')} -> {r.get('destination')}:{r.get('port')}/{r.get('protocol')} (by {r.get('created_by')})"
            elif component == "firewall":
                summary = f"rule missing from pfSense: {lead.key.split(':', 1)[-1]}"
            else:
                summary = f"{component}.{lead.key}: desired {lead.desired!r}, actual {lead.actual!r}"
            alert = open_finding(ctx, db, name=name, target=device_id, summary=summary,
                                 labels={"component": component, "drift_ids": [x.id for x in drifts], "class": lead.classification})
            if alert and alert.incident_id:
                for x in drifts:
                    x.incident_id = alert.incident_id
        action_id = lead.remediation_action
        if not action_id:
            continue
        busy = db.scalar(select(RemediationTransaction).where(RemediationTransaction.target == device_id, RemediationTransaction.action_id == action_id,
                                                               RemediationTransaction.status.in_(("PLANNED", "RUNNING", "AWAITING_APPROVAL"))))
        if busy:
            continue
        params: dict[str, Any] = {"component": component, "drift_ids": [x.id for x in drifts]}
        if component == "firewall":
            params["rules"] = [x.key.split(":", 1)[1] for x in drifts if ":" in x.key]
        if component == "network":
            params["vlan"] = lead.desired
        evidence = [f"{x.id}: {x.component}.{x.key} desired {x.desired!r} actual {x.actual!r} (sha256 {x.desired_checksum[:8]} vs {x.actual_checksum[:8]})" for x in drifts]
        result = plan_action(ctx, db, action_id=action_id, target=device_id, params=params, trigger=f"Configuration drift {lead.id} ({lead.classification})",
                             evidence=evidence, incident_id=lead.incident_id, drift_id=lead.id, correlation_id=lead.correlation_id)
        status_map = {"AUTOMATE": "REMEDIATING", "APPROVAL_REQUIRED": "APPROVAL_REQUIRED", "RECOMMEND": "APPROVAL_REQUIRED"}
        for x in drifts:
            x.status = status_map.get(result["outcome"], "OPEN")
            x.transaction_id = result.get("transaction_id")
            if result["outcome"] == "BLOCKED":
                x.status = "FAILED"
        if result["outcome"] == "AUTOMATE" and result.get("transaction_id"):
            tx_ids.append(result["transaction_id"])
    return tx_ids


def end_maintenance_review(ctx: Context, db: Session) -> list[str]:
    """After maintenance: expected drift that is still present becomes an incident (and normal remediation)."""
    from nexus.incidents.engine import open_finding

    reopened = []
    for drift in db.scalars(select(DriftEvent).where(DriftEvent.status == "EXPECTED")).all():
        drift.status = "OPEN"
        drift.during_maintenance = True
        reopened.append(drift.id)
    for device_id in sorted({d.device_id for d in db.scalars(select(DriftEvent).where(DriftEvent.id.in_(reopened)))}):
        open_finding(ctx, db, name="UnexpectedDriftAfterMaintenance", target=device_id,
                     summary=f"Drift still present on {device_id} after the maintenance window closed", labels={"drift_ids": reopened})
    return reopened


def drift_dict(d: DriftEvent) -> dict[str, Any]:
    return {"id": d.id, "device_id": d.device_id, "component": d.component, "key": d.key, "desired": d.desired, "actual": d.actual,
            "classification": d.classification, "risk": d.risk, "status": d.status, "remediation_action": d.remediation_action,
            "transaction_id": d.transaction_id, "incident_id": d.incident_id, "desired_checksum": d.desired_checksum,
            "actual_checksum": d.actual_checksum, "checksum_match": d.desired_checksum == d.actual_checksum, "diff": d.diff, "source": d.source,
            "during_maintenance": d.during_maintenance, "correlation_id": d.correlation_id, "detected_at": d.detected_at.isoformat(),
            "resolved_at": d.resolved_at.isoformat() if d.resolved_at else None}

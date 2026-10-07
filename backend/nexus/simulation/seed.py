"""Seed the simulated enterprise from simulation/enterprise.yaml, then generate history."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.store import set_setting
from nexus.core.util import sha256_of
from nexus.models import (
    Base,
    Certificate,
    ConfigItem,
    Dependency,
    Device,
    Group,
    Interface,
    IpAddress,
    MacAddress,
    Service,
    User,
    UserGroup,
    Vlan,
)

if TYPE_CHECKING:
    from nexus.core.context import Context


def is_seeded(db: Session) -> bool:
    return db.scalar(select(Device.id).limit(1)) is not None


def wipe(ctx: Context) -> None:
    with ctx.engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            if table.name != "alembic_version":
                conn.execute(table.delete())
    ctx.runtime.metric_history.clear()
    ctx.runtime.inflight.clear()
    ctx.runtime.sync_queue.clear()
    ctx.runtime.firewall_available = True
    ctx.runtime.firewall_reconnect_at = None
    ctx.runtime.db_degraded_until = None
    ctx.runtime.blackout_running = False
    ctx.runtime.pending_reconcile.clear()


def seed_enterprise(ctx: Context, db: Session) -> None:
    from nexus.policy.cache import refresh, sync_from_disk
    from nexus.policy.compiler import baseline_specs, policy_deny_specs

    data = yaml.safe_load((ctx.settings.config_root / "simulation" / "enterprise.yaml").read_text(encoding="utf-8"))
    now = ctx.clock.now()
    domain = data["domain"]
    for v in data["vlans"]:
        dhcp = v.get("dhcp") or {}
        db.add(Vlan(id=v["id"], name=v["name"], subnet=v["subnet"], gateway=v["gateway"], purpose=v["purpose"], dhcp_enabled=bool(dhcp),
                    dhcp_pool_size=dhcp.get("pool_size", 0), dhcp_in_use=dhcp.get("in_use", 0), dhcp_stale=dhcp.get("stale", 0)))
    for g in data["groups"]:
        db.add(Group(id=g["id"], description=g["description"], privileged=g.get("privileged", False)))
    db.flush()
    for u in data["users"]:
        db.add(User(id=u["id"], display_name=u["display_name"], email=f"{u['id']}@{domain}", department=u["department"], title=u["title"],
                    console_role=u["console_role"], ad_dn=f"CN={u['display_name']},OU={u['department']},DC=corp,DC=nexus,DC=lab", created_at=now - timedelta(days=400)))
        db.flush()
        for g in u["groups"]:
            db.add(UserGroup(user_id=u["id"], group_id=g))
    ports = {p["device"]: p for p in data["switchports"] if p.get("device")}
    for d in data["devices"]:
        db.add(Device(id=d["id"], kind=d["kind"], os=d["os"], role=d["role"], vlan_id=d["vlan"], expected_vlan_id=d["vlan"], criticality=d["criticality"],
                      owner_user_id=d.get("owner"), status="healthy", managed=True, ad_computer=d.get("ad_computer", False), expected_hostname=d["id"],
                      dns_name=f"{d['id'].lower()}.{domain}", metrics={"disk": dict(data["disks"].get(d["id"], {}))}, expected_ports=d.get("ports", []),
                      observed_ports=d.get("ports", []) if d["kind"] == "server" else [], sim_faults={}, location=d.get("location", ""),
                      description=d["role"], first_seen=now - timedelta(days=300), last_seen=now))
        db.flush()
        port = ports.get(d["id"])
        iface_id = f"SW-CORE01:{port['name']}" if port else None
        db.add(MacAddress(address=d["mac"], device_id=d["id"], vendor=d.get("vendor", ""), known=True, interface_id=iface_id,
                          first_seen=now - timedelta(days=300), last_seen=now))
        db.add(IpAddress(address=d["ip"], device_id=d["id"], mac=d["mac"], vlan_id=d["vlan"], assignment="dhcp" if d.get("dhcp") else "static",
                         dhcp_hostname=d["id"] if d.get("dhcp") else None, updated_at=now))
    db.flush()
    switchports = {}
    for p in data["switchports"]:
        db.add(Interface(id=f"SW-CORE01:{p['name']}", switch_id="SW-CORE01", name=p["name"], vlan_id=p.get("vlan"), device_id=p.get("device"),
                         mode=p.get("mode", "access"), status="up" if p.get("device") else "down"))
        if p.get("vlan"):
            switchports[p["name"]] = {"vlan": p["vlan"], "device": p.get("device")}
    for s in data["services"]:
        name, device = s["id"].split("@")
        db.add(Service(id=s["id"], name=name, display_name=s["display"], device_id=device, kind=s.get("kind", "systemd"), unit=s.get("unit", name),
                       ports=s.get("ports", []), status="running", enabled=True, criticality=s["criticality"], consumers=s.get("consumers", "none"),
                       rto_minutes=s.get("rto"), rpo_minutes=s.get("rpo"), last_change=now - timedelta(days=30)))
    db.flush()
    for dep in data["dependencies"]:
        db.add(Dependency(source_id=dep["source"], target_id=dep["target"], description=dep["description"]))
    for c in data["certificates"]:
        db.add(Certificate(id=c["id"], device_id=c["device"], service_id=c.get("service"), not_after=now + timedelta(days=c["days_valid"])))
    configs = dict(data["configs"])
    configs.setdefault("SW-CORE01", {})["switchports"] = switchports
    for device_id, comps in configs.items():
        for comp, actual in comps.items():
            value = {"paths": actual} if comp == "host_files" else actual
            db.add(ConfigItem(id=f"{device_id}:{comp}", device_id=device_id, component=comp, actual=value, checksum=sha256_of(value),
                              updated_at=now - timedelta(days=30), updated_by="baseline"))
    db.flush()
    set_setting(db, "autonomy_level", ctx.settings.autonomy_level, now)
    sync_from_disk(ctx, db, author="git")
    refresh(ctx, db)
    for spec in baseline_specs(ctx.policy_cache) + policy_deny_specs(ctx.policy_cache):
        spec.created_by = "git-intent"
        ctx.firewall.create_rule(db, spec)
    from nexus.identity.confidence import update_identity

    for dev in db.scalars(select(Device)):
        update_identity(ctx, db, dev, "initial inventory")

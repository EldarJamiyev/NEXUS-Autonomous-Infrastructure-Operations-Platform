"""Identity confidence - a configurable prototype heuristic, not a statistical model.

Each signal is True (earned), False (missing) or None (not applicable to this device kind).
confidence = earned weight / applicable weight. Weights live in policies/identity-confidence.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.models import Device, IpAddress, MacAddress, Service
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context

DEFAULT_SIGNALS = {"ad_computer_match": 25, "ad_user_session": 20, "dhcp_hostname": 15, "dns_match": 10,
                   "known_mac": 15, "expected_vlan": 10, "monitoring_presence": 5}
DEFAULT_LEVELS = [(95, "TRUSTED"), (80, "VERIFIED"), (60, "UNCERTAIN"), (40, "SUSPICIOUS"), (0, "UNKNOWN")]
LABELS = {"ad_computer_match": "AD computer object", "ad_user_session": "AD user session", "dhcp_hostname": "DHCP hostname",
          "dns_match": "DNS forward record", "known_mac": "Known MAC address", "expected_vlan": "Expected VLAN",
          "monitoring_presence": "Monitoring presence"}


@dataclass
class IdentityResult:
    confidence: int
    level: str
    signals: list[dict[str, Any]] = field(default_factory=list)


def signal_config(ctx: Context) -> tuple[dict[str, int], list[tuple[int, str]]]:
    cache = ctx.policy_cache
    if cache and cache.identity_signals:
        cfg = cache.identity_signals
        levels = sorted(((int(lv["min"]), lv["level"]) for lv in cfg.get("levels", [])), reverse=True)
        return {k: int(v) for k, v in cfg.get("signals", {}).items()}, levels or DEFAULT_LEVELS
    return DEFAULT_SIGNALS, DEFAULT_LEVELS


def level_for(confidence: int, levels: list[tuple[int, str]]) -> str:
    for threshold, name in levels:
        if confidence >= threshold:
            return name
    return "UNKNOWN"


def compute_identity(ctx: Context, db: Session, device: Device) -> IdentityResult:
    weights, levels = signal_config(ctx)
    ip = db.scalar(select(IpAddress).where(IpAddress.device_id == device.id))
    mac = db.scalar(select(MacAddress).where(MacAddress.device_id == device.id))
    interactive = device.kind in ("workstation", "unknown")
    session = db.scalar(select(UserSession).where(UserSession.device_id == device.id, UserSession.active.is_(True)))
    dns_up = (svc := db.get(Service, "dns@DC01")) is not None and svc.status == "running"
    checks: dict[str, tuple[bool | None, str]] = {
        "ad_computer_match": (ctx.identity.computer_exists(db, device.id) if device.kind not in ("firewall", "switch") else None,
                              "computer object found in directory" if device.ad_computer else "no computer object in directory"),
        "ad_user_session": ((session is not None) if interactive else None,
                            f"{session.user_id} logged on (4624)" if session else ("no interactive session" if interactive else "not applicable for servers")),
        "dhcp_hostname": ((bool(ip and ip.dhcp_hostname and device.expected_hostname and ip.dhcp_hostname.upper() == device.expected_hostname.upper()))
                          if ip and ip.assignment in ("dhcp", "apipa") else None,
                          f"DHCP option 12: {ip.dhcp_hostname or 'none'}" if ip else "no address"),
        "dns_match": ((dns_up and bool(device.dns_name) and ip is not None and ip.assignment != "apipa"),
                      ("A record matches " + (ip.address if ip else "-")) if dns_up and device.dns_name else ("DNS unavailable" if not dns_up else "no DNS record")),
        "known_mac": (bool(mac and mac.known), f"{mac.address} {'in inventory' if mac and mac.known else 'not in inventory'}" if mac else "no MAC observed"),
        "expected_vlan": ((device.expected_vlan_id is not None and device.vlan_id == device.expected_vlan_id),
                          f"VLAN {device.vlan_id} (expected {device.expected_vlan_id or 'unknown'})"),
        "monitoring_presence": (device.reachable, "responds to ICMP from MON01" if device.reachable else "no response"),
    }
    earned = applicable = 0
    signals = []
    for key, weight in weights.items():
        status, detail = checks.get(key, (None, "unsupported signal"))
        if status is not None:
            applicable += weight
            earned += weight if status else 0
        signals.append({"key": key, "label": LABELS.get(key, key), "weight": weight, "status": status, "detail": detail,
                        "points": weight if status else 0})
    confidence = round(100 * earned / applicable) if applicable else 0
    return IdentityResult(confidence=confidence, level=level_for(confidence, levels), signals=signals)


def update_identity(ctx: Context, db: Session, device: Device, reason: str, correlation_id: str | None = None) -> IdentityResult:
    result = compute_identity(ctx, db, device)
    old = device.identity_confidence
    device.identity_signals = {"signals": result.signals, "computed_at": ctx.clock.now().isoformat()}
    if old != result.confidence or device.identity_level != result.level:
        device.identity_confidence = result.confidence
        device.identity_level = result.level
        ctx.bus.emit(db, "IDENTITY_CONFIDENCE_CHANGED", f"{device.id} identity confidence {old}% -> {result.confidence}% ({result.level})",
                     severity="warning" if result.confidence < 60 else "info", target=device.id,
                     data={"old": old, "new": result.confidence, "level": result.level, "reason": reason},
                     correlation_id=correlation_id)
    return result

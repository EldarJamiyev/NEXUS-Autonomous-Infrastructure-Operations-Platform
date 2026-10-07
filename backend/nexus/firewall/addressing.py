"""Address resolution, first-match rule evaluation and shadowed-rule analysis."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_ports(spec: Any) -> set[int] | None:
    """'22' | '80,443' | '1000-1010' | 'ANY' -> set of ports, None meaning any."""
    s = str(spec).strip().upper()
    if s in ("ANY", "*", ""):
        return None
    out: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(part))
    return out


@dataclass
class Resolver:
    aliases: dict[str, list[str]] = field(default_factory=dict)
    group_ips: dict[str, list[str]] = field(default_factory=dict)
    device_ips: dict[str, str] = field(default_factory=dict)
    group_fallback: dict[str, list[str]] = field(default_factory=dict)  # used for static analysis only
    analysis: bool = False

    def networks(self, token: str, _depth: int = 0) -> list[Net] | None:
        t = str(token).strip()
        if t.upper() in ("ANY", "*"):
            return None
        if _depth > 5:
            return []
        if t in self.aliases:
            nets: list[Net] = []
            for member in self.aliases[t]:
                resolved = self.networks(member, _depth + 1)
                if resolved is None:
                    return None
                nets.extend(resolved)
            return nets
        if t.startswith("GRP:"):
            ips = self.group_ips.get(t[4:], [])
            if not ips and self.analysis:
                return [n for f in self.group_fallback.get(t[4:], []) for n in (self.networks(f, _depth + 1) or [])]
            return [ipaddress.ip_network(f"{ip}/32") for ip in ips]
        if t in self.device_ips:
            return [ipaddress.ip_network(f"{self.device_ips[t]}/32")]
        try:
            return [ipaddress.ip_network(t, strict=False)]
        except ValueError:
            return []

    def matches(self, token: str, ip: str | None) -> bool:
        nets = self.networks(token)
        if nets is None:
            return True
        if ip is None:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    def covers(self, outer: str, inner: str) -> bool:
        o, i = self.networks(outer), self.networks(inner)
        if o is None:
            return True
        if i is None:
            return False
        if not i:
            return True  # inner matches nothing; trivially covered
        return all(any(n.version == m.version and n.subnet_of(m) for m in o) for n in i)  # type: ignore[arg-type]


def _proto_covers(outer: str, inner: str) -> bool:
    return outer.upper() == "ANY" or outer.upper() == inner.upper()


def _ports_cover(outer: Any, inner: Any) -> bool:
    o, i = parse_ports(outer), parse_ports(inner)
    if o is None:
        return True
    if i is None:
        return False
    return i.issubset(o)


def rule_matches(resolver: Resolver, rule: dict[str, Any], src_ip: str | None, dst_ip: str | None, protocol: str, port: int) -> bool:
    if not rule.get("enabled", True):
        return False
    if rule["protocol"].upper() not in ("ANY", protocol.upper()):
        return False
    ports = parse_ports(rule["port"])
    if ports is not None and port not in ports:
        return False
    return resolver.matches(rule["source"], src_ip) and resolver.matches(rule["destination"], dst_ip)


def evaluate(resolver: Resolver, rules: list[dict[str, Any]], src_ip: str | None, dst_ip: str | None, protocol: str,
             port: int) -> tuple[str, dict[str, Any] | None]:
    """First-match semantics (pfSense evaluates rules top-down). No match -> implicit deny."""
    for rule in sorted(rules, key=lambda r: (r["position"], r["id"])):
        if rule_matches(resolver, rule, src_ip, dst_ip, protocol, port):
            return rule["action"].upper(), rule
    return "DENY", None


def shadow_analysis(resolver: Resolver, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = [r for r in sorted(rules, key=lambda r: (r["position"], r["id"])) if r.get("enabled", True)]
    findings = []
    for idx, later in enumerate(ordered):
        for earlier in ordered[:idx]:
            if (_proto_covers(earlier["protocol"], later["protocol"]) and _ports_cover(earlier["port"], later["port"])
                    and resolver.covers(earlier["source"], later["source"]) and resolver.covers(earlier["destination"], later["destination"])):
                conflicting = earlier["action"].upper() != later["action"].upper()
                if not conflicting and later.get("origin") == "baseline" and later["destination"].upper() == "ANY":
                    continue
                findings.append({
                    "rule": later["id"], "shadowed_by": earlier["id"], "kind": "SHADOWED RULE" if conflicting else "REDUNDANT RULE",
                    "severity": "warning" if conflicting else "info",
                    "message": (f"{later['id']} ({later['action']} {later['source']} -> {later['destination']}:{later['port']}) is never reached: "
                                f"{earlier['id']} ({earlier['action']} {earlier['source']} -> {earlier['destination']}:{earlier['port']}) matches first"),
                })
                break
    return findings

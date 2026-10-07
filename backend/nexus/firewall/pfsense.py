"""PfSenseAdapter - OPTIONAL, EXPERIMENTAL real-lab adapter.

Targets the community pfSense REST API package v2 (pfSense-pkg-RESTAPI, "pfrest"):
  GET  /api/v2/firewall/rules      list rules
  POST /api/v2/firewall/rule       create rule
  DELETE /api/v2/firewall/rule?id= delete rule
  POST /api/v2/firewall/apply      apply pending changes
Authentication: X-API-Key header.

Status: written against the published API documentation but NOT exercised against a live
pfSense in this repository's CI. It only manages rules whose description starts with "NEXUS:" and
never touches rules created by humans. Enable with NEXUS_FIREWALL_ADAPTER=pfsense, PFSENSE_URL,
PFSENSE_API_KEY. The default demo never uses it, and nothing in the simulation claims to change a
real firewall.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from sqlalchemy.orm import Session

from nexus.firewall.base import FirewallAdapter, FirewallUnavailable, RuleSpec

PREFIX = "NEXUS:"


class PfSenseAdapter(FirewallAdapter):
    name = "pfsense-rest-v2"
    mode = "REAL LAB"

    def __init__(self, base_url: str, api_key: str, verify_tls: bool = True, interface_map: str | None = None) -> None:
        if not base_url or not api_key:
            raise ValueError("PFSENSE_URL and PFSENSE_API_KEY are required for the pfSense adapter")
        self.client = httpx.Client(base_url=base_url.rstrip("/"), headers={"X-API-Key": api_key}, verify=verify_tls, timeout=8.0)
        raw = interface_map or os.environ.get("PFSENSE_INTERFACE_MAP", "10:lan,20:opt1,30:opt2,40:opt3,50:opt4,99:opt5")
        self.interfaces = {int(k): v for k, v in (p.split(":", 1) for p in raw.split(",") if ":" in p)}
        self._ok = True

    def _call(self, method: str, path: str, **kw: Any) -> Any:
        try:
            resp = self.client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            self._ok = False
            raise FirewallUnavailable(f"pfSense API error: {exc}") from exc
        if resp.status_code >= 500:
            self._ok = False
            raise FirewallUnavailable(f"pfSense API returned {resp.status_code}")
        resp.raise_for_status()
        self._ok = True
        return resp.json().get("data")

    def available(self) -> bool:
        try:
            self._call("GET", "/api/v2/status/system")
        except Exception:  # noqa: BLE001
            return False
        return True

    def _interface_for(self, source: str) -> str:
        for vlan, iface in self.interfaces.items():
            if source.startswith(f"10.{vlan}.{vlan}."):
                return iface
        return self.interfaces.get(30, "lan")

    def create_rule(self, db: Session, spec: RuleSpec) -> str:
        payload = {
            "type": "pass" if spec.action.upper() == "ALLOW" else "block",
            "interface": [self._interface_for(spec.source)], "ipprotocol": "inet",
            "protocol": None if spec.protocol.upper() == "ANY" else spec.protocol.lower(),
            "source": "any" if spec.source.upper() == "ANY" else spec.source,
            "destination": "any" if spec.destination.upper() == "ANY" else spec.destination,
            "destination_port": None if str(spec.port).upper() == "ANY" else str(spec.port).replace(",", " "),
            "descr": f"{PREFIX}{spec.lease_id or spec.policy_id or spec.origin}:{spec.description}"[:250],
        }
        data = self._call("POST", "/api/v2/firewall/rule", json=payload)
        self._call("POST", "/api/v2/firewall/apply")
        return str(data.get("id"))

    def delete_rule(self, db: Session, rule_id: str) -> None:
        self._call("DELETE", "/api/v2/firewall/rule", params={"id": rule_id})
        self._call("POST", "/api/v2/firewall/apply")

    def list_rules(self, db: Session) -> list[dict[str, Any]]:
        out = []
        for i, r in enumerate(self._call("GET", "/api/v2/firewall/rules") or []):
            descr = r.get("descr") or ""
            out.append({"id": str(r.get("id", i)), "position": i * 10, "action": "ALLOW" if r.get("type") == "pass" else "DENY",
                        "source": r.get("source") or "ANY", "destination": r.get("destination") or "ANY",
                        "protocol": (r.get("protocol") or "ANY").upper(), "port": r.get("destination_port") or "ANY",
                        "description": descr, "origin": "nexus" if descr.startswith(PREFIX) else "manual", "enabled": not r.get("disabled", False)})
        return out

    def get_state(self, db: Session) -> dict[str, Any]:
        try:
            rules = self.list_rules(db)
        except FirewallUnavailable:
            return {"adapter": self.name, "mode": self.mode, "available": False}
        return {"adapter": self.name, "mode": self.mode, "available": True, "rule_count": len(rules)}

    def apply_policy(self, db: Session, desired: list[RuleSpec]) -> dict[str, list[str]]:
        managed = [r for r in self.list_rules(db) if r["origin"] == "nexus"]
        removed = []
        for r in managed:
            self.delete_rule(db, r["id"])
            removed.append(r["id"])
        added = [self.create_rule(db, s) for s in desired if s.origin != "baseline"]
        return {"added": added, "removed": removed}

    def rollback(self, db: Session, backup: list[dict[str, Any]]) -> None:
        current = {r["id"] for r in self.list_rules(db) if r["origin"] == "nexus"}
        wanted = [r for r in backup if r.get("origin") == "nexus"]
        for rule_id in current:
            self.delete_rule(db, rule_id)
        for r in wanted:
            self.create_rule(db, RuleSpec(action=r["action"], source=r["source"], destination=r["destination"], protocol=r["protocol"],
                                          port=r["port"], description=r.get("description", ""), origin="nexus"))

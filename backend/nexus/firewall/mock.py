"""MockFirewallAdapter - the default. Rules live in the firewall_rules table (the simulated pfSense).

It can be disconnected by the Chaos Lab; every call then raises FirewallUnavailable so the rest of
NEXUS has to cope honestly (PENDING lease state, DEGRADED system mode, deferred reconciliation).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.util import sha256_of
from nexus.firewall.base import FirewallAdapter, FirewallUnavailable, RuleSpec
from nexus.ids import new_id
from nexus.models import FirewallRule

if TYPE_CHECKING:
    from nexus.core.context import Context


def rule_dict(r: FirewallRule) -> dict[str, Any]:
    return {"id": r.id, "position": r.position, "action": r.action, "source": r.source, "destination": r.destination,
            "protocol": r.protocol, "port": r.port, "description": r.description, "origin": r.origin, "lease_id": r.lease_id,
            "policy_id": r.policy_id, "enabled": r.enabled, "created_at": r.created_at.isoformat() if r.created_at else None,
            "created_by": r.created_by}


class MockFirewallAdapter(FirewallAdapter):
    name = "mock-pfsense"
    mode = "SIMULATION"

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    def available(self) -> bool:
        return self.ctx.runtime.firewall_available

    def _guard(self) -> None:
        if not self.available():
            raise FirewallUnavailable("pfSense API unreachable: connect timeout after 5s (simulated outage)")

    def create_rule(self, db: Session, spec: RuleSpec) -> str:
        self._guard()
        rule_id = spec.rule_id or new_id(db, "fwrule")
        if db.get(FirewallRule, rule_id) is not None:
            return rule_id
        db.add(FirewallRule(id=rule_id, position=spec.position, action=spec.action.upper(), source=spec.source,
                            destination=spec.destination, protocol=spec.protocol.upper(), port=str(spec.port).upper(),
                            description=spec.description, origin=spec.origin, lease_id=spec.lease_id, policy_id=spec.policy_id,
                            enabled=True, created_at=self.ctx.clock.now(), created_by=spec.created_by))
        db.flush()
        return rule_id

    def delete_rule(self, db: Session, rule_id: str) -> None:
        self._guard()
        rule = db.get(FirewallRule, rule_id)
        if rule is not None:
            db.delete(rule)
            db.flush()

    def list_rules(self, db: Session) -> list[dict[str, Any]]:
        self._guard()
        return [rule_dict(r) for r in db.scalars(select(FirewallRule).order_by(FirewallRule.position, FirewallRule.id))]

    def get_state(self, db: Session) -> dict[str, Any]:
        if not self.available():
            return {"adapter": self.name, "mode": self.mode, "available": False, "rule_count": None, "checksum": None}
        rules = self.list_rules(db)
        return {"adapter": self.name, "mode": self.mode, "available": True, "rule_count": len(rules),
                "checksum": sha256_of([{k: r[k] for k in ("action", "source", "destination", "protocol", "port", "position")} for r in rules])}

    def rollback(self, db: Session, backup: list[dict[str, Any]]) -> None:
        self._guard()
        for existing in db.scalars(select(FirewallRule)).all():
            db.delete(existing)
        db.flush()
        for r in backup:
            db.add(FirewallRule(id=r["id"], position=r["position"], action=r["action"], source=r["source"],
                                destination=r["destination"], protocol=r["protocol"], port=r["port"],
                                description=r.get("description", ""), origin=r.get("origin", "baseline"), lease_id=r.get("lease_id"),
                                policy_id=r.get("policy_id"), enabled=r.get("enabled", True), created_at=self.ctx.clock.now(),
                                created_by=r.get("created_by", "nexus")))
        db.flush()

"""Firewall adapter interface. The core engine only talks to this interface (ADR-004)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any

from sqlalchemy.orm import Session


class FirewallUnavailable(RuntimeError):
    """The firewall management API cannot be reached. Callers must report PENDING, never SUCCESS."""


@dataclass
class RuleSpec:
    action: str
    source: str
    destination: str
    protocol: str
    port: str
    description: str = ""
    origin: str = "policy"
    lease_id: str | None = None
    policy_id: str | None = None
    position: int = 500
    rule_id: str | None = None
    created_by: str = "nexus"

    def key(self) -> tuple[str, str, str, str, str]:
        return (self.action.upper(), self.source, self.destination, self.protocol.upper(), str(self.port).upper())

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def rule_key(rule: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (rule["action"].upper(), rule["source"], rule["destination"], rule["protocol"].upper(), str(rule["port"]).upper())


class FirewallAdapter(ABC):
    name: str = "abstract"
    mode: str = "SIMULATION"

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def create_rule(self, db: Session, spec: RuleSpec) -> str: ...

    @abstractmethod
    def delete_rule(self, db: Session, rule_id: str) -> None: ...

    @abstractmethod
    def list_rules(self, db: Session) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_state(self, db: Session) -> dict[str, Any]: ...

    @abstractmethod
    def rollback(self, db: Session, backup: list[dict[str, Any]]) -> None: ...

    def verify_rule(self, db: Session, spec: RuleSpec, present: bool = True) -> bool:
        keys = {rule_key(r) for r in self.list_rules(db) if r.get("enabled", True)}
        return (spec.key() in keys) == present

    def apply_policy(self, db: Session, desired: list[RuleSpec]) -> dict[str, list[str]]:
        """Make the ruleset equal to `desired`: remove rules not desired, add missing ones."""
        actual = self.list_rules(db)
        desired_keys = {s.key(): s for s in desired}
        actual_keys = {rule_key(r): r for r in actual}
        removed = [r["id"] for k, r in actual_keys.items() if k not in desired_keys]
        for rule_id in removed:
            self.delete_rule(db, rule_id)
        added = [self.create_rule(db, s) for k, s in desired_keys.items() if k not in actual_keys]
        return {"added": added, "removed": removed}

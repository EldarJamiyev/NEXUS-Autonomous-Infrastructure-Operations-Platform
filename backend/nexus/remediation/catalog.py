"""Loads and validates the remediation catalog (remediation/catalog.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

CATEGORY_RANK = {"SAFE": 0, "REVERSIBLE": 1, "HIGH_IMPACT": 2, "CRITICAL": 3}


class Action(BaseModel):
    id: str
    name: str
    description: str
    category: Literal["SAFE", "REVERSIBLE", "HIGH_IMPACT", "CRITICAL"]
    risk: Literal["LOW", "MEDIUM", "HIGH"]
    permission: Literal["VIEWER", "OPERATOR", "ENGINEER", "ADMIN"]
    base_confidence: int = Field(ge=0, le=100)
    manual_only: bool = False
    preconditions: list[dict[str, Any]] = []
    backup: Literal["none", "config", "firewall", "network_state", "service_state"] = "none"
    backup_component: str | None = None
    execution: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    rollback: Literal["not_required", "restore_backup", "firewall_restore", "network_restore"] = "not_required"
    timeout: int = 60

    @property
    def rollback_available(self) -> bool:
        return self.rollback != "not_required"


def substitute(spec: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in spec.items():
        if isinstance(v, str) and v.startswith("$"):
            out[k] = params.get(v[1:])
        else:
            out[k] = v
    return out


class Catalog:
    def __init__(self, path: Path | None = None) -> None:
        path = path or Path(__file__).with_name("catalog.yaml")
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.actions: dict[str, Action] = {a["id"]: Action.model_validate(a) for a in raw["actions"]}

    def get(self, action_id: str) -> Action:
        if action_id not in self.actions:
            raise KeyError(f"action {action_id} is not in the remediation catalog")
        return self.actions[action_id]

    def as_list(self) -> list[dict[str, Any]]:
        return [a.model_dump() | {"rollback_available": a.rollback_available} for a in self.actions.values()]

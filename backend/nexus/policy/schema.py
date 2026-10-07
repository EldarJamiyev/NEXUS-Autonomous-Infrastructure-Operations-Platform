"""Policy-as-code schemas. Unknown keys are rejected so typos fail validation instead of silently passing."""

from __future__ import annotations

import re
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
DAYS = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Metadata(Strict):
    id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9-]{2,63}$")
    name: str
    owner: str = ""
    description: str = ""


class Grant(Strict):
    destinations: list[str]
    protocol: Literal["TCP", "UDP", "ANY"] = "TCP"
    ports: list[int]
    lease_minutes: int = Field(30, ge=1, le=1440)
    max_lease_minutes: int | None = Field(None, ge=1, le=1440)
    approval: Literal["never", "always"] = "never"


class Deny(Strict):
    destinations: list[str]
    protocol: Literal["TCP", "UDP", "ANY"] = "TCP"
    ports: list[int]
    reason: str = ""


class Window(Strict):
    days: list[str]
    start: str
    end: str

    @field_validator("days")
    @classmethod
    def _days(cls, v: list[str]) -> list[str]:
        bad = [d for d in v if d.lower() not in DAYS]
        if bad:
            raise ValueError(f"unknown day(s): {bad}")
        return [d.lower() for d in v]

    @field_validator("start", "end")
    @classmethod
    def _hhmm(cls, v: str) -> str:
        if not HHMM.match(v):
            raise ValueError(f"time must be HH:MM, got {v!r}")
        return v


class Schedule(Strict):
    windows: list[Window] = []
    outside: Literal["approval_required", "deny"] = "approval_required"


class Conditions(Strict):
    min_identity_confidence: int = Field(80, ge=0, le=100)
    max_device_risk: int = Field(50, ge=0, le=100)
    max_user_risk: int = Field(60, ge=0, le=100)
    source_vlans: list[int] = []
    device_kinds: list[str] = []


class Subjects(Strict):
    groups: list[str]


class AccessSpec(Strict):
    subjects: Subjects
    conditions: Conditions = Conditions()
    grants: list[Grant] = []
    denies: list[Deny] = []
    schedule: Schedule | None = None


class FirewallRuleDef(Strict):
    id: str
    action: Literal["ALLOW", "DENY"]
    source: str
    destination: str
    protocol: Literal["TCP", "UDP", "ANY"]
    port: str | int
    description: str = ""


class FirewallSpec(Strict):
    aliases: dict[str, list[str]] = {}
    rules: list[FirewallRuleDef]
    positions: dict[str, int] = {}
    management_path: dict[str, Any] = {}


class QuarantineSpec(Strict):
    identity_levels: list[str] = ["UNKNOWN"]
    min_risk: int = 80
    device_kinds: list[str] = ["unknown", "workstation"]
    target_vlan: int = 99
    automatic_min_autonomy: int = 3
    managed_requires_level: int = 5
    protected_devices: list[str] = []


class SecuritySpec(Strict):
    quarantine: QuarantineSpec


class Doc(Strict):
    apiVersion: str = "nexus.omnis/v1"
    metadata: Metadata


class AccessPolicyDoc(Doc):
    kind: Literal["AccessPolicy"]
    spec: AccessSpec


class FirewallPolicyDoc(Doc):
    kind: Literal["FirewallPolicy"]
    spec: FirewallSpec


class SecurityPolicyDoc(Doc):
    kind: Literal["SecurityPolicy"]
    spec: SecuritySpec


class GenericDoc(Doc):
    kind: Literal["BaselinePolicy", "AutomationPolicy", "IdentitySignals", "RiskRules"]
    spec: dict[str, Any]


KIND_MODELS: dict[str, type[Doc]] = {"AccessPolicy": AccessPolicyDoc, "FirewallPolicy": FirewallPolicyDoc,
                                     "SecurityPolicy": SecurityPolicyDoc, "BaselinePolicy": GenericDoc,
                                     "AutomationPolicy": GenericDoc, "IdentitySignals": GenericDoc, "RiskRules": GenericDoc}


class PolicyValidationError(ValueError):
    def __init__(self, messages: list[str]) -> None:
        super().__init__("; ".join(messages))
        self.messages = messages


def parse_policy(text: str) -> Doc:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyValidationError([f"YAML syntax error: {exc}"]) from exc
    if not isinstance(raw, dict):
        raise PolicyValidationError(["document must be a mapping"])
    kind = raw.get("kind")
    model = KIND_MODELS.get(str(kind))
    if model is None:
        raise PolicyValidationError([f"unknown kind {kind!r}; expected one of {sorted(KIND_MODELS)}"])
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise PolicyValidationError([f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]) from exc

"""Active policy set: built from ACTIVE policy versions in the database (Git files are the source)."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.util import sha256_of
from nexus.models import Policy, PolicyVersion
from nexus.policy.schema import (
    AccessPolicyDoc,
    Doc,
    FirewallPolicyDoc,
    GenericDoc,
    PolicyValidationError,
    SecurityPolicyDoc,
    parse_policy,
)

if TYPE_CHECKING:
    from nexus.core.context import Context


def deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@dataclass
class PolicyCache:
    docs: dict[str, Doc] = field(default_factory=dict)
    access: list[AccessPolicyDoc] = field(default_factory=list)
    firewall: FirewallPolicyDoc | None = None
    security: list[SecurityPolicyDoc] = field(default_factory=list)
    generic: dict[str, GenericDoc] = field(default_factory=dict)
    identity_signals: dict[str, Any] = field(default_factory=dict)
    risk_rules: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def spec(self, policy_id: str) -> dict[str, Any]:
        doc = self.generic.get(policy_id)
        return dict(doc.spec) if doc else {}

    @property
    def automation(self) -> dict[str, Any]:
        return self.spec("POL-AUTOMATION")

    @property
    def server_baseline(self) -> dict[str, Any]:
        return self.spec("POL-SERVER-BASELINE")

    @property
    def thresholds(self) -> dict[str, Any]:
        defaults = {"disk_critical_percent": 90, "disk_recover_percent": 85, "cpu_critical_percent": 92, "cert_warning_days": 14,
                    "ntp_max_skew_seconds": 300, "dhcp_pool_critical_percent": 95, "auth_failure_burst": 3}
        return {**defaults, **self.spec("POL-MONITORING-BASELINE").get("thresholds", {})}


def build_cache(db: Session, overrides: dict[str, str] | None = None) -> PolicyCache:
    from nexus.risk.engine import DEFAULT_RULES

    cache = PolicyCache()
    contents: dict[str, str] = {}
    for policy in db.scalars(select(Policy).where(Policy.status == "ACTIVE")):
        ver = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == policy.id, PolicyVersion.version == policy.active_version))
        if ver:
            contents[policy.id] = ver.content
    for pid, text in (overrides or {}).items():
        contents[pid] = text
    for pid, text in contents.items():
        try:
            doc = parse_policy(text)
        except PolicyValidationError as exc:
            cache.errors.append(f"{pid}: {exc}")
            continue
        cache.docs[doc.metadata.id] = doc
        if isinstance(doc, AccessPolicyDoc):
            cache.access.append(doc)
        elif isinstance(doc, FirewallPolicyDoc):
            cache.firewall = doc
        elif isinstance(doc, SecurityPolicyDoc):
            cache.security.append(doc)
        elif isinstance(doc, GenericDoc):
            cache.generic[doc.metadata.id] = doc
            if doc.kind == "IdentitySignals":
                cache.identity_signals = dict(doc.spec)
            elif doc.kind == "RiskRules":
                cache.risk_rules = deep_merge(DEFAULT_RULES, doc.spec)
    cache.access.sort(key=lambda d: d.metadata.id)
    if not cache.risk_rules:
        cache.risk_rules = copy.deepcopy(DEFAULT_RULES)
    return cache


def refresh(ctx: Context, db: Session) -> PolicyCache:
    ctx.policy_cache = build_cache(db)
    return ctx.policy_cache


def policy_files(ctx: Context) -> dict[str, tuple[Path, str]]:
    """Map policy id -> (path, text) for every YAML file under policies/."""
    out: dict[str, tuple[Path, str]] = {}
    for path in sorted((ctx.settings.config_root / "policies").glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        try:
            pid = parse_policy(text).metadata.id
        except PolicyValidationError:
            pid = path.stem.upper()
        out[pid] = (path, text)
    return out


def sync_from_disk(ctx: Context, db: Session, author: str = "git", activate: bool = True) -> list[dict[str, Any]]:
    """Import new/changed policy files as new versions (and activate them if they validate)."""
    changes = []
    for pid, (path, text) in policy_files(ctx).items():
        checksum = sha256_of(text)
        policy = db.get(Policy, pid)
        try:
            doc = parse_policy(text)
            valid, error = True, ""
        except PolicyValidationError as exc:
            doc, valid, error = None, False, str(exc)
        if policy is None:
            policy = Policy(id=pid, name=doc.metadata.name if doc else pid, kind=doc.kind if doc else "Invalid",  # type: ignore[attr-defined]
                            description=doc.metadata.description if doc else error, status="ACTIVE",
                            file_path=str(path.relative_to(ctx.settings.config_root)), active_version=None)
            db.add(policy)
            db.flush()
        latest = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == pid).order_by(PolicyVersion.version.desc()))
        if latest and latest.checksum == checksum:
            continue
        version = (latest.version + 1) if latest else 1
        status = "ACTIVE" if (valid and activate) else ("REJECTED" if not valid else "DRAFT")
        if status == "ACTIVE":
            for v in db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == pid, PolicyVersion.status == "ACTIVE")):
                v.status = "SUPERSEDED"
            policy.active_version = version
            if doc:
                policy.name = doc.metadata.name
                policy.description = doc.metadata.description
        db.add(PolicyVersion(policy_id=pid, version=version, author=author, created_at=ctx.clock.now(), checksum=checksum,
                             content=text, status=status, note=error or f"imported from {path.name}", source="git"))
        changes.append({"policy": pid, "version": version, "status": status, "checksum": checksum, "error": error})
    db.flush()
    return changes

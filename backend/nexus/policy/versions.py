"""Policy version control: diff, activate, deactivate, rollback (with SHA-256 checksums)."""

from __future__ import annotations

import difflib
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.audit import record_audit
from nexus.models import Policy, PolicyVersion
from nexus.policy.cache import policy_files, refresh

if TYPE_CHECKING:
    from nexus.core.context import Context


def version_dict(v: PolicyVersion) -> dict[str, Any]:
    return {"policy_id": v.policy_id, "version": v.version, "author": v.author, "created_at": v.created_at.isoformat(),
            "checksum": v.checksum, "status": v.status, "note": v.note, "source": v.source}


def unified(a: str, b: str, a_name: str, b_name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile=a_name, tofile=b_name))


def diff_versions(db: Session, policy_id: str, a: int, b: int) -> str:
    va = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == policy_id, PolicyVersion.version == a))
    vb = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == policy_id, PolicyVersion.version == b))
    if not va or not vb:
        raise KeyError("version not found")
    return unified(va.content, vb.content, f"{policy_id}@v{a}", f"{policy_id}@v{b}")


def diff_against_disk(ctx: Context, db: Session) -> list[dict[str, Any]]:
    out = []
    files = policy_files(ctx)
    for pid, (path, text) in files.items():
        policy = db.get(Policy, pid)
        active = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == pid, PolicyVersion.version == (policy.active_version if policy else -1)))
        if active is None:
            out.append({"policy": pid, "status": "NEW", "diff": unified("", text, "/dev/null", path.name)})
        elif active.content != text:
            out.append({"policy": pid, "status": "CHANGED", "diff": unified(active.content, text, f"{pid}@v{active.version} (active)", path.name)})
    return out


def activate(ctx: Context, db: Session, policy_id: str, version: int, actor: str, reason: str = "") -> PolicyVersion:
    policy = db.get(Policy, policy_id)
    target = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == policy_id, PolicyVersion.version == version))
    if policy is None or target is None:
        raise KeyError("policy or version not found")
    if target.status == "REJECTED":
        raise ValueError("a rejected version cannot be activated")
    for v in db.scalars(select(PolicyVersion).where(PolicyVersion.policy_id == policy_id, PolicyVersion.status == "ACTIVE")):
        v.status = "SUPERSEDED"
    target.status = "ACTIVE"
    policy.active_version = version
    policy.status = "ACTIVE"
    db.flush()
    refresh(ctx, db)
    ctx.bus.emit(db, "POLICY_CHANGED", f"{policy_id} v{version} activated by {actor}", severity="notice", source="policy-engine",
                 data={"policy": policy_id, "version": version, "reason": reason})
    record_audit(ctx, db, actor=actor, actor_type="OPERATOR", action=f"activated policy {policy_id} v{version}", reason=reason or "policy change",
                 target=policy_id, result="SUCCESS")
    return target


def rollback(ctx: Context, db: Session, policy_id: str, actor: str) -> PolicyVersion:
    policy = db.get(Policy, policy_id)
    if policy is None or not policy.active_version:
        raise KeyError("policy not found")
    previous = db.scalar(select(PolicyVersion).where(PolicyVersion.policy_id == policy_id, PolicyVersion.version < policy.active_version,
                                                     PolicyVersion.status.in_(("SUPERSEDED", "INACTIVE"))).order_by(PolicyVersion.version.desc()))
    if previous is None:
        raise ValueError("no previous version to roll back to")
    return activate(ctx, db, policy_id, previous.version, actor, reason=f"rollback from v{policy.active_version}")


def set_status(ctx: Context, db: Session, policy_id: str, active: bool, actor: str) -> Policy:
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise KeyError("policy not found")
    policy.status = "ACTIVE" if active else "INACTIVE"
    db.flush()
    refresh(ctx, db)
    ctx.bus.emit(db, "POLICY_CHANGED", f"{policy_id} {'activated' if active else 'deactivated'} by {actor}", severity="notice", source="policy-engine",
                 data={"policy": policy_id, "status": policy.status})
    record_audit(ctx, db, actor=actor, actor_type="OPERATOR", action=f"{'activated' if active else 'deactivated'} policy {policy_id}",
                 reason="operator request", target=policy_id, result="SUCCESS")
    return policy

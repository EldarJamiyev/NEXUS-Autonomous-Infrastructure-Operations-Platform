"""Audit trail: WHO did WHAT, WHY, to which TARGET, with what RESULT, under which correlation id."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from nexus.logs import log_event
from nexus.models import AuditEvent

if TYPE_CHECKING:
    from nexus.core.context import Context

log = logging.getLogger("nexus.audit")


def record_audit(ctx: Context, db: Session, *, actor: str, actor_type: str, action: str, reason: str, target: str,
                 result: str, correlation_id: str | None = None, transaction_id: str | None = None,
                 incident_id: str | None = None, severity: str = "info", details: dict[str, Any] | None = None) -> AuditEvent:
    row = AuditEvent(ts=ctx.clock.now(), actor=actor, actor_type=actor_type, action=action, reason=reason[:512],
                     target=target, result=result, correlation_id=correlation_id, transaction_id=transaction_id,
                     incident_id=incident_id, severity=severity, details=details or {})
    db.add(row)
    db.flush()
    log_event(log, "AUDIT", actor=actor, action=action, target=target, result=result,
              correlation_id=correlation_id, transaction_id=transaction_id)
    return row

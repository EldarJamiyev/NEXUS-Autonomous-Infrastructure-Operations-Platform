"""In-process event bus with a transactional outbox.

Events are written to the `events` table inside the caller's transaction and fanned out to
subscribers only after that transaction commits (SQLAlchemy `after_commit`). A rolled-back
transaction therefore never leaks events. Subscriber queues are bounded; a slow consumer loses
its oldest events rather than blocking the control loop.

The `EventBus` protocol is the seam for a Redis Streams/NATS implementation later.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session, sessionmaker

from nexus.events.types import phase_for
from nexus.models import Event

log = logging.getLogger("nexus.events")
Handler = Callable[[dict[str, Any]], None]


class EventBus(Protocol):
    def emit(self, db: Session, type: str, message: str, **kw: Any) -> Event: ...
    def subscribe(self, maxsize: int = 500) -> asyncio.Queue: ...
    def unsubscribe(self, queue: asyncio.Queue) -> None: ...
    def add_handler(self, handler: Handler) -> None: ...


class InProcessEventBus:
    def __init__(self, clock: Any) -> None:
        self.clock = clock
        self._queues: set[asyncio.Queue] = set()
        self._handlers: list[Handler] = []
        self.published = 0
        self.dropped = 0
        self.last_latency_ms = 0.0
        self.latency_observer: Callable[[float], None] | None = None

    def attach(self, factory: sessionmaker[Session]) -> None:
        sa_event.listen(factory, "after_commit", self._after_commit)
        sa_event.listen(factory, "after_soft_rollback", self._after_rollback)

    # -- producer side -------------------------------------------------
    def emit(self, db: Session, type: str, message: str, *, severity: str = "info", source: str = "nexus",
             target: str | None = None, user_id: str | None = None, data: dict[str, Any] | None = None,
             correlation_id: str | None = None) -> Event:
        ev = Event(ts=self.clock.now(), type=type, severity=severity, source=source, target=target, user_id=user_id,
                   message=message[:512], data=data or {}, correlation_id=correlation_id)
        db.add(ev)
        db.flush()
        db.info.setdefault("nexus_pending_events", []).append((time.perf_counter(), serialize_event(ev)))
        return ev

    def _after_commit(self, session: Session) -> None:
        pending = session.info.pop("nexus_pending_events", [])
        for started, payload in pending:
            self._dispatch(payload, started)

    def _after_rollback(self, session: Session, previous_transaction: Any) -> None:
        session.info.pop("nexus_pending_events", None)

    def _dispatch(self, payload: dict[str, Any], started: float) -> None:
        self.published += 1
        for q in list(self._queues):
            try:
                if q.full():
                    q.get_nowait()
                    self.dropped += 1
                q.put_nowait({"kind": "event", "event": payload})
            except Exception:  # noqa: BLE001 - never let a subscriber break the producer
                self.dropped += 1
        for handler in self._handlers:
            try:
                handler(payload)
            except Exception:  # noqa: BLE001
                log.exception("event handler failed", extra={"event": payload.get("type")})
        self.last_latency_ms = (time.perf_counter() - started) * 1000
        if self.latency_observer:
            self.latency_observer(self.last_latency_ms / 1000)

    # -- consumer side -------------------------------------------------
    def subscribe(self, maxsize: int = 500) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._queues.add(q)
        return q

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._queues.discard(queue)

    def broadcast(self, message: dict[str, Any]) -> None:
        """Non-persistent fan-out (metrics ticks, demo state)."""
        for q in list(self._queues):
            if q.full():
                with contextlib.suppress(asyncio.QueueEmpty):
                    q.get_nowait()
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                self.dropped += 1

    def add_handler(self, handler: Handler) -> None:
        self._handlers.append(handler)

    @property
    def subscriber_count(self) -> int:
        return len(self._queues)


def serialize_event(ev: Event) -> dict[str, Any]:
    return {
        "id": ev.id, "ts": ev.ts.isoformat() if ev.ts else None, "type": ev.type, "severity": ev.severity,
        "source": ev.source, "target": ev.target, "user_id": ev.user_id, "message": ev.message, "data": ev.data or {},
        "correlation_id": ev.correlation_id, "phase": phase_for(ev.type),
    }

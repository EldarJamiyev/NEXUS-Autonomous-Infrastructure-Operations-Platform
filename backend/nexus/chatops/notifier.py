"""ChatOps notifications (Discord / Slack incoming webhooks).

Every notification is recorded in chatops_events. Without CHATOPS_WEBHOOK_URL the record is
marked DRY_RUN - NEXUS never claims a message was delivered when it was not.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import httpx
from sqlalchemy.orm import Session

from nexus.models import ChatOpsEvent

if TYPE_CHECKING:
    from nexus.core.context import Context

log = logging.getLogger("nexus.chatops")


def format_body(title: str, fields: dict[str, Any]) -> str:
    width = max((len(k) for k in fields), default=0)
    lines = [title, ""] + [f"{k + ':':<{width + 1}} {v}" for k, v in fields.items()]
    return "\n".join(lines)


def provider_payload(provider: str, title: str, body: str) -> dict[str, Any]:
    if provider == "discord":
        return {"username": "NEXUS OMNIS", "content": f"```\n{body}\n```"[:1990]}
    return {"text": f"*{title}*\n```{body}```"}


class ChatOpsNotifier:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    @property
    def provider(self) -> str:
        return self.ctx.settings.chatops_provider

    @property
    def configured(self) -> bool:
        return self.provider != "none" and bool(self.ctx.settings.chatops_webhook_url)

    def record(self, db: Session, kind: str, title: str, fields: dict[str, Any], correlation_id: str | None = None) -> ChatOpsEvent:
        body = format_body(title, fields)
        msg = ChatOpsEvent(ts=self.ctx.clock.now(), provider=self.provider if self.configured else "none", kind=kind, title=title, body=body,
                           fields={k: str(v) for k, v in fields.items()}, delivery_status="QUEUED" if self.configured else "DRY_RUN",
                           error=None if self.configured else "no webhook configured (set CHATOPS_PROVIDER and CHATOPS_WEBHOOK_URL)",
                           correlation_id=correlation_id)
        db.add(msg)
        db.flush()
        self.ctx.bus.emit(db, "CHATOPS_SENT", f"{title} -> {msg.provider} ({msg.delivery_status})", source="chatops",
                          data={"chatops_id": msg.id, "kind": kind, "status": msg.delivery_status}, correlation_id=correlation_id)
        if self.configured:
            self._schedule(msg.id, title, body)
        return msg

    def _schedule(self, msg_id: int, title: str, body: str) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.call_soon(lambda: loop.create_task(self._deliver(msg_id, title, body)))

    async def _deliver(self, msg_id: int, title: str, body: str) -> None:
        status, error = "SENT", None
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(str(self.ctx.settings.chatops_webhook_url), json=provider_payload(self.provider, title, body))
                if resp.status_code >= 300:
                    status, error = "FAILED", f"HTTP {resp.status_code}: {resp.text[:200]}"
        except httpx.HTTPError as exc:
            status, error = "FAILED", str(exc)[:300]
        with self.ctx.session() as db:
            msg = db.get(ChatOpsEvent, msg_id)
            if msg:
                msg.delivery_status, msg.error = status, error
        if status != "SENT":
            log.warning("chatops delivery failed", extra={"event": "CHATOPS_FAILED", "error": error})

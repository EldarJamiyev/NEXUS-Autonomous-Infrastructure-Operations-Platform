"""WebSocket live channel: every committed event, metric ticks and demo state."""

from __future__ import annotations

import asyncio
import contextlib

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from nexus import __version__
from nexus.api.deps import resolve

router = APIRouter()


@router.websocket("/ws")
async def live(websocket: WebSocket) -> None:
    ctx = websocket.app.state.ctx
    principal = resolve(ctx, websocket.query_params.get("token"))
    if principal is None:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    queue = ctx.bus.subscribe(1000)
    try:
        await websocket.send_json({"kind": "hello", "version": __version__, "environment": ctx.environment_label, "principal": principal.model_dump(),
                                   "demo": ctx.controlplane.demo.snapshot() if ctx.controlplane else None})
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=20)
            except TimeoutError:
                message = {"kind": "ping"}
            await websocket.send_json(message)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        ctx.bus.unsubscribe(queue)
        with contextlib.suppress(Exception):
            await websocket.close()

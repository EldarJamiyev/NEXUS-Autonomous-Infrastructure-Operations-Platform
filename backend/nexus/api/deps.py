"""API security: signed console tokens or API keys, role-based authorization enforced on the
server (not by hiding buttons), and a sliding-window rate limiter for sensitive endpoints."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from nexus.core.context import Context
from nexus.models import User

ROLE_RANK = {"VIEWER": 0, "OPERATOR": 1, "ENGINEER": 2, "ADMIN": 3}


class Principal(BaseModel):
    user_id: str
    name: str
    role: str
    method: str


class TokenSigner:
    def __init__(self, secret: str) -> None:
        self.key = secret.encode()

    def _b64(self, raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    def sign(self, payload: dict[str, Any], ttl: int = 12 * 3600) -> str:
        body = self._b64(json.dumps({**payload, "exp": int(time.time()) + ttl}, separators=(",", ":")).encode())
        return (body + b"." + self._b64(hmac.new(self.key, body, hashlib.sha256).digest())).decode()

    def verify(self, token: str) -> dict[str, Any] | None:
        try:
            body, sig = token.encode().split(b".", 1)
            if not hmac.compare_digest(sig, self._b64(hmac.new(self.key, body, hashlib.sha256).digest())):
                return None
            data = json.loads(base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4)))
        except (ValueError, json.JSONDecodeError):
            return None
        return data if data.get("exp", 0) > time.time() else None


class RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self.hits: dict[tuple[str, str], deque] = defaultdict(deque)

    def check(self, key: tuple[str, str]) -> float | None:
        now = time.time()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return 60 - (now - q[0])
        q.append(now)
        return None


def get_ctx(request: Request) -> Context:
    return request.app.state.ctx


def resolve(ctx: Context, token: str | None) -> Principal | None:
    if not token:
        return None
    body = ctx.signer.verify(token)  # type: ignore[attr-defined]
    if body:
        with ctx.session() as db:
            user = db.get(User, body.get("sub", ""))
            if user and user.enabled:
                return Principal(user_id=user.id, name=user.display_name, role=user.console_role, method="console-token")
        return None
    for entry in [e for e in ctx.settings.api_keys.split(",") if ":" in e]:
        role, key = entry.split(":", 1)
        if key and hmac.compare_digest(key.strip(), token) and role.strip().upper() in ROLE_RANK:
            return Principal(user_id=f"api-{role.strip().lower()}", name=f"API key ({role.strip().upper()})", role=role.strip().upper(), method="api-key")
    return None


async def current_principal(request: Request) -> Principal:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    principal = resolve(request.app.state.ctx, token)
    if principal is None:
        raise HTTPException(status_code=401, detail="authentication required", headers={"WWW-Authenticate": "Bearer"})
    return principal


def require(role: str):  # noqa: ANN201
    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if ROLE_RANK.get(principal.role, -1) < ROLE_RANK[role]:
            raise HTTPException(status_code=403, detail=f"requires {role} role (you are {principal.role})")
        return principal
    return dependency


def limited(bucket: str):  # noqa: ANN201
    async def dependency(request: Request) -> None:
        ctx: Context = request.app.state.ctx
        client = request.client.host if request.client else "unknown"
        retry = ctx.limiter.check((client, bucket))  # type: ignore[attr-defined]
        if retry is not None:
            raise HTTPException(status_code=429, detail=f"rate limit exceeded for {bucket}", headers={"Retry-After": str(int(retry) + 1)})
    return dependency

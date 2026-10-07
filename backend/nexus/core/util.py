"""Small shared helpers: checksums, canonical JSON, time formatting."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_of(value: Any) -> str:
    data = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(data.encode()).hexdigest()


def stable_hash(text: str) -> int:
    return int(hashlib.sha1(text.encode()).hexdigest()[:8], 16)  # noqa: S324 - non-cryptographic jitter


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def hhmmss(dt: datetime | None, tz: Any = None) -> str:
    if not dt:
        return "-"
    return (dt.astimezone(tz) if tz else dt).strftime("%H:%M:%S")


def clamp(value: float, low: float = 0, high: float = 100) -> float:
    return max(low, min(high, value))


def seconds_between(a: datetime | None, b: datetime | None) -> float | None:
    if not a or not b:
        return None
    return round((b - a).total_seconds(), 2)

"""Simulation-aware clock.

All engines read time from here so the demo can accelerate time (temporal access policies,
lease expiry) and seed history on a shifted clock. In real-lab mode it is wall-clock UTC.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo


class SimClock:
    def __init__(self, site_timezone: str = "UTC") -> None:
        self.site_tz = ZoneInfo(site_timezone)
        self.reset()

    def reset(self) -> None:
        self._anchor_real = time.time()
        self._anchor_sim = self._anchor_real
        self.acceleration = 1.0

    def now(self) -> datetime:
        real = time.time()
        sim = self._anchor_sim + (real - self._anchor_real) * self.acceleration
        return datetime.fromtimestamp(sim, tz=UTC)

    def site_now(self) -> datetime:
        return self.now().astimezone(self.site_tz)

    def set_time(self, when: datetime) -> None:
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        self._anchor_real = time.time()
        self._anchor_sim = when.timestamp()

    def shift(self, delta: timedelta) -> None:
        self.set_time(self.now() + delta)

    def set_acceleration(self, factor: float) -> None:
        current = self.now()
        self.acceleration = max(0.1, min(float(factor), 3600.0))
        self.set_time(current)

    @property
    def offset_seconds(self) -> float:
        return (self.now() - datetime.now(tz=UTC)).total_seconds()

    @property
    def is_wall_clock(self) -> bool:
        return self.acceleration == 1.0 and abs(self.offset_seconds) < 2

    def describe(self) -> dict:
        return {
            "now": self.now().isoformat(),
            "site_time": self.site_now().strftime("%Y-%m-%d %H:%M:%S"),
            "site_timezone": str(self.site_tz),
            "acceleration": self.acceleration,
            "offset_seconds": round(self.offset_seconds, 1),
            "wall_clock": self.is_wall_clock,
        }

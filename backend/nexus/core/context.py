"""Dependency container shared by every engine (settings, DB, bus, clock, adapters, runtime state)."""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from nexus.clock import SimClock
from nexus.config import Settings
from nexus.database.session import session_scope
from nexus.events.bus import InProcessEventBus

if TYPE_CHECKING:
    from nexus.chatops.notifier import ChatOpsNotifier
    from nexus.firewall.base import FirewallAdapter
    from nexus.identity.adapter import IdentityProvider
    from nexus.monitoring.metrics import Metrics
    from nexus.remediation.catalog import Catalog
    from nexus.remediation.executor import CommandExecutor
    from nexus.remediation.verification import Probes
    from nexus.simulation.world import World


@dataclass
class Runtime:
    """Volatile in-memory state. Anything an operator must be able to audit lives in the database."""

    started_at: float = field(default_factory=time.time)
    inflight: set[tuple[str, str]] = field(default_factory=set)
    metric_history: dict[str, deque] = field(default_factory=dict)
    network_history: deque = field(default_factory=lambda: deque(maxlen=180))
    last_tick: float = 0.0
    last_detection: float = 0.0
    last_reconcile: float = 0.0
    reconcile_count: int = 0
    detection_count: int = 0
    firewall_available: bool = True
    firewall_reconnect_at: float | None = None
    db_degraded_until: float | None = None
    recovery_until: float | None = None
    blackout_running: bool = False
    pending_reconcile: set[str] = field(default_factory=set)
    snapshot_dirty: bool = False
    last_snapshot: float = 0.0
    sync_queue: list[str] = field(default_factory=list)
    recent_remediations: deque = field(default_factory=lambda: deque(maxlen=200))
    demo: Any = None


class Context:
    def __init__(self, settings: Settings, engine: Engine, factory: sessionmaker[Session], bus: InProcessEventBus,
                 clock: SimClock) -> None:
        self.settings = settings
        self.engine = engine
        self.factory = factory
        self.bus = bus
        self.clock = clock
        self.runtime = Runtime()
        self.live = False  # True while the async control plane is running
        self.controlplane: Any = None
        self.firewall: FirewallAdapter
        self.identity: IdentityProvider
        self.executor: CommandExecutor
        self.probes: Probes
        self.chatops: ChatOpsNotifier
        self.metrics: Metrics
        self.catalog: Catalog
        self.world: World
        self.policy_cache: Any = None

    @contextmanager
    def session(self) -> Iterator[Session]:
        with session_scope(self.factory) as db:
            yield db

    @property
    def environment_label(self) -> str:
        return "SIMULATION" if self.settings.is_simulation else "REAL LAB"

    def step_delay(self) -> float:
        return max(0, self.settings.step_delay_ms) / 1000.0

    def dispatch(self, tx_ids: list[str]) -> None:
        """Hand planned transactions to the async control plane, or queue them for a sync driver."""
        if not tx_ids:
            return
        if self.live and self.controlplane is not None:
            for tx_id in tx_ids:
                self.controlplane.schedule_transaction(tx_id)
        else:
            self.runtime.sync_queue.extend(tx_ids)

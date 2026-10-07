"""Async control plane: detection, reconciliation, simulation tick and snapshot loops, plus the
scheduler for remediation transactions, chaos runs, the blackout drill and the guided demo.

Single-writer rule: all loops run on one asyncio event loop, each unit of work is a short
synchronous DB transaction, and nothing awaits while holding a session.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from nexus.models import ChaosRun, Incident, RemediationTransaction

if TYPE_CHECKING:
    from nexus.core.context import Context

log = logging.getLogger("nexus.controlplane")
STATEFUL = {"INCIDENT_CREATED", "INCIDENT_RESOLVED", "INCIDENT_MITIGATED", "QUARANTINE_STARTED", "QUARANTINE_RELEASED", "LEASE_CREATED",
            "LEASE_EXPIRED", "LEASE_REVOKED", "DRIFT_DETECTED", "DRIFT_REMEDIATED", "REMEDIATION_COMPLETED", "REMEDIATION_FAILED",
            "FIREWALL_UPDATED", "FIREWALL_CHANGE", "SYSTEM_MODE_CHANGED", "DEVICE_DISCOVERED", "USER_LOGIN", "USER_LOGOUT", "POLICY_CHANGED",
            "RISK_CHANGED", "FAILURE_INJECTED"}


class ControlPlane:
    def __init__(self, ctx: Context) -> None:
        from nexus.simulation.demo import DemoRunner

        self.ctx = ctx
        self.tasks: set[asyncio.Task] = set()
        self.loops: list[asyncio.Task] = []
        self.demo = DemoRunner(ctx)
        self.reconcile_cycles = 0
        ctx.controlplane = self
        ctx.runtime.demo = self.demo
        ctx.bus.add_handler(self._on_event)

    def _on_event(self, ev: dict[str, Any]) -> None:
        if ev.get("type") in STATEFUL:
            self.ctx.runtime.snapshot_dirty = True

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self.ctx.live = True
        s = self.ctx.settings
        with self.ctx.session() as db:
            stuck = db.scalars(select(RemediationTransaction).where(RemediationTransaction.status.in_(("PLANNED", "RUNNING")))).all()
            for tx in stuck:  # crash recovery: never silently resume a half-applied change
                if tx.status == "RUNNING":
                    tx.status, tx.result, tx.human_action, tx.error = "FAILED", "FAILED", "REQUIRED", "controller restarted mid-transaction; verify manually"
        for tx in [t for t in stuck if t.status == "PLANNED"]:
            self.schedule_transaction(tx.id)
        if s.background_tasks:
            self.loops = [
                asyncio.create_task(self._loop("tick", lambda: s.sim_tick_interval, self.tick_once)),
                asyncio.create_task(self._loop("detect", lambda: s.detection_interval, self.detect_once)),
                asyncio.create_task(self._loop("reconcile", lambda: 1.0, self.reconcile_tick)),
                asyncio.create_task(self._loop("snapshot", lambda: 3.0, self.snapshot_once)),
            ]
        log.info("control plane started", extra={"event": "CONTROLLER_STARTED", "background": s.background_tasks})

    async def stop(self) -> None:
        self.demo.stop()
        for t in self.loops + list(self.tasks):
            t.cancel()
        await asyncio.gather(*self.loops, *self.tasks, return_exceptions=True)
        self.ctx.live = False

    def spawn(self, coro: Coroutine[Any, Any, Any], name: str) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(coro, name=name)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def schedule_transaction(self, tx_id: str) -> None:
        from nexus.remediation.runner import run_async

        loop = asyncio.get_running_loop()
        loop.call_soon(lambda: self.spawn(run_async(self.ctx, tx_id), f"tx-{tx_id}"))

    async def _loop(self, name: str, interval: Callable[[], float], fn: Callable[[], Any]) -> None:
        while True:
            try:
                fn()
            except Exception:  # noqa: BLE001 - a failing pass must not kill the loop
                log.exception("control loop pass failed", extra={"event": "LOOP_ERROR", "loop": name})
            await asyncio.sleep(max(0.2, interval()))

    # ---------------------------------------------------------------------- passes
    def tick_once(self) -> None:
        with self.ctx.session() as db:
            metrics = self.ctx.world.tick(db)
        self.ctx.runtime.last_tick = time.time()
        self.ctx.bus.broadcast({"kind": "metrics", "ts": self.ctx.clock.now().isoformat(), "devices": metrics})

    def detect_once(self) -> None:
        from nexus.core.modes import evaluate_mode
        from nexus.monitoring.detector import scan

        with self.ctx.session() as db:
            scan(self.ctx, db)
        with self.ctx.session() as db:
            evaluate_mode(self.ctx, db)
        self.ctx.runtime.last_detection = time.time()

    def reconcile_tick(self) -> None:
        rt = self.ctx.runtime
        now = time.time()
        if rt.firewall_reconnect_at and now >= rt.firewall_reconnect_at:
            rt.firewall_available, rt.firewall_reconnect_at = True, None
            with self.ctx.session() as db:
                self.ctx.bus.emit(db, "FIREWALL_RECONCILIATION", "pfSense API reachable again - replaying pending changes", severity="notice", source="controller", target="PFSENSE")
            rt.pending_reconcile.add("PFSENSE")
        if rt.db_degraded_until and now >= rt.db_degraded_until:
            rt.db_degraded_until = None
        if now - rt.last_reconcile >= self.ctx.settings.reconcile_interval:
            self.reconcile_once(None)
        elif rt.pending_reconcile:
            targets = set(rt.pending_reconcile)
            rt.pending_reconcile.clear()
            self.reconcile_once(targets)

    def reconcile_once(self, devices: set[str] | None) -> dict[str, Any]:
        from nexus.drift.engine import scan as drift_scan
        from nexus.leases.engine import apply_pending, expire_leases
        from nexus.risk.engine import recompute_all

        with self.ctx.session() as db:
            expired = expire_leases(self.ctx, db)
            applied = apply_pending(self.ctx, db)
            result = drift_scan(self.ctx, db, devices)
        if devices is None:
            self.reconcile_cycles += 1
            self.ctx.runtime.reconcile_count += 1
            self.ctx.runtime.last_reconcile = time.time()
            with self.ctx.session() as db:
                recompute_all(self.ctx, db)
                changed = bool(expired or applied or result["new"] or result["cleared"])
                if changed or self.reconcile_cycles % 6 == 1:
                    self.ctx.bus.emit(db, "RECONCILIATION_COMPLETED", f"Reconciliation #{self.ctx.runtime.reconcile_count}: {len(result['new'])} new drift, "
                                      f"{len(result['cleared'])} cleared, {len(expired)} lease(s) expired, {applied} pending change(s) applied",
                                      source="reconciler", data={**result, "expired": expired, "applied": applied})
        return {"expired": expired, "applied": applied, **result}

    def snapshot_once(self) -> None:
        from nexus.timemachine.snapshots import create_snapshot

        rt = self.ctx.runtime
        periodic = time.time() - rt.last_snapshot >= self.ctx.settings.snapshot_interval
        if rt.snapshot_dirty or periodic:
            with self.ctx.session() as db:
                create_snapshot(self.ctx, db, "state change" if rt.snapshot_dirty else "periodic")

    # ------------------------------------------------------------------------ chaos
    def start_chaos_sync(self, db: Any, scenario: str, actor: str) -> ChaosRun:
        from nexus.chaos.scenarios import run_followup, start

        run, sc = start(self.ctx, db, scenario, actor)
        if self.ctx.live:
            for delay, fn in sc.followups:
                self.spawn(self._followup(run.id, delay, fn), f"chaos-{run.id}")
        else:
            for _delay, fn in sc.followups:
                run_followup(self.ctx, db, run.id, fn)
        return run

    async def _followup(self, run_id: str, delay: float, fn: Any) -> None:
        from nexus.chaos.scenarios import run_followup

        await asyncio.sleep(delay)
        with self.ctx.session() as db:
            run_followup(self.ctx, db, run_id, fn)

    def start_blackout(self, actor: str) -> str:
        from nexus.ids import new_id

        with self.ctx.session() as db:
            parent = ChaosRun(id=new_id(db, "chaos"), scenario="blackout", title="Full infrastructure blackout", status="INJECTING", targets=[],
                              injections=[], requested_by=actor, started_at=self.ctx.clock.now())
            db.add(parent)
            self.ctx.bus.emit(db, "FAILURE_INJECTED", f"Chaos {parent.id}: FULL INFRASTRUCTURE BLACKOUT drill started by {actor}", severity="high",
                              source="chaos-lab", target="NEXUS", data={"run": parent.id, "scenario": "blackout"})
            run_id = parent.id
        self.spawn(self._blackout(run_id, actor), f"blackout-{run_id}")
        return run_id

    async def _blackout(self, run_id: str, actor: str) -> None:
        from nexus.chaos.scenarios import BLACKOUT_SEQUENCE, SCENARIOS
        from nexus.incidents.reports import run_report_markdown, save_report

        rt = self.ctx.runtime
        rt.blackout_running = True
        started = self.ctx.clock.now()
        try:
            for sid in BLACKOUT_SEQUENCE:
                with self.ctx.session() as db:
                    child = self.start_chaos_sync(db, sid, f"blackout {run_id}")
                    parent = db.get(ChaosRun, run_id)
                    if parent:
                        parent.injections = list(parent.injections or []) + [f"{SCENARIOS[sid].title}: {'; '.join(child.injections)}"]
                        parent.targets = sorted(set(parent.targets or []) | set(child.targets))
                await asyncio.sleep(1.2)
            with self.ctx.session() as db:
                parent = db.get(ChaosRun, run_id)
                if parent:
                    parent.status = "OBSERVING"
            deadline = time.time() + 150
            quiet_since = None
            while time.time() < deadline:
                await asyncio.sleep(2)
                with self.ctx.session() as db:
                    busy = db.scalar(select(func.count()).select_from(RemediationTransaction).where(RemediationTransaction.status.in_(("PLANNED", "RUNNING")))) or 0
                    fresh = db.scalar(select(func.count()).select_from(Incident).where(Incident.created_at >= started, Incident.status == "OPEN",
                                                                                     Incident.human_required.is_(False))) or 0
                if busy == 0 and fresh == 0:
                    quiet_since = quiet_since or time.time()
                    if time.time() - quiet_since > 6:
                        break
                else:
                    quiet_since = None
        finally:
            rt.blackout_running = False
        with self.ctx.session() as db:
            md = run_report_markdown(self.ctx, db, "Full infrastructure blackout - final incident report", started,
                                     "Nine faults were injected within about eleven seconds: an unknown device, an unauthorized firewall rule, SSH drift, "
                                     "a DNS outage, a monitoring failure, an unexpected listening port, a DHCP conflict, a policy conflict and an Nginx outage.")
            rep = save_report(self.ctx, db, "blackout", "Full infrastructure blackout - final incident report", md, subject=run_id)
            parent = db.get(ChaosRun, run_id)
            if parent:
                parent.status = "COMPLETED"
                parent.finished_at = self.ctx.clock.now()
                parent.report_id = rep.id
            self.ctx.bus.emit(db, "INCIDENT_UPDATED", f"Blackout drill {run_id} finished - report {rep.id}", severity="notice", source="chaos-lab",
                              data={"run": run_id, "report": rep.id})

    def blackout_started_at(self) -> datetime:
        return datetime.now(tz=UTC)

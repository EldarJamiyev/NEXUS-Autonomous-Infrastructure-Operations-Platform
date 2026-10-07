"""Guided demo: 20 scenes in 8 presentation steps. Every scene acts through the real engines and
waits for the real outcome (with a timeout that is reported honestly if it expires)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from nexus.models import Device, Event, Lease

if TYPE_CHECKING:
    from nexus.core.context import Context

STEPS = ["Infrastructure health", "Identity event", "Access decision", "Service failure", "AutoHeal", "Configuration drift", "Quarantine", "Final incident report"]


@dataclass
class Scene:
    number: int
    step: int
    title: str
    narrative: str
    page: str
    action: Callable[[Any], Any] | None = None
    wait_for: tuple[str, ...] = ()
    target: str | None = None
    hold: float = 3.0


@dataclass
class DemoState:
    status: str = "idle"  # idle|running|paused|finished|failed
    scene: int = 0
    started_at: float | None = None
    log: list[dict[str, Any]] = field(default_factory=list)
    report_id: str | None = None
    skip: bool = False


class DemoRunner:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.state = DemoState()
        self.task: asyncio.Task | None = None
        self.paused = asyncio.Event()
        self.paused.set()
        self.mark: float = 0.0

    def snapshot(self) -> dict[str, Any]:
        scenes = self.scenes()
        cur = scenes[self.state.scene - 1] if 0 < self.state.scene <= len(scenes) else None
        return {"status": self.state.status, "scene": self.state.scene, "total": len(scenes), "steps": STEPS,
                "current": {"number": cur.number, "step": cur.step, "step_title": STEPS[cur.step - 1], "title": cur.title, "narrative": cur.narrative,
                            "page": cur.page} if cur else None,
                "log": self.state.log[-24:], "report_id": self.state.report_id,
                "elapsed": round(time.time() - self.state.started_at, 1) if self.state.started_at else 0}

    def _broadcast(self) -> None:
        self.ctx.bus.broadcast({"kind": "demo", "state": self.snapshot()})

    # ---------------------------------------------------------------- actions
    def _do(self, fn: Callable[..., Any]) -> Callable[[Any], Any]:
        def run(db: Any) -> Any:
            return fn(db)
        return run

    def scenes(self) -> list[Scene]:
        w = self.ctx.world
        return [
            Scene(1, 1, "Healthy infrastructure", "Every device reports in, services run, and the reconciliation loop finds nothing to fix.", "/", hold=4),
            Scene(2, 2, "Eldar logs in", "Event 4624 from DC01: Eldar Jamiyev authenticates on PC-023.", "/identity",
                  action=lambda db: w.logon(db, "eldar", "PC-023"), wait_for=("USER_LOGIN",), target="PC-023"),
            Scene(3, 2, "Identity is correlated", "AD computer object, user session, DHCP hostname, DNS, MAC and VLAN agree: PC-023 is TRUSTED.", "/identity",
                  wait_for=("IDENTITY_CONFIDENCE_CHANGED",), target="PC-023", hold=3),
            Scene(4, 3, "Access lease created", "Eldar asks for SSH to LINUX01. POL-IT-ADMIN, identity and risk are evaluated; a 30-minute lease is issued.", "/access",
                  action=self._request_lease, wait_for=("LEASE_CREATED",), target="PC-023"),
            Scene(5, 3, "Firewall state changes", "The lease becomes a pfSense rule (mock adapter) and the rule is verified present.", "/access",
                  wait_for=("FIREWALL_UPDATED",), hold=3),
            Scene(6, 4, "Nginx failure occurs", "Chaos: the nginx master process on LINUX01 is killed.", "/autoheal",
                  action=self._chaos("kill-nginx"), wait_for=("FAILURE_INJECTED",), target="LINUX01", hold=1.5),
            Scene(7, 5, "AutoHeal detects it", "Monitoring sees the process and TCP/443 down, validates the alert and opens an incident.", "/autoheal",
                  wait_for=("INCIDENT_CREATED",), target="LINUX01"),
            Scene(8, 5, "Nginx is restarted", "SAFE action, automatic: preconditions pass, systemctl restart nginx runs through the allowlist.", "/autoheal",
                  wait_for=("REMEDIATION_STARTED",), target="LINUX01"),
            Scene(9, 5, "Health verification passes", "Success is not the exit code: systemd active, TCP/443 open and HTTP 200 are probed.", "/autoheal",
                  wait_for=("VERIFICATION_PASSED",), target="LINUX01"),
            Scene(10, 5, "ChatOps notification", "An AUTOHEAL EVENT message is recorded (and sent if a webhook is configured).", "/chatops",
                  wait_for=("CHATOPS_SENT",)),
            Scene(11, 6, "SSH configuration drift appears", "Someone sets PermitRootLogin yes on LINUX01. The FIM agent reports the change.", "/drift",
                  action=self._chaos("break-ssh-config"), wait_for=("CONFIG_CHANGED",), target="LINUX01", hold=1.5),
            Scene(12, 6, "NEXUS detects drift", "Actual sshd_config is compared with Git intent: SECURITY drift, checksums differ.", "/drift",
                  wait_for=("DRIFT_DETECTED",), target="LINUX01"),
            Scene(13, 6, "Risk increases", "Security drift raises LINUX01's risk score - every point is explained.", "/risk", wait_for=("RISK_CHANGED",), target="LINUX01"),
            Scene(14, 6, "Automatic remediation", "REVERSIBLE action with 91% confidence: backup, restore baseline, sshd -t, reload.", "/drift",
                  wait_for=("REMEDIATION_STARTED",), target="LINUX01"),
            Scene(15, 6, "Configuration is verified", "Checksum equals Git intent and TCP/22 answers. Rollback stays available.", "/drift",
                  wait_for=("DRIFT_REMEDIATED",), target="LINUX01"),
            Scene(16, 7, "Unknown device appears", "An unidentified laptop is plugged into Gi1/0/14 and starts probing SSH.", "/twin",
                  action=self._chaos("unknown-device"), wait_for=("DEVICE_DISCOVERED",), hold=2),
            Scene(17, 7, "Identity confidence drops", "No AD object, unknown MAC, no DNS record: identity confidence is near zero.", "/identity",
                  wait_for=("IDENTITY_CONFIDENCE_CHANGED",)),
            Scene(18, 7, "Risk becomes critical", "Administrative protocol attempts from an identityless device push risk past 80.", "/risk",
                  wait_for=("RISK_CHANGED",), hold=3),
            Scene(19, 7, "Device is quarantined", "SECURITY-004 permits automatic quarantine of unmanaged endpoints: VLAN 99, verified isolated.", "/twin",
                  wait_for=("QUARANTINE_STARTED",)),
            Scene(20, 8, "Final incident report", "NEXUS writes the run report: what happened, why, what it did, and how each fix was verified.", "/reports",
                  action=self._report, hold=4),
        ]

    def _request_lease(self, db: Any) -> Any:
        from nexus.core.decision import approve
        from nexus.leases.engine import request_access

        out = request_access(self.ctx, db, user_id="eldar", device_id="PC-023", destination="LINUX01", port=22, reason="Guided demo: system administration",
                             duration_minutes=30, requested_by="eldar")
        if out.get("approval_id"):
            approve(self.ctx, db, out["approval_id"], "murad", note="demo: outside business hours, approved by second administrator")
            self.state.log.append({"t": round(time.time() - (self.state.started_at or time.time()), 1), "text": "Outside business hours: approval required, approved by Murad (four-eyes rule)"})
        return out

    def _chaos(self, scenario: str) -> Callable[[Any], Any]:
        def fn(db: Any) -> Any:
            self.ctx.controlplane.start_chaos_sync(db, scenario, "demo")
        return fn

    def _report(self, db: Any) -> Any:
        from datetime import UTC, datetime

        from nexus.incidents.reports import run_report_markdown, save_report

        since = datetime.fromtimestamp(self.state.started_at or time.time(), tz=UTC)
        md = run_report_markdown(self.ctx, db, "NEXUS guided demo - final incident report", since,
                                 "Twenty scenes: identity correlation, access lease, service failure with AutoHeal, configuration drift with verified rollback-capable remediation, and quarantine of an identityless device.")
        rep = save_report(self.ctx, db, "demo", "Guided demo - final incident report", md)
        self.state.report_id = rep.id

    # -------------------------------------------------------------------- run
    def start(self) -> dict[str, Any]:
        if self.task and not self.task.done():
            return self.snapshot()
        self.state = DemoState(status="running", started_at=time.time())
        self.paused.set()
        self.task = asyncio.get_running_loop().create_task(self._run())
        return self.snapshot()

    def pause(self) -> None:
        if self.state.status == "running":
            self.state.status = "paused"
            self.paused.clear()
            self._broadcast()

    def resume(self) -> None:
        if self.state.status == "paused":
            self.state.status = "running"
            self.paused.set()
            self._broadcast()

    def next(self) -> None:
        self.state.skip = True
        self.resume()

    def stop(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
        self.state.status = "idle"
        self._broadcast()

    async def _wait(self, scene: Scene, timeout: float = 25.0) -> bool:
        if not scene.wait_for:
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            await self.paused.wait()
            with self.ctx.session() as db:
                q = select(Event).where(Event.type.in_(scene.wait_for), Event.id > self.mark)
                if scene.target:
                    q = q.where(Event.target == scene.target)
                ev = db.scalar(q.order_by(Event.id))
            if ev is not None:
                self.mark = ev.id
                return True
            if self.state.skip:
                return False
            await asyncio.sleep(0.25)
        return False

    async def _run(self) -> None:
        with self.ctx.session() as db:
            self.mark = db.scalar(select(Event.id).order_by(Event.id.desc())) or 0
            if db.scalar(select(Lease).where(Lease.user_id == "eldar", Lease.status == "ACTIVE", Lease.destination_id == "LINUX01")):
                self.ctx.world.logoff(db, "eldar", "PC-023")
        with self.ctx.session() as db:
            self.mark = db.scalar(select(Event.id).order_by(Event.id.desc())) or 0
        try:
            for scene in self.scenes():
                await self.paused.wait()
                self.state.scene = scene.number
                self.state.skip = False
                self._broadcast()
                if scene.action:
                    with self.ctx.session() as db:
                        scene.action(db)
                        self.ctx.bus.emit(db, "DEMO_SCENE", f"Scene {scene.number:02d}: {scene.title}", source="demo", data={"scene": scene.number})
                ok = await self._wait(scene)
                t = round(time.time() - (self.state.started_at or time.time()), 1)
                self.state.log.append({"t": t, "scene": scene.number, "text": scene.title + ("" if ok else " (not observed within 25 s - shown as-is)"), "ok": ok})
                self._broadcast()
                end = time.time() + scene.hold
                while time.time() < end and not self.state.skip:
                    await self.paused.wait()
                    await asyncio.sleep(0.2)
            self.state.status = "finished"
        except asyncio.CancelledError:
            self.state.status = "idle"
            raise
        except Exception as exc:  # noqa: BLE001
            self.state.status = "failed"
            self.state.log.append({"t": 0, "text": f"demo error: {exc}", "ok": False})
        self._broadcast()


def unknown_device_ids(ctx: Context) -> list[str]:
    with ctx.session() as db:
        return list(db.scalars(select(Device.id).where(Device.kind == "unknown")))

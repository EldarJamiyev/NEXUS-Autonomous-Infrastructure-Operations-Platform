"""Transaction engine: every automated change is a transaction.

DETECTED -> TRIAGED -> POLICY CHECK -> SAFETY CHECK -> BACKUP -> EXECUTION -> VERIFICATION
-> COMMIT | ROLLBACK -> CHATOPS -> AUDIT

Each phase runs in its own short database transaction. The async runner pauses between phases
(NEXUS_STEP_DELAY_MS) so the console can show the progression live; the sync runner is used for
seeding history and in tests. Both execute the same phase functions.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from nexus.core.audit import record_audit
from nexus.core.util import sha256_of
from nexus.ids import new_id
from nexus.logs import log_event
from nexus.models import (
    Alert,
    Approval,
    ConfigItem,
    Decision,
    Device,
    DriftEvent,
    Incident,
    IncidentEvent,
    IpAddress,
    RemediationTransaction,
    Service,
)
from nexus.remediation.catalog import Action, substitute
from nexus.remediation.executor import CommandRejected, render

if TYPE_CHECKING:
    from nexus.core.context import Context

log = logging.getLogger("nexus.remediation")
STEP_NAMES = ["DETECTED", "TRIAGED", "POLICY CHECK", "SAFETY CHECK", "BACKUP", "EXECUTION", "VERIFICATION", "COMMIT", "CHATOPS", "AUDIT"]


def create_transaction(ctx: Context, db: Session, *, action_id: str, target: str, params: dict[str, Any], trigger: str, decision: Decision,
                       incident_id: str | None, drift_id: str | None, correlation_id: str | None, requested_by: str,
                       awaiting: bool) -> RemediationTransaction:
    action = ctx.catalog.get(action_id)
    now = ctx.clock.now()
    detected = now
    if incident_id and (inc := db.get(Incident, incident_id)):
        detected = inc.created_at
    elif drift_id and (drift := db.get(DriftEvent, drift_id)):
        detected = drift.detected_at
    steps = [{"name": n, "status": "pending", "ts": None, "detail": ""} for n in STEP_NAMES]
    steps[0].update(status="done", ts=detected.isoformat(), detail=trigger)
    steps[1].update(status="done", ts=now.isoformat(), detail=f"{decision.id}: {decision.outcome} ({decision.confidence}% confidence)")
    if awaiting:
        steps[2].update(status="waiting", detail="awaiting human approval")
    tx = RemediationTransaction(id=new_id(db, "tx"), action_id=action_id, action_name=action.name, target=target, params=params, trigger=trigger[:128],
                                category=action.category, risk=action.risk, automation_confidence=decision.confidence,
                                status="AWAITING_APPROVAL" if awaiting else "PLANNED", steps=steps, rollback_available=action.rollback_available,
                                rollback_status="AVAILABLE" if action.rollback_available else "NOT_REQUIRED", decision_id=decision.id,
                                incident_id=incident_id, drift_id=drift_id, correlation_id=correlation_id, requested_by=requested_by, created_at=now)
    db.add(tx)
    db.flush()
    ctx.bus.emit(db, "REMEDIATION_PLANNED", f"{tx.id} {action.name} on {target} ({tx.status})", source="autoheal", target=target,
                 data={"transaction": tx.id, "action": action_id, "status": tx.status}, correlation_id=correlation_id)
    return tx


class TransactionRun:
    def __init__(self, ctx: Context, tx_id: str) -> None:
        self.ctx = ctx
        self.tx_id = tx_id
        self.outcome = "PENDING"  # VERIFIED | VERIFY_FAILED | EXEC_FAILED | SKIPPED | REJECTED

    # ------------------------------------------------------------- utilities
    def _load(self, db: Session) -> tuple[RemediationTransaction, Action, Device | None]:
        tx = db.get(RemediationTransaction, self.tx_id)
        if tx is None:
            raise KeyError(self.tx_id)
        return tx, self.ctx.catalog.get(tx.action_id), db.get(Device, tx.target)

    def _step(self, tx: RemediationTransaction, name: str, status: str, detail: str = "") -> None:
        steps = [dict(s) for s in tx.steps]
        for s in steps:
            if s["name"] == name:
                s.update(status=status, ts=self.ctx.clock.now().isoformat(), detail=detail[:400])
        tx.steps = steps

    def _incident_event(self, db: Session, tx: RemediationTransaction, stage: str, message: str, data: dict[str, Any] | None = None) -> None:
        if tx.incident_id:
            db.add(IncidentEvent(incident_id=tx.incident_id, ts=self.ctx.clock.now(), stage=stage, message=message[:512], data=data or {}))

    def phases(self) -> list[tuple[str, Callable[[Session], bool], float]]:
        d = self.ctx.step_delay()
        return [("begin", self.begin, d), ("policy", self.policy_check, d), ("safety", self.safety_check, d), ("backup", self.backup, d),
                ("execute", self.execute, d * 2), ("verify", self.verify, d), ("commit", self.commit_or_rollback, d),
                ("chatops", self.chatops, d / 2), ("audit", self.audit, 0)]

    # ---------------------------------------------------------------- phases
    def begin(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        if tx.status != "PLANNED":
            return False
        tx.status = "RUNNING"
        tx.started_at = self.ctx.clock.now()
        self.ctx.runtime.inflight.add((tx.target, tx.action_id))
        self._step(tx, "POLICY CHECK", "running")
        self.ctx.bus.emit(db, "REMEDIATION_STARTED", f"{tx.id} {action.name} on {tx.target} started", severity="notice", source="autoheal",
                          target=tx.target, data={"transaction": tx.id, "action": tx.action_id}, correlation_id=tx.correlation_id)
        if tx.incident_id and (inc := db.get(Incident, tx.incident_id)) and inc.status == "OPEN":
            inc.status = "INVESTIGATING"
            inc.updated_at = self.ctx.clock.now()
        self._incident_event(db, tx, "REMEDIATION", f"{tx.id}: {action.name} started")
        return True

    def policy_check(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        decision = db.get(Decision, tx.decision_id) if tx.decision_id else None
        approved = bool(tx.approval_id and (ap := db.get(Approval, tx.approval_id)) and ap.status == "APPROVED")
        if decision and (decision.outcome == "AUTOMATE" or approved):
            how = f"approved by {db.get(Approval, tx.approval_id).decided_by}" if approved else f"{decision.outcome} per {decision.id}"  # type: ignore[union-attr]
            self._step(tx, "POLICY CHECK", "done", f"{how}; required permission {action.permission}")
            self._step(tx, "SAFETY CHECK", "running")
            return True
        self._step(tx, "POLICY CHECK", "failed", "no automation decision or approval on record")
        tx.status, tx.result = "REJECTED", "REJECTED"
        self.outcome = "REJECTED"
        return False

    def safety_check(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        if dev is None:
            self._step(tx, "SAFETY CHECK", "failed", "target missing")
            tx.status, tx.result = "FAILED", "FAILED"
            self.outcome = "EXEC_FAILED"
            return False
        try:
            commands = [" ".join(render(s["op"], dev, substitute(s, tx.params))) for s in action.execution]
        except CommandRejected as exc:
            self._step(tx, "SAFETY CHECK", "failed", str(exc))
            tx.status, tx.result, tx.error = "FAILED", "FAILED", str(exc)
            self.outcome = "EXEC_FAILED"
            return False
        pre = [self.ctx.probes.precondition(db, tx.target, substitute(p, tx.params)) for p in action.preconditions]
        failed = [p for p in pre if not p["passed"]]
        if failed:
            detail = "; ".join(p["detail"] for p in failed)
            cleared = any(p["check"] in ("service_not_running", "disk_above", "device_not_quarantined") for p in failed)
            self._step(tx, "SAFETY CHECK", "skipped" if cleared else "failed", detail)
            tx.status = "SKIPPED" if cleared else "FAILED"
            tx.result = "NOT_NEEDED" if cleared else "FAILED"
            tx.error = None if cleared else detail
            self.outcome = "SKIPPED" if cleared else "EXEC_FAILED"
            return cleared  # cleared -> still notify/audit; failed -> audit
        tx.commands = [{"command": c, "status": "pending"} for c in commands]
        self._step(tx, "SAFETY CHECK", "done", f"allowlist OK ({len(commands)} step(s)); preconditions: " + "; ".join(p["detail"] for p in pre))
        self._step(tx, "BACKUP", "running")
        return True

    def backup(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        if self.outcome == "SKIPPED":
            return True
        backup: dict[str, Any] = {}
        pre: dict[str, Any] = {"services": {s.id: s.status for s in db.scalars(select(Service).where(Service.device_id == tx.target))}}
        detail = "not required"
        if action.backup == "config":
            comp = action.backup_component or tx.params.get("component")
            item = db.get(ConfigItem, f"{tx.target}:{comp}")
            backup["config"] = {"component": comp, "actual": item.actual if item else {}, "checksum": item.checksum if item else ""}
            pre["config_checksum"] = item.checksum if item else None
            detail = f"{comp} saved (sha256 {backup['config']['checksum'][:12]})"
        elif action.backup == "firewall":
            from nexus.core.store import get_setting

            rules = self.ctx.firewall.list_rules(db)
            backup["firewall"] = rules
            backup["nexus_blocks"] = get_setting(db, "firewall_nexus_blocks") or []
            backup["checksum"] = sha256_of([(r["action"], r["source"], r["destination"], r["protocol"], r["port"]) for r in rules])
            detail = f"{len(rules)} rules saved (sha256 {backup['checksum'][:12]})"
        elif action.backup == "network_state" and dev:
            ip = db.scalar(select(IpAddress.address).where(IpAddress.device_id == dev.id))
            backup["network"] = {"vlan": dev.vlan_id, "ip": ip, "quarantined": dev.quarantined}
            detail = f"VLAN {dev.vlan_id}, address {ip}"
        elif action.backup == "service_state":
            backup["services"] = pre["services"]
            detail = "service states recorded"
        tx.backup = backup
        tx.pre_state = pre
        self._step(tx, "BACKUP", "done", detail)
        self._step(tx, "EXECUTION", "running")
        return True

    def execute(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        if self.outcome == "SKIPPED":
            return True
        results = []
        for step in action.execution:
            res = self.ctx.executor.run(db, dev, substitute(step, tx.params), tx)  # type: ignore[arg-type]
            results.append(res.as_dict())
            if res.exit_code != 0:
                break
        tx.commands = results
        failed = next((r for r in results if r["exit_code"] != 0), None)
        if failed:
            self.outcome = "EXEC_FAILED"
            self._step(tx, "EXECUTION", "failed", f"{failed['command']} -> exit {failed['exit_code']}: {failed['output'][:200]}")
            self._step(tx, "VERIFICATION", "skipped", "execution/validation failed")
            self.ctx.bus.emit(db, "VERIFICATION_FAILED", f"{tx.id}: validation failed - {failed['output'][:160]}", severity="high", source="autoheal",
                              target=tx.target, data={"transaction": tx.id}, correlation_id=tx.correlation_id)
        else:
            self._step(tx, "EXECUTION", "done", "; ".join(f"{r['command']} (exit 0)" for r in results) or "no commands")
            self._step(tx, "VERIFICATION", "running", "stabilising before probes")
        return True

    def verify(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        if self.outcome in ("SKIPPED", "EXEC_FAILED"):
            return True
        checks = [self.ctx.probes.check(db, tx.target, substitute(p, tx.params), tx) for p in action.verification]
        tx.verification = checks
        ok = all(c["passed"] for c in checks) and bool(checks)
        self.outcome = "VERIFIED" if ok else "VERIFY_FAILED"
        summary = ", ".join(f"{c['probe']} {'OK' if c['passed'] else 'FAILED'}" for c in checks)
        self._step(tx, "VERIFICATION", "done" if ok else "failed", summary)
        self.ctx.bus.emit(db, "VERIFICATION_PASSED" if ok else "VERIFICATION_FAILED", f"{tx.id} verification {'passed' if ok else 'FAILED'}: {summary}",
                          severity="info" if ok else "high", source="verification-engine", target=tx.target,
                          data={"transaction": tx.id, "checks": checks}, correlation_id=tx.correlation_id)
        self._incident_event(db, tx, "VERIFICATION", f"{tx.id} verification {'passed' if ok else 'failed'}: {summary}", {"checks": checks})
        return True

    def commit_or_rollback(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        now = self.ctx.clock.now()
        if self.outcome == "SKIPPED":
            self._step(tx, "COMMIT", "skipped", "condition already cleared - no change made")
            return True
        if self.outcome == "VERIFIED":
            tx.status, tx.result, tx.human_action = "COMMITTED", "SUCCESS", "NOT_REQUIRED"
            tx.post_state = {**(tx.post_state or {}), "services": {s.id: s.status for s in db.scalars(select(Service).where(Service.device_id == tx.target))}}
            self._step(tx, "COMMIT", "done", "desired state verified; change committed" + (" (rollback remains available)" if action.rollback_available else ""))
            return True
        tx.human_action = "REQUIRED"
        tx.result = "FAILED"
        if not action.rollback_available or not tx.backup:
            tx.status = "FAILED"
            tx.rollback_status = "NOT_APPLICABLE"
            self._step(tx, "COMMIT", "failed", "verification failed; stateless action - nothing to roll back; escalating to a human")
            return True
        self.ctx.bus.emit(db, "ROLLBACK_STARTED", f"{tx.id} rolling back {action.name} on {tx.target}", severity="high", source="autoheal",
                          target=tx.target, data={"transaction": tx.id}, correlation_id=tx.correlation_id)
        op = {"restore_backup": "restore_backup", "firewall_restore": "firewall_restore", "network_restore": "network_restore"}[action.rollback]
        step = {"op": op, "component": (tx.backup.get("config") or {}).get("component")}
        res = self.ctx.executor.run(db, dev, step, tx)  # type: ignore[arg-type]
        for s in action.execution:
            if s["op"] in ("service_restart", "service_reload") and res.exit_code == 0:
                self.ctx.executor.run(db, dev, substitute(s, tx.params), tx)  # type: ignore[arg-type]
        restored, detail = self._verify_original(db, tx, dev)
        tx.status = "ROLLED_BACK" if res.exit_code == 0 and restored else "FAILED"
        tx.rollback_status = "COMPLETED" if tx.status == "ROLLED_BACK" else "FAILED"
        tx.commands = list(tx.commands or []) + [res.as_dict() | {"rollback": True}]
        self._step(tx, "COMMIT", "rolled_back" if tx.status == "ROLLED_BACK" else "failed",
                   f"ROLLBACK: {res.display} (exit {res.exit_code}); verify original state: {detail}")
        self.ctx.bus.emit(db, "ROLLBACK_COMPLETED" if tx.status == "ROLLED_BACK" else "ROLLBACK_FAILED",
                          f"{tx.id} rollback {'completed' if tx.status == 'ROLLED_BACK' else 'FAILED'}: {detail}", severity="high",
                          source="autoheal", target=tx.target, data={"transaction": tx.id}, correlation_id=tx.correlation_id)
        self._incident_event(db, tx, "REMEDIATION", f"{tx.id} rolled back: {detail}")
        tx.finished_at = now
        return True

    def _verify_original(self, db: Session, tx: RemediationTransaction, dev: Device | None) -> tuple[bool, str]:
        b = tx.backup or {}
        if "config" in b:
            item = db.get(ConfigItem, f"{tx.target}:{b['config']['component']}")
            ok = bool(item and item.checksum == b["config"]["checksum"])
            return ok, f"{b['config']['component']} checksum {'matches' if ok else 'DIFFERS from'} pre-change backup"
        if "firewall" in b:
            rules = self.ctx.firewall.list_rules(db)
            current = sha256_of([(r["action"], r["source"], r["destination"], r["protocol"], r["port"]) for r in rules])
            ok = current == b.get("checksum")
            return ok, f"ruleset checksum {'matches' if ok else 'DIFFERS from'} backup"
        if "network" in b and dev:
            ok = dev.vlan_id == b["network"]["vlan"]
            return ok, f"device back in VLAN {dev.vlan_id}"
        return True, "no state to compare"

    def chatops(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        if self.outcome in ("REJECTED",):
            return True
        self._step(tx, "CHATOPS", "running")
        inc = db.get(Incident, tx.incident_id) if tx.incident_id else None
        verification = ", ".join(c["detail"] if c["probe"].startswith("http") else c["probe"] for c in (tx.verification or []) if c["passed"])
        if self.outcome == "VERIFIED":
            fields = {"Alert": tx.trigger, "Target": tx.target,
                      "Detected": (inc.created_at if inc else tx.created_at).astimezone(self.ctx.clock.site_tz).strftime("%H:%M:%S"),
                      "Action": action.name, "Verification": verification or "passed", "Result": "RESOLVED", "Human action": "NOT REQUIRED"}
            msg = self.ctx.chatops.record(db, "AUTOHEAL_EVENT", "AUTOHEAL EVENT", fields, tx.correlation_id)
        elif self.outcome == "SKIPPED":
            msg = None
        else:
            fields = {"Target": tx.target, "Action": action.name, "Verification": "FAILED" if self.outcome == "VERIFY_FAILED" else "NOT REACHED",
                      "Rollback": {"COMPLETED": "COMPLETED", "FAILED": "FAILED", "NOT_APPLICABLE": "NOT APPLICABLE"}.get(tx.rollback_status, tx.rollback_status),
                      "Human action": "REQUIRED"}
            msg = self.ctx.chatops.record(db, "AUTOHEAL_FAILED", "AUTOHEAL FAILED", fields, tx.correlation_id)
        self._step(tx, "CHATOPS", "done" if msg else "skipped", f"{msg.provider} {msg.delivery_status}" if msg else "no notification for skipped action")
        return True

    def audit(self, db: Session) -> bool:
        tx, action, dev = self._load(db)
        now = self.ctx.clock.now()
        tx.finished_at = tx.finished_at or now
        if tx.started_at:
            tx.duration_ms = int((tx.finished_at - tx.started_at).total_seconds() * 1000)
        if tx.status == "RUNNING":
            tx.status, tx.result = "FAILED", tx.result or "FAILED"
        result = tx.result or "FAILED"
        rec = record_audit(self.ctx, db, actor="AUTOHEAL" if tx.requested_by == "AUTOHEAL" else tx.requested_by,
                           actor_type="AUTOHEAL" if tx.requested_by == "AUTOHEAL" else "OPERATOR", action=action.name.lower(), reason=tx.trigger,
                           target=tx.target, result=result, correlation_id=tx.correlation_id, transaction_id=tx.id, incident_id=tx.incident_id,
                           severity="info" if result in ("SUCCESS", "NOT_NEEDED") else "high",
                           details={"status": tx.status, "rollback": tx.rollback_status, "verification": tx.verification})
        self._step(tx, "AUDIT", "done", f"audit record #{rec.id}")
        if decision := (db.get(Decision, tx.decision_id) if tx.decision_id else None):
            decision.result = tx.status
        self._close_loop(db, tx, action)
        event = "REMEDIATION_COMPLETED" if result in ("SUCCESS", "NOT_NEEDED") else "REMEDIATION_FAILED"
        self.ctx.bus.emit(db, event, f"{tx.id} {action.name} on {tx.target}: {tx.status}" + (f" in {tx.duration_ms} ms" if tx.duration_ms else ""),
                          severity="info" if event == "REMEDIATION_COMPLETED" else "high", source="autoheal", target=tx.target,
                          data={"transaction": tx.id, "status": tx.status, "result": result, "duration_ms": tx.duration_ms}, correlation_id=tx.correlation_id)
        log_event(log, event, target=tx.target, transaction_id=tx.id, result=result, correlation_id=tx.correlation_id)
        self.ctx.runtime.inflight.discard((tx.target, tx.action_id))
        self.ctx.runtime.snapshot_dirty = True
        self.ctx.metrics.observe_remediation(result, tx.duration_ms)
        return True

    def _close_loop(self, db: Session, tx: RemediationTransaction, action: Action) -> None:
        from nexus.incidents.engine import resolve_incident

        now = self.ctx.clock.now()
        drift_ids = list(tx.params.get("drift_ids") or ([tx.drift_id] if tx.drift_id else []))
        for d in db.scalars(select(DriftEvent).where(DriftEvent.id.in_(drift_ids))).all():
            if tx.result == "SUCCESS":
                d.status, d.resolved_at = "REMEDIATED", now
                self.ctx.bus.emit(db, "DRIFT_REMEDIATED", f"{d.id} remediated by {tx.id}: {d.device_id} {d.component}.{d.key} compliant",
                                  source="autoheal", target=d.device_id, data={"drift": d.id, "transaction": tx.id}, correlation_id=d.correlation_id)
            elif tx.result == "NOT_NEEDED":
                d.status, d.resolved_at = "RESOLVED_EXTERNALLY", now
            else:
                d.status = "FAILED"
        dev = db.get(Device, tx.target)
        if dev:
            from nexus.risk.engine import recompute_device

            recompute_device(self.ctx, db, dev, f"{tx.id} {tx.status.lower()}", tx.correlation_id, evaluate_policy=False)
        if not tx.incident_id:
            return
        inc = db.get(Incident, tx.incident_id)
        if inc is None:
            return
        if tx.result == "SUCCESS":
            firing = db.scalar(select(Alert).where(Alert.incident_id == inc.id, Alert.status == "FIRING"))
            containment = tx.action_id in ("REM-NET-QUARANTINE", "REM-NET-BLOCK-PORT")
            if containment or (firing and not drift_ids):
                inc.status = "MITIGATED"
                inc.mitigated_at = now
                inc.updated_at = now
                db.add(IncidentEvent(incident_id=inc.id, ts=now, stage="RESOLUTION", message=f"Mitigated by {tx.id} ({action.name})"))
                self.ctx.bus.emit(db, "INCIDENT_MITIGATED", f"{inc.id} mitigated by {tx.id}", source="incident-engine", target=inc.target,
                                  data={"incident": inc.id}, correlation_id=inc.correlation_id)
            else:
                resolve_incident(self.ctx, db, inc.id, f"{action.name} verified ({tx.id})", actor="AUTOHEAL")
        elif tx.result == "FAILED":
            inc.human_required = True
            inc.status = "INVESTIGATING"
            inc.updated_at = now
            recs = list(inc.recommendations or [])
            recs.append(f"{tx.id} {action.name} failed verification; rollback {tx.rollback_status.lower()} - investigate manually")
            inc.recommendations = recs


def run_sync(ctx: Context, tx_id: str, time_step: float = 0.0) -> str:
    """Synchronous run. `time_step` advances the simulated clock between phases (synthetic history only)."""
    from datetime import timedelta

    run = TransactionRun(ctx, tx_id)
    for _name, phase, _delay in run.phases():
        if time_step and _name != "begin":
            ctx.clock.shift(timedelta(seconds=time_step * (2 if _name == "verify" else 1)))
        with ctx.session() as db:
            if not phase(db):
                if run.outcome in ("REJECTED", "EXEC_FAILED") and _name in ("policy", "safety"):
                    with ctx.session() as db2:
                        run.audit(db2)
                break
    return run.outcome


async def run_async(ctx: Context, tx_id: str) -> str:
    run = TransactionRun(ctx, tx_id)
    try:
        for name, phase, delay in run.phases():
            with ctx.session() as db:
                cont = phase(db)
            if not cont:
                if run.outcome in ("REJECTED", "EXEC_FAILED") and name in ("policy", "safety"):
                    with ctx.session() as db:
                        run.audit(db)
                break
            if delay:
                await asyncio.sleep(delay)
    except Exception:  # noqa: BLE001
        log.exception("transaction crashed", extra={"transaction_id": tx_id})
        with ctx.session() as db:
            tx = db.get(RemediationTransaction, tx_id)
            if tx and tx.status in ("RUNNING", "PLANNED"):
                tx.status, tx.result, tx.human_action, tx.error = "FAILED", "FAILED", "REQUIRED", "internal error - see logs"
        ctx.runtime.inflight.discard(next((k for k in ctx.runtime.inflight if k[0] == tx_id), ("", "")))
    return run.outcome


def drain_sync(ctx: Context, limit: int = 50, time_step: float = 0.0) -> list[str]:
    """Run queued transactions synchronously (seeding, tests, CLI offline mode)."""
    done: list[str] = []
    while ctx.runtime.sync_queue and len(done) < limit:
        tx_id = ctx.runtime.sync_queue.pop(0)
        run_sync(ctx, tx_id, time_step)
        done.append(tx_id)
    return done


def tx_dict(tx: RemediationTransaction) -> dict[str, Any]:
    return {"id": tx.id, "action_id": tx.action_id, "action_name": tx.action_name, "target": tx.target, "params": tx.params, "trigger": tx.trigger,
            "category": tx.category, "risk": tx.risk, "automation_confidence": tx.automation_confidence, "status": tx.status, "result": tx.result,
            "steps": tx.steps, "pre_state": tx.pre_state, "backup": {k: (v if k != "firewall" else f"{len(v)} rules") for k, v in (tx.backup or {}).items()},
            "post_state": {k: v for k, v in (tx.post_state or {}).items() if k != "removed_rules"}, "commands": tx.commands,
            "verification": tx.verification, "rollback_available": tx.rollback_available, "rollback_status": tx.rollback_status,
            "human_action": tx.human_action, "decision_id": tx.decision_id, "incident_id": tx.incident_id, "drift_id": tx.drift_id,
            "approval_id": tx.approval_id, "correlation_id": tx.correlation_id, "requested_by": tx.requested_by, "error": tx.error,
            "created_at": tx.created_at.isoformat(), "started_at": tx.started_at.isoformat() if tx.started_at else None,
            "finished_at": tx.finished_at.isoformat() if tx.finished_at else None, "duration_ms": tx.duration_ms}

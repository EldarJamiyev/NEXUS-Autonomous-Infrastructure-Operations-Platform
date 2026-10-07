"""Prometheus metrics. Gauges are computed from the state model at scrape time."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import func, select

from nexus.models import Certificate, Device, DriftEvent, Incident, Lease, RiskScore, Service
from nexus.models import Session as UserSession

if TYPE_CHECKING:
    from nexus.core.context import Context


class StateCollector:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    def collect(self) -> Any:
        ctx = self.ctx
        with ctx.session() as db:
            def g(name: str, doc: str, value: float) -> GaugeMetricFamily:
                m = GaugeMetricFamily(name, doc)
                m.add_metric([], value)
                return m

            yield g("nexus_active_sessions", "Active AD sessions", db.scalar(select(func.count()).select_from(UserSession).where(UserSession.active.is_(True))) or 0)
            yield g("nexus_active_leases", "Active access leases", db.scalar(select(func.count()).select_from(Lease).where(Lease.status == "ACTIVE")) or 0)
            yield g("nexus_quarantined_devices", "Quarantined devices", db.scalar(select(func.count()).select_from(Device).where(Device.quarantined.is_(True))) or 0)
            yield g("nexus_unknown_devices", "Devices without established identity", db.scalar(select(func.count()).select_from(Device).where(Device.kind == "unknown", Device.quarantined.is_(False))) or 0)
            yield g("nexus_policy_conflicts", "Conflicts in the last policy compilation", len((getattr(ctx.runtime, "last_compile", None) or {}).get("conflicts", [])))
            yield g("nexus_controller_health", "1 when the control loop is running", 1.0 if ctx.live or not ctx.settings.background_tasks else 0.0)
            yield g("nexus_event_bus_subscribers", "Live event subscribers", ctx.bus.subscriber_count)
            unexpected = db.scalar(select(func.count()).select_from(DriftEvent).where(DriftEvent.component == "firewall", DriftEvent.key.like("unauthorized_rule%"),
                                                                                     DriftEvent.status.in_(("OPEN", "REMEDIATING", "APPROVAL_REQUIRED", "FAILED")))) or 0
            yield g("nexus_unexpected_firewall_rules", "Unauthorized firewall rules currently present", unexpected)
            inc = GaugeMetricFamily("nexus_open_incidents", "Open incidents by priority", labels=["priority"])
            for p in ("P1", "P2", "P3", "P4"):
                inc.add_metric([p], db.scalar(select(func.count()).select_from(Incident).where(Incident.priority == p, Incident.status.in_(("OPEN", "INVESTIGATING")))) or 0)
            yield inc
            drift = GaugeMetricFamily("nexus_drift_events", "Drift events by status", labels=["status"])
            for status, n in db.execute(select(DriftEvent.status, func.count()).group_by(DriftEvent.status)).all():
                drift.add_metric([status.lower()], n)
            yield drift
            risk = GaugeMetricFamily("nexus_risk_score", "Risk score per entity", labels=["entity_type", "entity"])
            for r in db.scalars(select(RiskScore)):
                risk.add_metric([r.entity_type, r.entity_id], r.score)
            yield risk
            up = GaugeMetricFamily("nexus_sim_service_up", "Simulated service process state (1 running)", labels=["device", "service"])
            for s in db.scalars(select(Service)):
                up.add_metric([s.device_id, s.name], 1.0 if s.status == "running" else 0.0)
            yield up
            reach = GaugeMetricFamily("nexus_sim_node_reachable", "Simulated ICMP reachability", labels=["device"])
            cpu = GaugeMetricFamily("nexus_sim_cpu_percent", "Simulated CPU utilisation", labels=["device"])
            disk = GaugeMetricFamily("nexus_sim_disk_used_percent", "Simulated filesystem usage", labels=["device", "mount"])
            for d in db.scalars(select(Device)):
                reach.add_metric([d.id], 1.0 if d.reachable else 0.0)
                if (d.metrics or {}).get("cpu") is not None:
                    cpu.add_metric([d.id], float(d.metrics["cpu"]))
                for mount, pct in ((d.metrics or {}).get("disk", {}) or {}).items():
                    disk.add_metric([d.id, mount], float(pct))
            yield reach
            yield cpu
            yield disk
            certs = GaugeMetricFamily("nexus_sim_cert_days_remaining", "Days until certificate expiry", labels=["cn", "device"])
            now = ctx.clock.now()
            for c in db.scalars(select(Certificate)):
                certs.add_metric([c.id, c.device_id], round((c.not_after - now).total_seconds() / 86400, 2))
            yield certs


class Metrics:
    def __init__(self, ctx: Context) -> None:
        self.registry = CollectorRegistry()
        self.remediation_success = Counter("nexus_remediation_success_total", "Verified successful remediations", registry=self.registry)
        self.remediation_failure = Counter("nexus_remediation_failure_total", "Failed or rolled-back remediations", registry=self.registry)
        self.event_latency = Histogram("nexus_event_processing_latency_seconds", "Commit-to-dispatch latency of bus events",
                                       buckets=(0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5), registry=self.registry)
        self.registry.register(StateCollector(ctx))
        ctx.bus.latency_observer = self.event_latency.observe

    def observe_remediation(self, result: str, duration_ms: int | None) -> None:
        if result == "SUCCESS":
            self.remediation_success.inc()
        elif result in ("FAILED", "ROLLED_BACK"):
            self.remediation_failure.inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)

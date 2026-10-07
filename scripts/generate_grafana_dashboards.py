"""Generate the provisioned Grafana dashboards (grafana/dashboards/*.json). Run: python scripts/generate_grafana_dashboards.py"""

from __future__ import annotations

import json
from pathlib import Path

PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
OUT = Path(__file__).resolve().parent.parent / "grafana" / "dashboards"


class Board:
    def __init__(self, uid: str, title: str, description: str) -> None:
        self.uid, self.title, self.description = uid, title, description
        self.panels: list[dict] = []
        self.x = self.y = 0
        self.row_h = 0

    def _place(self, w: int, h: int) -> dict:
        if self.x + w > 24:
            self.x, self.y = 0, self.y + self.row_h
            self.row_h = 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def add(self, panel: dict, w: int, h: int) -> None:
        panel.update(id=len(self.panels) + 1, gridPos=self._place(w, h))
        self.panels.append(panel)

    def stat(self, title: str, expr: str, w: int = 4, unit: str = "short", red: float | None = 1, desc: str = "") -> None:
        steps = [{"color": "green", "value": None}] + ([{"color": "red", "value": red}] if red is not None else [])
        self.add({"type": "stat", "title": title, "description": desc, "datasource": PROM,
                  "targets": [{"refId": "A", "expr": expr, "datasource": PROM}],
                  "fieldConfig": {"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": steps}}, "overrides": []},
                  "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "area"}}, w, 4)

    def ts(self, title: str, exprs: list[tuple[str, str]], w: int = 12, h: int = 8, unit: str = "short", stack: bool = False, desc: str = "") -> None:
        self.add({"type": "timeseries", "title": title, "description": desc, "datasource": PROM,
                  "targets": [{"refId": chr(65 + i), "expr": e, "legendFormat": legend, "datasource": PROM} for i, (e, legend) in enumerate(exprs)],
                  "fieldConfig": {"defaults": {"unit": unit, "custom": {"lineWidth": 1, "fillOpacity": 12, "stacking": {"mode": "normal" if stack else "none"}}}, "overrides": []},
                  "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}}}, w, h)

    def table(self, title: str, expr: str, w: int = 12, h: int = 8) -> None:
        self.add({"type": "table", "title": title, "datasource": PROM,
                  "targets": [{"refId": "A", "expr": expr, "instant": True, "format": "table", "datasource": PROM}],
                  "transformations": [{"id": "organize", "options": {"excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True, "environment": True}}}],
                  "fieldConfig": {"defaults": {}, "overrides": []}, "options": {"showHeader": True}}, w, h)

    def logs(self, title: str, expr: str, w: int = 24, h: int = 9) -> None:
        self.add({"type": "logs", "title": title, "datasource": LOKI, "targets": [{"refId": "A", "expr": expr, "datasource": LOKI}],
                  "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending", "enableLogDetails": True}}, w, h)

    def dump(self) -> dict:
        return {"uid": self.uid, "title": self.title, "description": self.description, "tags": ["nexus"], "timezone": "browser", "schemaVersion": 39,
                "version": 1, "editable": False, "refresh": "10s", "time": {"from": "now-1h", "to": "now"}, "panels": self.panels,
                "templating": {"list": []}, "annotations": {"list": []}}


def boards() -> list[Board]:
    out = []
    b = Board("nexus-overview", "NEXUS Overview", "Control plane state at a glance (SIMULATION metrics unless a real lab is connected)")
    b.stat("Open incidents", "sum(nexus_open_incidents)")
    b.stat("Active leases", "nexus_active_leases", red=None)
    b.stat("Quarantined devices", "nexus_quarantined_devices")
    b.stat("Unknown devices", "nexus_unknown_devices")
    b.stat("Unauthorized firewall rules", "nexus_unexpected_firewall_rules")
    b.stat("Controller health", "nexus_controller_health", red=None, desc="1 = control loop running")
    b.ts("Open incidents by priority", [("nexus_open_incidents", "{{priority}}")], stack=True)
    b.ts("Remediations per hour", [("increase(nexus_remediation_success_total[1h])", "verified success"), ("increase(nexus_remediation_failure_total[1h])", "failed / rolled back")])
    b.ts("Highest device risk", [("max(nexus_risk_score{entity_type=\"device\"})", "max risk")], w=12)
    b.ts("Services not running", [("count(nexus_sim_service_up == 0) or vector(0)", "services down")], w=12)
    b.logs("NEXUS structured log (remediation, audit, errors)", '{job="nexus"} | json | event=~"REMEDIATION.*|AUDIT|API_ERROR|LOOP_ERROR"')
    out.append(b)
    b = Board("nexus-risk", "NEXUS Risk", "Deterministic, explainable risk scores")
    b.ts("Device risk", [("nexus_risk_score{entity_type=\"device\"}", "{{entity}}")], w=16, h=9)
    b.table("Current risk (all entities)", "sort_desc(nexus_risk_score)", w=8, h=9)
    b.ts("User risk", [("nexus_risk_score{entity_type=\"user\"}", "{{entity}}")], w=24)
    out.append(b)
    b = Board("nexus-incidents", "NEXUS Incidents", "Incident volume and priority")
    for p in ("P1", "P2", "P3", "P4"):
        b.stat(f"Open {p}", f'nexus_open_incidents{{priority="{p}"}}', w=6)
    b.ts("Open incidents", [("nexus_open_incidents", "{{priority}}")], w=24, stack=True)
    out.append(b)
    b = Board("nexus-remediation", "NEXUS Remediation", "AutoHeal outcomes and control-plane latency")
    b.stat("Verified successes (total)", "nexus_remediation_success_total", red=None, w=6)
    b.stat("Failures / rollbacks (total)", "nexus_remediation_failure_total", w=6)
    b.stat("Success ratio (24h)", "increase(nexus_remediation_success_total[24h]) / clamp_min(increase(nexus_remediation_success_total[24h]) + increase(nexus_remediation_failure_total[24h]), 1)", unit="percentunit", red=None, w=6)
    b.stat("Event bus subscribers", "nexus_event_bus_subscribers", red=None, w=6)
    b.ts("Remediation rate", [("rate(nexus_remediation_success_total[5m])", "success/s"), ("rate(nexus_remediation_failure_total[5m])", "failure/s")])
    b.ts("Event dispatch latency (p95)", [("histogram_quantile(0.95, sum(rate(nexus_event_processing_latency_seconds_bucket[5m])) by (le))", "p95")], unit="s")
    out.append(b)
    b = Board("nexus-network", "NEXUS Network", "Reachability and load of simulated assets")
    b.ts("Reachability (1 = up)", [("nexus_sim_node_reachable", "{{device}}")], w=24, h=7)
    b.ts("CPU %", [("nexus_sim_cpu_percent", "{{device}}")], w=24, unit="percent")
    out.append(b)
    b = Board("nexus-identity", "NEXUS Identity", "Sessions, unknown devices and containment")
    b.stat("Active sessions", "nexus_active_sessions", red=None, w=8)
    b.stat("Unknown devices", "nexus_unknown_devices", w=8)
    b.stat("Quarantined", "nexus_quarantined_devices", w=8)
    b.ts("Sessions and unknown devices", [("nexus_active_sessions", "sessions"), ("nexus_unknown_devices", "unknown devices"), ("nexus_quarantined_devices", "quarantined")], w=24)
    out.append(b)
    b = Board("nexus-leases", "NEXUS Leases", "Ephemeral access leases")
    b.stat("Active leases", "nexus_active_leases", red=None, w=8)
    b.ts("Active leases over time", [("nexus_active_leases", "active leases")], w=16, h=4)
    out.append(b)
    b = Board("nexus-infrastructure-health", "NEXUS Infrastructure Health", "Services, disks and certificates")
    b.table("Service process state (1 = running)", "nexus_sim_service_up", w=12, h=10)
    b.ts("Disk usage %", [("nexus_sim_disk_used_percent", "{{device}} {{mount}}")], w=12, h=10, unit="percent")
    b.ts("Certificate days remaining", [("nexus_sim_cert_days_remaining", "{{cn}}")], w=24)
    out.append(b)
    return out


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for board in boards():
        (OUT / f"{board.uid}.json").write_text(json.dumps(board.dump(), indent=2) + "\n", encoding="utf-8")
        print("wrote", board.uid, len(board.panels), "panels")

"""Alert triage: impact x urgency matrix -> P1..P4 (ITIL-style, deterministic)."""

from __future__ import annotations

from typing import Any

MATRIX = {("HIGH", "HIGH"): "P1", ("HIGH", "MEDIUM"): "P2", ("HIGH", "LOW"): "P3",
          ("MEDIUM", "HIGH"): "P2", ("MEDIUM", "MEDIUM"): "P3", ("MEDIUM", "LOW"): "P4",
          ("LOW", "HIGH"): "P3", ("LOW", "MEDIUM"): "P4", ("LOW", "LOW"): "P4"}
SEVERITY_FROM_PRIORITY = {"P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM", "P4": "LOW"}


def triage(*, severity: str, criticality: str, users: int, services: int, risk: int, recent_change: bool) -> dict[str, Any]:
    factors = []
    if criticality == "CRITICAL" or users >= 3 or services >= 3:
        impact = "HIGH"
    elif criticality == "HIGH" or users >= 1 or services >= 1:
        impact = "MEDIUM"
    else:
        impact = "LOW"
    factors.append(f"impact {impact}: asset {criticality}, {users} user(s), {services} service(s) affected")
    if severity == "critical" or risk >= 80:
        urgency = "HIGH"
    elif severity == "high" or risk >= 60:
        urgency = "MEDIUM"
    else:
        urgency = "LOW"
    factors.append(f"urgency {urgency}: alert severity {severity}, risk {risk}")
    if recent_change:
        factors.append("recent change on the asset (change-related incidents are common)")
    priority = MATRIX[(impact, urgency)]
    return {"priority": priority, "impact": impact, "urgency": urgency, "factors": factors, "severity": SEVERITY_FROM_PRIORITY[priority]}

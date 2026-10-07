# Changelog

## 0.1.0 - 2026-10-06

First public version.

- Control plane: detection, reconciliation and snapshot loops on a single-writer asyncio event loop; transactional-outbox event bus.
- Relational state model (35 tables) with Alembic migrations; SQLite by default, PostgreSQL-compatible.
- Identity confidence heuristic, deterministic risk scoring with trust decay, session-bound ephemeral access leases.
- Policy as code: schema validation, normalization, conflict and shadowed-rule detection, impact and risk analysis, rule generation, lockout protection, version control.
- Drift detection against Git intent with SHA-256 evidence and real unified diffs; maintenance mode.
- Remediation catalog (25 actions), command allowlist, decision engine with human-in-the-loop rules, transactions with backup, verification and rollback.
- Incident correlation, deterministic root-cause analysis, ITIL triage, recurring-failure detection, Markdown/HTML reports.
- Time machine, what-if and disaster-recovery lab, change impact analysis, troubleshooting center, morning brief, shift handover, read-only operator assistant.
- Chaos lab with 21 scenarios and the blackout drill; 20-scene guided demo.
- React console: 24 pages, digital twin, live WebSocket updates, command palette, presentation mode, light/dark themes.
- `nexusctl` CLI, Docker image and compose stack with Prometheus, Alertmanager, Grafana (8 dashboards) and Loki.
- Ansible roles and playbooks, PowerShell AD/Windows scripts, GitHub Actions CI.

# Remediation guide

The catalog (`backend/nexus/remediation/catalog.yaml`) lists 25 actions. Each declares category, risk, required
permission, base confidence, preconditions, backup type, execution steps (operation templates), verification probes,
rollback and timeout.

## Decision rules

- **SAFE** (restart a verified-down service, rotate approved logs, reclaim DHCP): automatic at level ≥ 3.
- **REVERSIBLE** (restore SSH/Nginx/monitoring baselines, firewall rollback, VLAN restore, containment rule):
  automatic when automation confidence ≥ 80%.
- **HIGH_IMPACT** (Docker restart, container restart, quarantine, Windows baseline): approval, unless a security
  policy explicitly permits it (SECURITY-004 for unmanaged endpoints) or level 4 inside a change window.
- **CRITICAL** (certificate renewal, human investigation): never automatic in the demo.

Automation confidence = catalog baseline minus evidence gaps: alert not validated (-20), root cause MEDIUM (-10) or
LOW (-25), no verification probe (-25), each failed attempt on the same target in 24 h (-15, max -30).

Guards on every decision: allowlist rendering, preconditions, duplicate in-flight action, loop guard (3 per target
per 10 min), mass-change guard (10 automated per minute), protected assets, change window, firewall availability.

## Writing a new action

See CONTRIBUTING.md. Keep operations narrow (an enum of units, paths or containers), always add a verification
probe that tests the outcome, and add a rollback whenever the action changes configuration.

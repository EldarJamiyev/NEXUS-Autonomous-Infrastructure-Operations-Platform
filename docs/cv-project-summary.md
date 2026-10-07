# NEXUS OMNIS - CV project summary

## One line

Self-healing infrastructure control-plane prototype (Python/FastAPI, React/TypeScript) with event-driven
monitoring, configuration-drift detection, identity-aware access, risk evaluation, reversible remediation,
incident correlation, a network digital twin and ChatOps.

## CV bullets (pick 3-5)

- Designed and implemented NEXUS OMNIS, a self-healing infrastructure control-plane prototype integrating
  event-driven monitoring, configuration drift detection, identity-aware access, risk evaluation, reversible
  remediation, incident correlation, network digital-twin visualization and ChatOps.
- Implemented declarative infrastructure intent (Git-controlled YAML) and automated reconciliation workflows with
  pre-change backups, allowlisted execution, verification of the real end state and automatic rollback.
- Built a simulated enterprise (Windows/AD, Linux, pfSense firewall, six VLANs, monitoring and endpoints) whose
  failures NEXUS must detect through probes and logs; 21 chaos scenarios plus a nine-fault blackout drill.
- Implemented deterministic incident correlation and root-cause analysis over a service dependency graph, change
  impact simulation and historical infrastructure state reconstruction (time machine).
- Developed a real-time React/FastAPI operations console (24 pages, WebSocket updates, command palette) covering
  network state, risk, incidents, ephemeral access leases and automated remediation.
- Delivered with 48 behavioural backend tests, strict typing (mypy, TypeScript), Docker/Compose with
  Prometheus/Alertmanager/Grafana/Loki, Ansible roles, PowerShell AD scripts and GitHub Actions CI.

## Short paragraph (cover letter / LinkedIn)

I built NEXUS OMNIS to automate the repetitive loop IT engineers live in: notice a failure, investigate, fix,
verify, explain. It models users, devices, network, services, configuration, policy and risk as one state, compares
reality with intent stored in Git, and only acts when its rules say an action is safe - backing up first, verifying
the outcome and rolling back if the fix didn't work. Everything runs against a realistic simulated enterprise, and
the integrations to real AD, pfSense, Ansible and Prometheus are built behind clear adapter interfaces.

## What to say it is not

A production product, an AI system, or the first of its kind. It is a deliberately honest prototype: deterministic
decisions, labelled heuristics, and a clear line between simulation and real infrastructure.

## Skills demonstrated (by the system, not a keyword list)

Linux and Windows administration (sshd, nginx, systemd, W32Time, AD events), networking (VLANs, DHCP, ARP, DNS,
first-match firewall rules, shadowing), Python (FastAPI, SQLAlchemy, Alembic, asyncio), React/TypeScript,
REST and WebSockets, SQL schema design, Docker, Prometheus/Grafana/Loki, Ansible, PowerShell, Git-based intent,
CI/CD, incident response and automation safety.

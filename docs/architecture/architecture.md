# Architecture

NEXUS OMNIS is a single control-plane process (FastAPI + asyncio) around one relational state model. Every
feature reads and writes the same tables; there are no per-feature stores. The web console is a React SPA
served by the same process and kept live over a WebSocket.

## Layers

| Layer | Modules | Responsibility |
|---|---|---|
| Observation | `monitoring/detector.py`, `network/discovery.py`, `identity/ingest.py`, `api/routers/operations.py` (Alertmanager), `/api/ingest/*` | Turn probes, DHCP/ARP/syslog, Windows events, agent reports and webhooks into normalised events and alerts |
| State | `models/`, `database/`, `timemachine/` | 35 tables (identity, network, policy, risk, drift, incidents, transactions, audit, events, snapshots) |
| Understanding | `identity/confidence.py`, `risk/engine.py`, `dependencies/graph.py`, `incidents/rca.py`, `network/inventory.py` | Identity confidence, risk with trust decay, impact propagation, deterministic root cause |
| Intent and policy | `policy/`, `drift/`, `baselines/`, `policies/` | Git-controlled desired state, policy compiler, access evaluator, drift classification |
| Decision | `core/decision.py`, `incidents/engine.py` (planner), `policy/security.py` | Human-in-the-loop rules, safety rails, automation confidence, approvals |
| Action | `remediation/` (catalog, executor, verification, runner), `leases/`, `firewall/` | Allowlisted execution, backup, verification, commit or rollback |
| Communication | `chatops/`, `events/bus.py`, `api/routers/ws.py`, `core/audit.py` | Notifications, live events, audit trail |
| Simulation | `simulation/world.py`, `simulation/seed.py`, `simulation/history.py`, `chaos/`, `simulation/demo.py` | The fictional enterprise, its physics, synthetic history, failure injection, guided demo |

## The control loop

`core/controlplane.py` runs four loops on one event loop:

- **tick** (2 s): advances simulated CPU, memory, traffic and fault symptoms; broadcasts metrics.
- **detect** (2 s): monitoring scan → alert pipeline (validate → correlate → incident → RCA → plan); evaluates system mode.
- **reconcile** (20 s full, 1 s targeted): lease expiry, pending firewall changes, drift scan, risk recompute with trust recovery.
  Configuration-change events schedule a targeted reconcile of that device, so drift is found in about a second.
- **snapshot** (on change, at least every 60 s): Time Machine state capture with retention.

**Single-writer rule.** Every unit of work is a short synchronous database transaction; nothing awaits while a
session is open. Remediation transactions are coroutines that commit after each phase and sleep between phases
so the console can show progress. This removes lock contention on SQLite and makes ordering deterministic.

## Event bus

Events are inserted into the `events` table inside the caller's transaction and dispatched to subscribers in
SQLAlchemy's `after_commit` hook (a transactional outbox). Rolled-back work never emits events. Subscriber
queues are bounded and drop their oldest entries rather than blocking the producer. The `EventBus` protocol
is the seam for Redis Streams or NATS when the control plane is split.

## Remediation transaction

`DETECTED → TRIAGED → POLICY CHECK → SAFETY CHECK → BACKUP → EXECUTION → VERIFICATION → COMMIT | ROLLBACK → CHATOPS → AUDIT`

Each step is persisted with timestamp and detail. Preconditions are re-checked at execution time (a service
that recovered on its own is SKIPPED, not restarted). Verification probes the desired end state; if it fails
the backup is restored and the original state verified (configuration checksum, firewall ruleset checksum or
VLAN membership). Stateless actions report `rollback NOT APPLICABLE` and escalate to a human.

## Correlation and root cause

Alerts in the availability family merge when the dependency graph connects them; security findings merge
only on the same target and correlation group. Candidates are scored on observed failure (+40), explaining
all symptoms through the graph (+30), recent non-NEXUS configuration change (+20), failed validation (+10),
earliest symptom (+10), and failing dependencies (-25). HIGH ≥ 70, MEDIUM ≥ 45.

## Simulation boundary

The World owns actual state (service processes, configuration files, faults). NEXUS engines never read
`Device.sim_faults`; only the World, the simulated executor and the simulated probes do. Chaos scenarios change
the World and record `FAILURE_INJECTED`; detection is left to NEXUS. The same engines run in real-lab mode with
the pfSense adapter, Ansible executor, network probes and ingest endpoints.

## Scaling path

1. PostgreSQL via `DATABASE_URL` (the schema is portable; migrations use batch mode for SQLite).
2. Redis Streams behind the `EventBus` protocol; WebSocket fan-out from the stream.
3. Split detection/reconciliation workers from the API; keep a single leader for remediation (leader election
   via a database advisory lock) so the duplicate guard stays authoritative.
4. Per-site collectors that push observations to the central ingest API.

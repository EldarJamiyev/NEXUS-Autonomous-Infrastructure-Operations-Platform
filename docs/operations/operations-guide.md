# Operations guide

## Daily routine

1. **Daily operations** page or `nexusctl status`: overnight incidents, unresolved alerts, expiring leases, drift,
   high-risk devices, failed automations, certificates, capacity.
2. **Generate morning brief** for a text summary you can paste into a team channel.
3. Work the **Approvals** queue: each card shows why NEXUS stopped (category, confidence, change window, guards).
4. Before ending a shift, **Shift handover** → *Save as report*.

## Autonomy levels

| Level | Behaviour |
|---|---|
| 0 Observe | record only |
| 1 Alert | incidents and alerts, no actions |
| 2 Recommend | every action needs approval |
| 3 Reversible AutoHeal (default) | SAFE automatic, REVERSIBLE when confidence ≥ 80% |
| 4 Critical AutoHeal | also HIGH_IMPACT inside change windows at ≥ 90% |
| 5 Autonomous Quarantine | also quarantine managed devices |

Change it on the System page (ADMIN). Every change is audited.

## System modes

NORMAL, DEGRADED (firewall API unavailable, state store degraded, monitoring blind), RECOVERY (replaying pending
changes) and EMERGENCY (multiple P1s or the blackout drill). The banner under the top bar explains the reason and
the current behaviour, e.g. "new privileged leases blocked".

## Maintenance windows

Changes → *Start maintenance mode* (ENGINEER). Drift detected during maintenance is EXPECTED and not remediated.
Ending maintenance triggers reconciliation; drift that remains becomes an incident. HIGH_IMPACT actions outside
the configured window (default Saturday 02:00-04:00 site time) require approval.

## Incidents

Acknowledge (OPERATOR), resolve or mark false positive. *Retry remediation* (ENGINEER) re-plans for the current root
cause. Reports are available as Markdown and HTML from the incident page.

## Simulation clock

System → Simulation clock lets an ADMIN jump site time (for after-hours access policies) or accelerate time ×60
(lease expiry). Restore real time afterwards.

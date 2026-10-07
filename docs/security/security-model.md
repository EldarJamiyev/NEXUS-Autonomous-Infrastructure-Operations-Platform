# Security model

## Principles

1. **Least privilege** - four console roles enforced on the server; adapters use dedicated, scoped credentials.
2. **Never trust input** - alerts, webhooks, agent reports and Windows events are data, validated and normalised;
   none of them can name a command.
3. **Deterministic automation** - decisions are rules over recorded evidence; no model decides on infrastructure.
4. **Verify, then commit** - success means the desired end state was observed.
5. **Reversible by default** - backups before change, automatic rollback, manual rollback for committed changes.
6. **Everything audited** - who, what, why, target, result, correlation ID.

## Roles

| Role | Can |
|---|---|
| VIEWER | read everything |
| OPERATOR | acknowledge/resolve incidents, revoke leases, release quarantine (decision-engine gated), snapshots, ChatOps test |
| ENGINEER | remediation, drift fixes, quarantine requests, chaos, change requests, approvals of HIGH_IMPACT |
| ADMIN | autonomy level, clock, policy activation/rollback, demo reset, CRITICAL approvals |

## Automation boundary

| Category | Automatic? |
|---|---|
| SAFE | yes (level ≥ 3) |
| REVERSIBLE | when automation confidence ≥ 80% |
| HIGH_IMPACT | only with an explicit security-policy permission or level 4 inside a change window |
| CRITICAL | no (approval; emergency policy disabled by default) |

Safety rails: command allowlist, preconditions re-checked at execution, duplicate and loop guards, mass-change guard,
protected assets, change windows, lockout protection for firewall changes, timeouts, crash recovery (transactions
running at controller restart are marked FAILED for human verification rather than resumed blindly).

## AI boundary

The operator assistant is a deterministic intent matcher that only issues read-only queries. See ADR-009.

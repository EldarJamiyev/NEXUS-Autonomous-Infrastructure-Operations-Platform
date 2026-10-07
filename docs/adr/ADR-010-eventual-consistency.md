# ADR-010: Eventual consistency

Status: Accepted (2026-10)

## Context

Observations, decisions and actions happen at different times; the firewall may be unreachable.

## Decision

Reconciliation loops converge reality toward intent. When an adapter is unavailable, changes are recorded as PENDING and replayed in RECOVERY mode; existing safe state is preserved.

## Consequences

Short windows of divergence are visible and explained (system mode banner) rather than hidden.

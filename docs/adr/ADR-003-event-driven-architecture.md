# ADR-003: Event-driven architecture

Status: Accepted (2026-10)

## Context

The console must update live and engines must react to observations without polling everything.

## Decision

An in-process bus with a transactional outbox: events are written with the state change and dispatched after commit. Configuration-change events trigger targeted reconciliation.

## Consequences

No phantom events on rollback. Single process today; the `EventBus` protocol allows Redis Streams later.

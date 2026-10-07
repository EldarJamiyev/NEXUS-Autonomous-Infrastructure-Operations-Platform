# ADR-002: Relational state model

Status: Accepted (2026-10)

## Context

Features such as access, risk, drift and incidents must reason over the same facts.

## Decision

One relational schema (SQLAlchemy 2, Alembic) holds identity, network, policy, risk, drift, incidents, transactions, audit, events and snapshots. SQLite for the demo, PostgreSQL by URL.

## Consequences

Joins answer cross-cutting questions (who is affected, why can X access Y). Schema migrations are required for changes. A graph database was considered; the graph is small enough to compute in memory from tables.

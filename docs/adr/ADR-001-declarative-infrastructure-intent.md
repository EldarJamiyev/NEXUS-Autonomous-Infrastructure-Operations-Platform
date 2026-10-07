# ADR-001: Declarative infrastructure intent

Status: Accepted (2026-10)

## Context

Operators need one place that says what infrastructure should look like, reviewable like code.

## Decision

Desired state is YAML in Git (`baselines/`, `policies/`). NEXUS imports files as versioned, checksummed policy versions and reconciles reality against the active versions. Runtime rollback activates a previous version; Git stays the source of truth.

## Consequences

Drift is objective (intent vs actual, with SHA-256 evidence). Changes are reviewable. Operators must commit intended changes or the next scan reports them as drift.

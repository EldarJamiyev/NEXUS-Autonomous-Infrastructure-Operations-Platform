# ADR-011: Idempotent operations

Status: Accepted (2026-10)

## Context

Retries and repeated alerts must not stack changes.

## Decision

Alerts de-duplicate by fingerprint; the decision engine skips duplicates of in-flight actions; loop and mass-change guards cap retries; preconditions are re-checked at execution; Ansible roles are idempotent.

## Consequences

Repeated runs converge instead of compounding. Every skip is recorded with its reason.

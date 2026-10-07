# ADR-006: Verification before commit

Status: Accepted (2026-10)

## Context

A zero exit code does not mean the service works.

## Decision

Every action verifies the desired end state with probes (process, port, HTTP, checksum, policy test, VLAN membership). Failure triggers rollback and verification of the original state.

## Consequences

Slower than fire-and-forget; far fewer false successes. The Fail remediation scenario demonstrates exit 0 followed by a verified rollback.

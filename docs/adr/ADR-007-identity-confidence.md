# ADR-007: Identity confidence

Status: Accepted (2026-10)

## Context

IP addresses do not identify people or devices; access decisions need corroboration.

## Decision

A weighted, configurable heuristic over AD computer object, AD session, DHCP hostname, DNS record, known MAC, expected VLAN and monitoring presence. Signals not applicable to a device kind are excluded from the denominator.

## Consequences

Explainable and tunable. Explicitly not a statistical model; weights are prototype values.

# ADR-004: Firewall adapter pattern

Status: Accepted (2026-10)

## Context

Vendor logic must not leak into the core, and the demo must run without a firewall.

## Decision

The core talks only to `FirewallAdapter` (create, delete, list, state, apply, verify, rollback). `MockFirewallAdapter` is the default; `PfSenseAdapter` is optional and marked experimental.

## Consequences

New vendors are adapters. The mock can be disconnected to exercise DEGRADED mode honestly.

# ADR-008: Simulation and real separation

Status: Accepted (2026-10)

## Context

The demo must be realistic without ever pretending to change real systems.

## Decision

A World object owns simulated physics; engines observe it only through adapters and probes, never through fault flags. Every page shows the environment; real-lab adapters are opt-in.

## Consequences

The same engines run in both modes. Simulation fidelity is bounded by the World model.

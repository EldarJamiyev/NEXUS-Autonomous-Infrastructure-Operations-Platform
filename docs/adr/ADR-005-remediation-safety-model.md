# ADR-005: Remediation safety model

Status: Accepted (2026-10)

## Context

Automation that runs arbitrary commands from alerts is a liability.

## Decision

A catalog of actions bound to validated command templates (argv, no shell) with preconditions, backup, verification, rollback and timeout. Alert text is never executed. Categories SAFE, REVERSIBLE, HIGH_IMPACT, CRITICAL drive human-in-the-loop rules.

## Consequences

New capabilities require catalog entries and tests. Some fixes stay manual by design (certificate renewal).

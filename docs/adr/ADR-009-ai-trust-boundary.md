# ADR-009: AI trust boundary

Status: Accepted (2026-10)

## Context

AI can help explain, but must not control infrastructure.

## Decision

All decisions are deterministic. The operator assistant is a rule-based intent matcher issuing read-only queries. If an LLM is added later it may only summarise the outputs of those read-only queries.

## Consequences

No hallucinated actions. Natural-language coverage is limited to supported intents.

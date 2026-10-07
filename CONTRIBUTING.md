# Contributing

## Development setup

```bash
make install        # backend (editable + dev tools) and frontend dependencies
make dev            # API on :8000, Vite on :5173
make check          # ruff, mypy, pytest, tsc, vitest - what CI runs
```

## Conventions

- Python: type hints everywhere, ruff and mypy clean, docstrings on modules and non-obvious functions.
- Every engine function takes `(ctx, db, ...)`; never `await` while holding a database session.
- Tests assert observable behaviour (state, events, verification results), not implementation details.
- Frontend: strict TypeScript, shared primitives in `components/ui.tsx`, data via `useApi` with `refreshOn`.
- Commits: imperative mood ("Add DHCP reclaim action"), one concern per commit.

## Adding a remediation action

1. Add the action to `backend/nexus/remediation/catalog.yaml` (category, risk, permission, preconditions,
   backup, execution, verification, rollback, timeout).
2. If it needs a new operation, add a validated template to `render()` and an implementation to
   `SimulatedExecutor` in `remediation/executor.py` (and the real-lab task in `ansible/playbooks/tasks/`).
3. Map an alert or drift class to it (`incidents/engine.py` `plan_for`, or `policies/server-baseline.yaml`).
4. Write a test that breaks the world, runs `process(ctx)` and asserts the verified end state.

## Adding a chaos scenario

Add an injection function and a `Scenario` entry in `backend/nexus/chaos/scenarios.py`. Scenarios may only
change the simulated World - never call NEXUS engines directly - so detection stays honest.

# Testing

```bash
cd backend && pytest -q          # 48 tests, about two minutes (each test gets a copy of a seeded template database)
cd frontend && npm test          # vitest unit tests
make check                       # ruff + mypy + pytest + tsc + vitest
```

The backend suite asserts behaviour, for example:

- an alert storm (DNS, AD logon failures, portal 503) becomes **one** P1 incident whose root cause is DNS;
- a remediation whose commands all exit 0 but whose verification fails is **rolled back**, the configuration checksum
  equals the backup and the next attempt needs approval (confidence fell below the threshold);
- an unknown device that probes SSH is quarantined, and the verification includes a firewall policy test that denies it;
- what-if leaves the captured state byte-for-byte unchanged;
- the command allowlist rejects `nginx; rm -rf /`, unapproved paths and unknown operations;
- duplicate remediation is skipped, healthy services are not restarted;
- events are dispatched only after commit and subscriber queues are bounded;
- backend RBAC (403 for lower roles), 401 without a token, 422 for invalid input, 429 under rate limiting;
- an Alertmanager alert for a healthy service is marked STALE and never acted on.

CI additionally validates Prometheus rules (promtool), Alertmanager config (amtool), Ansible syntax, builds the
Docker image and probes `/health` and the console. During development the console was exercised in headless
Chromium across all 24 pages with zero console errors.

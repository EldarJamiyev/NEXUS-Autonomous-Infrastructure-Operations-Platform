# Security policy

NEXUS OMNIS is a portfolio prototype. Run it locally or in an isolated lab, not on the internet.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository (Security → Advisories → New draft) or contact the
maintainer directly. Please include reproduction steps. Do not open public issues for vulnerabilities.

## Security design

| Control | Implementation |
|---|---|
| Authentication | HMAC-signed console tokens (12 h) or API keys (`NEXUS_API_KEYS=ROLE:key`). Demo login can be disabled. |
| Authorization | Roles VIEWER < OPERATOR < ENGINEER < ADMIN, enforced on every mutating endpoint server-side (`api/deps.py`). |
| Four-eyes | Approvers cannot approve their own requests; CRITICAL approvals need ADMIN. |
| Command safety | Strict allowlist of operation templates, validated parameters, argv lists (no shell), alert text never executed. |
| Input validation | Pydantic models on every request body; strict policy schemas reject unknown keys. |
| Rate limiting | Sliding-window limits on auth, chaos, remediation, webhook and policy endpoints (HTTP 429). |
| Secrets | Only from environment / `.env` (git-ignored). No secrets in the frontend bundle. ChatOps webhook URLs are never returned by the API. |
| Webhook trust | Alertmanager alerts are validated against observed state before any action; an optional bearer token can be required. |
| CSRF | Not applicable: the API uses bearer tokens in the `Authorization` header, not cookies. CORS is restricted to configured origins. |
| Audit | Every meaningful action records who, what, why, target, result, correlation ID. |
| Container | Non-root user (uid 10001), health check, no extra packages. |

## Known limitations

- SQLite is single-node; use PostgreSQL and backups for anything long-lived.
- No built-in TLS: put NEXUS behind a reverse proxy (Caddy, nginx, Traefik) with HTTPS.
- If `NEXUS_SECRET_KEY` is unset a random key is generated per start (tokens reset on restart).
- Real-lab adapters (pfSense, Ansible executor) hold powerful credentials; scope them to the lab and rotate them.

## Hardening checklist for a lab deployment

1. `NEXUS_DEMO_AUTH=false`, long random `NEXUS_SECRET_KEY` and API keys.
2. HTTPS reverse proxy; restrict `NEXUS_CORS_ORIGINS`.
3. `NEXUS_ALERTMANAGER_TOKEN` set and configured in Alertmanager.
4. Autonomy level 2 (Recommend) until runbooks are trusted.
5. Least-privilege service accounts for pfSense, AD inventory and Ansible.

The full threat model is in [docs/security/threat-model.md](docs/security/threat-model.md).

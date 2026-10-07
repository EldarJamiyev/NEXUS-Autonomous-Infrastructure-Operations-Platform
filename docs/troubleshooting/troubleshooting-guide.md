# Infrastructure troubleshooting guide

The interactive version is the **Troubleshooting** page: eleven guides (no Internet, cannot access server, AD login
failure, DNS failure, DHCP problem, SSH unavailable, Nginx unavailable, high disk usage, firewall block, unknown
device, configuration drift), each with symptoms, evidence to collect, likely causes, copyable commands, live NEXUS
checks against the current state, resolution and verification. The content lives in
`backend/nexus/operations/troubleshooting.py`.

Runbooks with read-only diagnostics and decision-engine-gated actions are on the **Runbooks** page (`runbooks/*.yaml`).

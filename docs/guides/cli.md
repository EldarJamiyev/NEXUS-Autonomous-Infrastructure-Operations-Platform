# CLI guide (`nexusctl`)

`nexusctl` talks to the API. Configure with `NEXUS_URL` (default http://localhost:8000), `NEXUS_API_TOKEN`
(or demo login as `NEXUS_USER`, default eldar). In Docker: `docker compose exec nexus nexusctl <command>`.

| Command | Purpose |
|---|---|
| `nexusctl status` | mode, autonomy, health, counts |
| `nexusctl selftest` | twelve component checks |
| `nexusctl devices list` / `users list` / `leases list` | inventories |
| `nexusctl risk PC-023` | risk score with every factor and its evidence |
| `nexusctl explain access eldar PC-023 LINUX01 22` | full access evaluation |
| `nexusctl drift scan` / `nexusctl drift remediate DRIFT-001` | reconcile and fix |
| `nexusctl incidents list` / `nexusctl incidents show INC-0001` | incidents and their Markdown report |
| `nexusctl policy validate [file]` / `diff` / `apply` / `rollback POL-ID` | policy lifecycle |
| `nexusctl network snapshot --label before-change` | Time Machine snapshot |
| `nexusctl whatif` / `nexusctl whatif vlan_down vlan=30` | read-only simulation |
| `nexusctl chaos list` / `nexusctl chaos run unknown-device` | inject and watch the stages |
| `nexusctl demo` / `demo blackout` / `demo reset` | guided demo, blackout report, reset |

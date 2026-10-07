# Chaos lab guide

Each scenario changes only the simulated World and records `FAILURE_INJECTED`. The run panel then shows what NEXUS
did: trigger, detection (with measured latency), incident, root cause, risk, decision, action, verification and final
state, plus the live event log. Scenarios marked **HUMAN STEP** end with a person by design; the panel offers the
simulated manual fix.

| Scenario | Expected NEXUS behaviour |
|---|---|
| Kill Nginx | NginxDown → SAFE restart → systemd + TCP/443 + HTTP 200 → resolved |
| Fill disk | DiskSpaceCritical → rotate the approved log set → usage < 85% |
| Break SSH config | SECURITY drift → restore baseline (backup, sshd -t, reload) → checksum = intent |
| Add firewall rule | CRITICAL drift → ruleset rollback → ANY→LINUX01:22 now DENY, management path intact |
| Create unknown device | identity ≈ 5%, admin-port attempts → risk > 80 → SECURITY-004 quarantine to VLAN 99 |
| Change VLAN | VLAN drift on PC-024 (APIPA address) → switchport restored → reserved address back |
| Break DNS | three symptoms → one P1 incident → DNS restart → symptoms clear |
| Break monitoring | node_exporter down → restart → scrape target up |
| Create DHCP conflict | rogue static claim on PC-024's IP → claimant quarantined, PC-024 untouched |
| Fail AD login | 12× 4625 → RepeatedAuthFailures → device risk exceeds lease threshold → lease revoked; human closes |
| Create policy conflict | draft grants GG-HR SSH → BASELINE_CONSTRAINT → activation rejected; human withdraws |
| Expire certificate | CertificateExpired → never auto-renewed → human renews |
| Fail remediation | restore + restart exit 0 → TCP/443 still dropped → verification fails → rollback → human fixes, approves retry |
| Disconnect firewall | DEGRADED → leases BLOCKED / PENDING (never SUCCESS) → reconnect → RECOVERY → replay |
| Database degraded | DEGRADED for 45 s → only SAFE actions automatic, snapshots deferred |
| DHCP exhaustion | pool 62/64 → reclaim stale leases → < 85% |
| Increase CPU | HighCPU → container restart is HIGH_IMPACT → approval → CPU < 80% and HTTP 200 |
| Break NTP | clock skew → restart W32Time + resync → offset < 1 s |
| Disable a service | DockerDown + services drift → re-enable → verified |
| Unreachable device | NodeDown on MON01, monitoring DEGRADED → no remote path → human power-cycles |
| Unexpected port | xrdp on APP01:3389 → containment rule → policy test DENY |
| **Blackout** | nine of the above within ~11 s → EMERGENCY mode → final incident report |

From the CLI: `nexusctl chaos list`, `nexusctl chaos run break-dns`, `nexusctl demo blackout`.

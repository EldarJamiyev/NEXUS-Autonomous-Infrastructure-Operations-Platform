# Threat model

Scope: the NEXUS control plane, its API and console, adapters, and the data it ingests. Method: for each threat,
impact, how NEXUS detects it, mitigations in this codebase, and remaining risk.

| Threat | Impact | Detection | Mitigation | Remaining risk |
|---|---|---|---|---|
| Compromised workstation | lateral movement to servers | failed-logon bursts, admin-port attempts, risk score, identity mismatch | session-bound leases, risk-gated revocation, default deny, quarantine policy | attacker using a legitimate active session within thresholds |
| Stolen credentials | access as a legitimate user | logon from unusual device (identity confidence), 4625 patterns | access requires an AD session on a high-confidence device; leases expire; four-eyes approvals | credential + device theft together |
| Malicious administrator | unauthorized firewall/config changes | drift vs Git intent, firewall syslog, audit trail | rollback to intent, approvals, audit; changes outside NEXUS are reported | an ADMIN can change NEXUS policy; Git review and audit are the control |
| Firewall tampering | exposure of admin services | unauthorized-rule drift (CRITICAL), shadow analysis | automatic verified rollback, management-path protection | change between reconciliation cycles (≤ 20 s, faster with syslog) |
| Configuration tampering | weakened hosts (e.g. root SSH) | FIM/agent reports, checksums | restore baseline with validation and rollback | agent itself disabled - monitored as missing reports / MonitoringAgentDown |
| API compromise | attacker drives remediation | audit log, rate-limit violations | RBAC, signed tokens, rate limits, allowlist (no arbitrary commands even for ADMIN) | full ADMIN token can change autonomy and policies |
| Database manipulation | false state, hidden incidents | checksums on snapshots/policy versions, audit gaps | DB access only from the NEXUS container; backups; PostgreSQL roles in production | host-level compromise of the DB file |
| Event spoofing (webhook) | trigger unwanted actions | alert validation against observed state | alerts never carry commands; STALE alerts discarded; optional bearer token; rate limits | spoofed alerts can still create noise incidents if state agrees |
| Identity spoofing | impersonate a trusted device | multi-signal confidence (AD object, DHCP hostname, DNS, MAC, VLAN) | no single signal is trusted; unknown identities never receive leases | MAC + hostname cloning on the right VLAN with a stolen session |
| DHCP spoofing / IP conflict | traffic interception | ARP shows two MACs for one IP | DHCP_CONFLICT incident, claimant risk, quarantine of unidentified claimant | rogue DHCP server (not modelled) |
| DNS manipulation | users redirected, AD broken | DNS consistency check (DHCP vs DNS vs AD), service probes | restart of verified-down DNS; mismatches raise uncertainty | poisoned but running DNS returning wrong answers |
| Controller compromise | attacker controls automation | NexusControllerDown alert, external monitoring | non-root container, no shell execution path, scoped adapter credentials, autonomy can be lowered | a compromised controller holds adapter credentials - isolate it and rotate keys |

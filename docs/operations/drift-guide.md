# Drift guide

Desired state: `baselines/*.yaml` (hosts inherit `linux-common`; `network.yaml` holds switchport intent) plus the
firewall intent (baseline rules + access-policy denies + active leases + NEXUS containment rules).

Actual state comes from host agents (simulated, or `ansible/roles/nexus-agent` in a real lab), the firewall adapter
and the switch. Native settings are **normalized** before comparison (`PermitRootLogin yes` → `permit_root_login: true`).

| Class | Examples | Default handling |
|---|---|---|
| CRITICAL | unauthorized permissive firewall rule | incident + REVERSIBLE ruleset rollback |
| SECURITY | PermitRootLogin, PasswordAuthentication, file modes, Windows baseline, wrong VLAN | incident + restore |
| OPERATIONAL | nginx, docker, monitoring, disabled services | restore (Docker restart is HIGH_IMPACT → approval) |
| COSMETIC | MOTD banner | report only |

Each drift record carries expected and actual SHA-256 checksums, a real unified diff in native syntax, the intent
source file and the remediation transaction. *Accept as intended* closes it - then update Git, or it returns on the
next scan. A manual rollback of a fix accepts the re-appearing drift for 15 minutes so NEXUS does not fight the operator.

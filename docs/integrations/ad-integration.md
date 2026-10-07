# Active Directory integration (real lab)

NEXUS uses one identity interface. In simulation the identity tables are seeded from `simulation/enterprise.yaml`;
in a real lab they are filled by two PowerShell scripts that push to the ingest API. The engines cannot tell the
difference - which is the point.

> Simulation is not a real AD environment. These scripts were syntax-checked with PowerShell 7 but not run
> against a live domain in this repository.

## Inventory (users, groups, computers)

On a management host with RSAT (`ActiveDirectory` module), using an ADMIN API key:

```powershell
$env:NEXUS_URL = 'https://nexus.corp.example'; $env:NEXUS_API_KEY = '<ADMIN key>'
.\powershell\Get-NexusADInventory.ps1                     # POST /api/ingest/ad-inventory
.\powershell\Get-NexusADInventory.ps1 -OutFile ad.json   # inspect first
```
New users get console role VIEWER; group memberships are mapped from `MemberOf`; computers mark matching devices
as AD-joined (an identity-confidence signal).

## Security events

Schedule on a domain controller (or a Windows Event Collector) every 5 minutes with an ENGINEER key:

```powershell
.\powershell\Get-NexusSecurityEvents.ps1 -Minutes 5      # POST /api/ingest/windows-events
```

| Event | NEXUS meaning |
|---|---|
| 4624 / 4634 / 4647 | session opened / closed (leases are session-bound and revoked at logoff) |
| 4625 | authentication failure (sub-status decoded: bad password, unknown user, locked out, no logon servers) |
| 4672 | privileged logon |
| 4720 / 4726 | account created / deleted |
| 4728 / 4729 / 4732 / 4733 | group membership added / removed (applied to `user_groups`) |

## Windows baseline

`Get-NexusWindowsBaseline.ps1` reports the settings in `baselines/dc01.yaml` (SMBv1, firewall profiles, RDP NLA,
password length, logon auditing, lockout threshold). `Test-NexusWindowsBaseline.ps1` exits 1 on drift.
`Invoke-NexusWindowsRemediation.ps1 -Setting <all|smb1|firewall|nla|audit|password> [-WhatIf]` restores settings,
backing up previous values to `%ProgramData%\NEXUS\backups` first.

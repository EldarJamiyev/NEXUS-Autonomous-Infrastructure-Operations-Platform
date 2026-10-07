# Policy guide

Policies live in `policies/*.yaml` and are validated by strict schemas (unknown keys fail). Kinds:
`AccessPolicy`, `FirewallPolicy`, `SecurityPolicy`, `BaselinePolicy`, `AutomationPolicy`, `IdentitySignals`, `RiskRules`.

## Access policy

```yaml
apiVersion: nexus.omnis/v1
kind: AccessPolicy
metadata: {id: POL-IT-ADMIN, name: IT administration access, owner: GG-IT}
spec:
  subjects: {groups: [GG-NETWORK-ADMIN, GG-SYSTEM-ADMIN]}
  conditions: {min_identity_confidence: 80, max_device_risk: 50, max_user_risk: 60, source_vlans: [30], device_kinds: [workstation]}
  grants:
    - {destinations: [LINUX01, APP01, MON01], protocol: TCP, ports: [22], lease_minutes: 30, max_lease_minutes: 240}
    - {destinations: [PFSENSE], protocol: TCP, ports: [443], lease_minutes: 15, approval: always}
  denies:
    - {destinations: [ANY], protocol: TCP, ports: [3389], reason: example explicit deny}
  schedule:
    windows: [{days: [mon, tue, wed, thu, fri], start: "08:00", end: "18:00"}]
    outside: approval_required        # or deny
```

Evaluation order: session on the device, quarantine, explicit denies, grants, baseline constraints (for example
`ssh_allowed_groups`), identity confidence, device and user risk, source VLAN, device type, firewall availability,
schedule, approval. The **Explain** buttons call the same evaluator.

## Compiler

`GET /api/policies/compile` runs schema validation, normalization, conflict detection (grant/deny overlap and
baseline constraints - the latter are blocking), impact analysis, risk analysis, firewall rule generation and
verification (default deny last, management path preserved, duplicates, **shadowed rules**). The repository ships
one intentional finding: HR's deny on APP01:8443 is shadowed by the legacy broad rule FW-130.

## Lifecycle

1. Edit the YAML in Git and open a pull request.
2. Policies page → *Draft & validate* or `nexusctl policy validate file.yaml`; *Simulate impact* shows who gains or loses access.
3. ADMIN: *Apply from Git* (`nexusctl policy apply`) creates new versions; invalid files are REJECTED.
4. Roll back with the Policies page or `nexusctl policy rollback POL-ID` - and revert the commit.

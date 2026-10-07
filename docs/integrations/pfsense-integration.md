# pfSense integration (optional, experimental)

The core only knows the `FirewallAdapter` interface (`create_rule`, `delete_rule`, `list_rules`, `get_state`,
`apply_policy`, `verify_rule`, `rollback`). `MockFirewallAdapter` is the default. `PfSenseAdapter`
(`backend/nexus/firewall/pfsense.py`) targets the community **pfSense REST API package v2**.

> Status: written against the published API, **not exercised against a live pfSense in this repository**.
> Test it in an isolated lab first.

```bash
NEXUS_ENV=real-lab
NEXUS_FIREWALL_ADAPTER=pfsense
PFSENSE_URL=https://10.10.10.1
PFSENSE_API_KEY=<key with firewall rule privileges only>
PFSENSE_VERIFY_TLS=true
PFSENSE_INTERFACE_MAP=10:lan,20:opt1,30:opt2,40:opt3,50:opt4,99:opt5
```

Behaviour:

- Only rules whose description starts with `NEXUS:` are created, changed or deleted. Human-made rules are listed
  and analysed (drift, shadowing) but never touched by `apply_policy`.
- Every change is followed by `POST /api/v2/firewall/apply` and verified by listing the rules again.
- API failures raise `FirewallUnavailable`: leases become PENDING, the system mode turns DEGRADED, and pending
  changes are replayed when the API returns.

Lockout protection: the compiler refuses a ruleset that would block the management path
(`management_path` in `policies/firewall-baseline.yaml`), and firewall remediations verify that path afterwards.

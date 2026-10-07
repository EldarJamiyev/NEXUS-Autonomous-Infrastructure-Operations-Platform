# Interview questions and answers

Answers reference the actual implementation so you can open the code while explaining.

## Purpose and positioning

**1. Why did you build this?**
To automate the loop I kept seeing in IT operations: alert, investigate, fix, verify, write up. Most tools stop at
"something is red". I wanted a system that works out why, who is affected, whether a fix is safe, and proves the fix
worked - while staying explainable and conservative.

**2. What real problem does it solve?**
Repetitive incidents (a stopped service, a full disk, a reverted config, an unauthorised firewall rule) consume
engineer time and are often fixed inconsistently. NEXUS handles the safe ones automatically with a full audit trail,
correlates alert storms into one incident, and escalates the rest with evidence attached.

**3. Why isn't this just Ansible?**
Ansible applies desired state when you run it. NEXUS decides *when* to act and *whether* it is safe: it observes
continuously, correlates symptoms, scores risk, applies human-in-the-loop rules, verifies outcomes and rolls back.
Ansible is one possible executor underneath it (`AnsibleExecutor`, `remediate.yml`).

**4. Why isn't this just monitoring?**
Monitoring tells you something crossed a threshold. NEXUS validates the alert against current state, finds the root
cause through the dependency graph, decides on an action, executes it through an allowlist and verifies the result.
It consumes monitoring (Alertmanager webhook) rather than replacing it.

**5. Why not use a NAC product?**
NAC controls admission to the network. NEXUS reuses that idea (identity confidence, quarantine VLAN) but ties it to
the same state as service health, drift and incidents, so a quarantine decision, a lease and an outage share context.
In a real environment I would integrate with NAC rather than compete with it.

**6. What is simulated and what is real?**
The enterprise (hosts, services, AD data, firewall ruleset) is simulated by default. The engines, API, console,
transactions, verification logic and safety rails are real code paths. Real-lab adapters exist for pfSense, AD
(PowerShell push), Ansible execution, network probes and Prometheus, but they were not exercised against live equipment.

**7. What would you change for production?**
PostgreSQL with replication, a durable message bus (Redis Streams/NATS) behind the existing `EventBus` protocol,
SSO (OIDC) instead of demo tokens, secrets in a vault, HTTPS, horizontal API workers with a single elected remediation
leader, signed policy commits, and canary rollouts of new remediation actions.

## Access and identity

**8. Why use temporary leases?**
Standing firewall rules accumulate and nobody removes them. A lease is scoped (user, device, destination, port),
time-limited, bound to the AD session, revoked when risk rises, and every rule has an owner and an expiry.

**9. What happens if DHCP changes an IP?**
Leases are bound to the session and source IP. When the session ends (4634/4647) the lease is revoked. A new
address means a new evaluation and a new lease; the firewall rule for the old IP is removed and its absence verified.

**10. Why isn't an IP address enough for identity?**
IPs are reassigned, spoofable and shared. Identity confidence combines AD computer object, AD user session, DHCP
hostname, DNS record, known MAC, expected VLAN and monitoring presence, and excludes signals that don't apply to a
device type.

**11. How does identity correlation work?**
The chain user → group → session → device → IP → MAC → VLAN → switch port is built from 4624 events, DHCP and ARP
observations and switchport state. `identity/confidence.py` computes earned weight over applicable weight; levels run
from TRUSTED (≥95) to UNKNOWN (<40).

**12. How does an access decision work?**
`policy/evaluator.py` checks, in order: an active AD session for that user on that device, quarantine, explicit denies,
a matching grant, baseline constraints (e.g. `ssh_allowed_groups`), identity confidence, device and user risk against
the policy's thresholds, source VLAN, device type, firewall availability, schedule and grant approval. The explanation
is the list of those checks, so it cannot disagree with the decision.

**13. Why can't Aysel access port 22?**
She is in GG-FINANCE; POL-FINANCE explicitly denies administrative protocols, and no policy grants TCP/22 to her
groups. The Access page and `nexusctl explain access aysel PC-024 LINUX01 22` show the exact check that failed.

**14. What happens outside business hours?**
POL-IT-ADMIN's schedule returns APPROVAL_REQUIRED outside 08:00-18:00 site time. The lease is created as
PENDING_APPROVAL and a different engineer must approve it (four-eyes rule enforced server-side).

## Risk

**15. How does risk work?**
It is a sum of explained factors: asset criticality, identity level, open drift by class, unexpected listeners,
admin-protocol attempts from unidentified devices, open incidents, DHCP conflicts, failed logons, privileged sessions,
active leases, unmanaged status and a trust deficit; quarantine subtracts containment. Levels: ≥80 CRITICAL, ≥60 HIGH, ≥30 MEDIUM.

**16. Why isn't the risk score AI?**
Because operators must be able to verify and challenge it. Every point has a rule and evidence. Weights are prototype
values in `policies/risk-rules.yaml`; a learned model would be harder to audit and would need data I don't have.

**17. What is trust decay?**
Trust drops once per distinct cause (minor anomaly -5, identity mismatch -15, critical incident -30) and recovers +1
per clean reconciliation cycle. A device that misbehaved doesn't look pristine seconds later.

## Remediation and safety

**18. How do you prevent lockout?**
The policy compiler rejects rulesets that block the management path (`management_path` in the firewall baseline), every
firewall remediation verifies that path afterwards, infrastructure devices are protected from automatic quarantine,
and SSH changes are validated with `sshd -t` before reload.

**19. How does rollback work?**
Actions declare a backup type (config, firewall ruleset, network state, service state). The runner stores the backup
before executing; if validation or verification fails it restores the backup and verifies the original state
(configuration checksum, ruleset checksum or VLAN). Stateless actions report rollback NOT APPLICABLE and escalate.

**20. How do you verify remediation?**
With probes for the desired end state, not exit codes: systemd state, TCP reachability, HTTP status, config checksum
against Git intent, firewall policy tests, VLAN membership, DNS lookups, NTP offset. The Fail remediation scenario shows
exit 0 followed by a failed TCP/443 probe and an automatic rollback.

**21. How do you avoid executing dangerous commands?**
Alerts never contain commands. Actions reference catalog templates; parameters are validated against enums, ranges or
patterns and rendered as argv lists without a shell. `render()` rejects unknown operations and `nginx; rm -rf /`.

**22. How do you avoid duplicate remediation?**
Alert fingerprints de-duplicate repeated alerts; the decision engine returns SKIPPED_DUPLICATE when the same action is
already planned or running on the target; preconditions are re-checked at execution, so a service that recovered is not restarted.

**23. How does idempotency work?**
Reconciliation converges toward intent rather than replaying steps, Ansible roles are idempotent, firewall
`apply_policy` compares rule keys before changing anything, and repeated decisions are absorbed by the duplicate and loop guards.

**24. When does NEXUS ask a human?**
For HIGH_IMPACT and CRITICAL actions, REVERSIBLE actions below 80% confidence, any action at autonomy ≤ 2, protected
assets, changes outside the maintenance window, a mass-change burst, or when no safe action exists.

**25. What is automation confidence?**
Evidence completeness: the catalog's base value minus penalties for an unvalidated alert, medium/low root-cause
confidence, missing verification, and failed attempts in the last 24 hours. After one failed fix, the same fix drops
below the threshold and needs approval.

**26. What happens if verification fails and rollback fails too?**
The transaction ends as FAILED with rollback FAILED, the incident is marked human-required, a ChatOps AUTOHEAL FAILED
message is recorded and the audit record carries the details. NEXUS never reports success.

## Drift and policy

**27. How do you detect drift?**
Desired state from `baselines/*.yaml` and the compiled firewall intent is compared with normalised actual state from
host agents, the firewall and the switch. Differences are classified, checksummed (SHA-256) and stored with a real diff.

**28. How do you distinguish drift from an authorised change?**
Authorised changes go through Git (then the intent changes), maintenance mode (drift is EXPECTED and reviewed when the
window ends), an operator accepting the drift, or a manual rollback (accepted for 15 minutes). Everything else is drift.

**29. How do you detect a shadowed firewall rule?**
The compiler resolves aliases and groups to networks and checks, for each rule, whether an earlier rule covers its
source, destination, protocol and ports. A covering rule with a different action makes the later rule unreachable -
the repository's HR deny on APP01:8443 is shadowed by FW-130.

**30. How are policy conflicts handled?**
Grant/deny overlaps are warnings (deny wins). Grants that violate baseline constraints are blocking: the policy set does
not compile and a draft is REJECTED. The Chaos Lab policy-conflict scenario demonstrates it.

## Incidents

**31. How does root cause work?**
Deterministically. Candidates are the symptom services plus failing upstream dependencies. Each is scored: observed
failure +40, explains all symptoms through the graph +30, recent non-NEXUS config change +20, failed validation +10,
earliest symptom +10, failing dependencies -25. HIGH ≥ 70, MEDIUM ≥ 45.

**32. How does correlation turn an alert storm into one incident?**
New alerts in the availability family attach to an open incident if the dependency graph connects their services within
a 10-minute window. A DNS outage, AD logon failures and a portal 503 become one P1 with DNS as root cause.

**33. How is priority set?**
An impact × urgency matrix. Impact: critical asset, users or services affected. Urgency: alert severity or risk ≥ 80.
P1 requires high on both.

**34. How do you avoid falsely claiming a root cause for recurring failures?**
Recurrence (≥3 in 7 days) is flagged with a recommended investigation list and an explicit note that recurrence is a
pattern, not a cause.

**35. What does an incident report contain?**
Summary, severity, priority, affected assets and users, timeline, root cause and evidence, risk evolution, drift,
decisions, every remediation step with commands and verification, rollback status, ChatOps, final state and recommendations.

## Architecture and reliability

**36. Why one process?**
For a prototype it keeps state consistent and the demo trivial to run. The seams for splitting exist: the event bus
protocol, adapters, and engines that are plain functions over a session.

**37. How do you handle concurrency with SQLite?**
All loops run on one asyncio event loop; each unit of work is a short synchronous transaction, and nothing awaits while
a session is open. That removes lock contention and makes ordering deterministic.

**38. How do events reach the UI?**
Engines insert events in the same transaction as the state change; an `after_commit` hook dispatches them to bounded
subscriber queues; the WebSocket endpoint forwards them. Rolled-back work emits nothing.

**39. What happens if pfSense is unavailable?**
The adapter raises FirewallUnavailable; leases are recorded as PENDING or BLOCKED, the mode becomes DEGRADED with the
reason and current behaviour, existing state is preserved, and pending changes are replayed in RECOVERY.

**40. What happens if NEXUS itself fails?**
Infrastructure keeps running - NEXUS is not in the data path. On restart, transactions that were mid-flight are marked
FAILED for human verification instead of being resumed blindly; Prometheus alerts on `NexusControllerDown`.

**41. What happens during split-brain?**
Today there is one controller. With several, only an elected leader (database advisory lock) may run remediation, so the
duplicate guard stays authoritative; followers observe and serve the API.

**42. How would you scale this?**
PostgreSQL, Redis Streams for events, stateless API workers, partitioned detection per site, a single remediation leader
per site, and collectors pushing observations to the ingest API.

**43. How does the time machine reconstruct history?**
Snapshots capture devices, users, services, VLANs, firewall, leases, policies, risk, drift and incidents on every state
change (debounced) and periodically. A point in time is the latest snapshot before it plus the recorded events after it;
comparison lists added, removed and changed entities.

**44. How is what-if kept read-only?**
It computes impact from the current tables without writing; the test suite captures state before and after a simulation
and asserts they are identical.

## Integrations

**45. How would you connect a real firewall?**
Implement `FirewallAdapter` for the vendor. The pfSense adapter manages only rules tagged `NEXUS:`, applies and re-lists
after each change, and reports unavailability instead of guessing.

**46. How would you connect AD?**
Push from Windows: `Get-NexusADInventory.ps1` for users/groups/computers and `Get-NexusSecurityEvents.ps1` for 4624,
4625, 4634, 4647, 4672, 4720, 4726, 4728, 4729, 4732 and 4733. Push avoids giving NEXUS domain credentials.

**47. How does Prometheus fit in?**
NEXUS exports metrics; rules with the same names as its detector fire to Alertmanager, which posts to NEXUS. NEXUS
validates and de-duplicates them, so either source can detect a failure without double incidents.

**48. How does ChatOps avoid false claims?**
Without a webhook every message is stored as DRY_RUN; with one, delivery status and errors are recorded per message.

## Security

**49. How is the API secured?**
Signed tokens or API keys, server-side RBAC on every mutating endpoint, Pydantic validation, rate limits, CORS limits,
no secrets in the frontend, audit of every action, and no endpoint that executes free-form commands.

**50. What is the AI trust boundary?**
No AI makes infrastructure decisions. The assistant maps questions to read-only queries deterministically. An LLM could
summarise those read-only results later, but would never gain write access.

**51. How do you handle a spoofed Alertmanager webhook?**
Alerts are validated against observed state - an alert claiming Nginx is down while it serves HTTP 200 is marked STALE
and ignored - and a bearer token can be required. Alerts never carry actions.

**52. What is the biggest risk in this design?**
The controller holds adapter credentials. Mitigations: scoped keys, non-root container, no shell path, autonomy levels,
and isolation of the controller network.

## Engineering process

**53. How did you test it?**
48 backend tests that break the simulated world and assert outcomes (one incident for an alert storm, rollback after
exit 0, quarantine verified by policy test, read-only what-if, RBAC, rate limits), frontend unit tests, strict typing,
and headless-browser checks of all pages. CI also builds and boots the Docker image.

**54. What bugs did testing catch?**
An unquoted comma in YAML flow mappings silently dropped the firewall baseline - the strict schema exposed it, and the
lockout check then correctly refused to commit firewall fixes. Over-eager correlation merged unrelated findings on the
same host; a planner read labels from the wrong alert. Each is now covered by a test.

**55. What are you proudest of, and what would you do next?**
That it is honest: verification instead of exit codes, PENDING instead of fake success, labelled heuristics. Next: run
it against a real lab (pfSense, AD, two Ubuntu servers), add OIDC, PostgreSQL and a durable bus, and measure
detection-to-verified-fix times on real failures.

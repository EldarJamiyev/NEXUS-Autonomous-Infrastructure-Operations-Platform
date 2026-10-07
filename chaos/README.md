# Chaos scenarios

Generated from `backend/nexus/chaos/scenarios.py` - the scenarios only change the simulated World; NEXUS does the rest.

## Kill Nginx (`kill-nginx`)

Kill the nginx master process on LINUX01.

- **trigger:** SIGKILL to nginx
- **events:** process exits, HTTPS stops
- **detection:** NginxDown via process + TCP/443 probe
- **risk:** portal users affected
- **decision:** SAFE restart, automatic
- **action:** systemctl restart nginx
- **verification:** systemd active + TCP/443 + HTTP 200
- **final state:** incident resolved, ChatOps AUTOHEAL EVENT

## Fill disk (`fill-disk`)

A runaway log fills /var on APP01.

- **trigger:** log growth
- **events:** /var reaches 96%
- **detection:** DiskSpaceCritical
- **risk:** capacity incident
- **decision:** SAFE log rotation
- **action:** logrotate -f /etc/logrotate.d/portal
- **verification:** usage below 85%
- **final state:** resolved; no arbitrary deletion

## Break SSH config (`break-ssh-config`)

Enable PermitRootLogin on LINUX01 by hand.

- **trigger:** manual edit
- **events:** FIM reports sshd_config change
- **detection:** drift vs Git intent (SECURITY)
- **risk:** LINUX01 risk rises
- **decision:** REVERSIBLE restore, confidence 91%
- **action:** backup, write baseline, sshd -t, reload
- **verification:** config checksum = intent, TCP/22 open
- **final state:** COMPLIANT, rollback available

## Add firewall rule (`add-firewall-rule`)

Someone adds ALLOW ANY -> LINUX01:22 directly on pfSense.

- **trigger:** webConfigurator change
- **events:** pfSense syslog
- **detection:** unauthorized rule vs intent (CRITICAL)
- **risk:** risk HIGH
- **decision:** REVERSIBLE rollback, confidence 94%
- **action:** backup ruleset, remove rule
- **verification:** ruleset = intent, ANY->LINUX01:22 now DENY, management path intact
- **final state:** rollback verified

## Create unknown device (`unknown-device`)

Plug an unidentified endpoint into a user port; it probes SSH.

- **trigger:** new MAC on Gi1/0/14
- **events:** DHCP, ARP, failed DNS/AD correlation, TCP/22 attempts
- **detection:** identity confidence collapses
- **risk:** risk becomes CRITICAL
- **decision:** SECURITY-004 permits automatic quarantine (unmanaged endpoint)
- **action:** move port to VLAN 99, revoke leases
- **verification:** VLAN 99 + policy test DENY
- **final state:** incident mitigated

## Change VLAN (`change-vlan`)

PC-024's switchport is moved to the server VLAN.

- **trigger:** switch CLI change
- **events:** PC-024 falls back to APIPA
- **detection:** VLAN drift vs network intent + identity drop
- **risk:** risk rises
- **decision:** REVERSIBLE switchport restore
- **action:** switchport access vlan 30
- **verification:** device back in VLAN 30 with its reserved address
- **final state:** compliant

## Break DNS (`break-dns`)

Stop the DNS Server service on DC01.

- **trigger:** DNS service stops
- **events:** DNS down, AD logon failures, portal 503 (alert storm)
- **detection:** three symptoms correlated into ONE incident
- **risk:** P1
- **decision:** SAFE restart of a verified-down service
- **action:** Restart-Service DNS
- **verification:** service running, TCP/53, lookups succeed
- **final state:** all symptoms clear

## Break monitoring (`break-monitoring`)

node_exporter on APP01 is OOM-killed.

- **trigger:** agent exits
- **events:** scrape target down
- **detection:** MonitoringAgentDown
- **risk:** low
- **decision:** SAFE restart
- **action:** systemctl restart prometheus-node-exporter
- **verification:** scrape target up
- **final state:** resolved

## Create DHCP conflict (`dhcp-conflict`)

A rogue device statically claims PC-024's address.

- **trigger:** static IP claim
- **events:** ARP shows two MACs for 10.30.30.43
- **detection:** DHCP conflict + unknown identity
- **risk:** claimant risk CRITICAL
- **decision:** SECURITY-004 quarantine of the claimant
- **action:** move claimant to VLAN 99
- **verification:** claimant isolated
- **final state:** PC-024 keeps its address

## Fail AD login (`fail-ad-login`)

Repeated failed logons for aysel from PC-025.

- **trigger:** 12x Event 4625
- **events:** authentication failure burst
- **detection:** RepeatedAuthFailures
- **risk:** PC-025 risk rises above lease thresholds
- **decision:** no automatic account action (human)
- **action:** lease from PC-025 revoked by risk gate
- **verification:** access re-evaluated
- **final state:** human required

## Create policy conflict (`policy-conflict`)

A draft policy grants GG-HR SSH, violating the server baseline.

- **trigger:** draft submitted
- **events:** compiler runs schema/conflict checks
- **detection:** BASELINE_CONSTRAINT conflict
- **risk:** policy risk
- **decision:** activation blocked
- **action:** none - drafts never auto-apply
- **verification:** conflict reported
- **final state:** human required

## Expire certificate (`expire-certificate`)

The portal TLS certificate expires.

- **trigger:** notAfter passes
- **events:** certificate monitor
- **detection:** CertificateExpired
- **risk:** user-facing TLS errors
- **decision:** NEVER auto-renewed in the demo
- **action:** human renews via CA
- **verification:** certificate valid
- **final state:** human required

## Fail remediation (`fail-remediation`)

A bad deploy plus a hidden host firewall rule makes the fix fail verification.

- **trigger:** bad deploy + nftables drop
- **events:** config change then nginx stops
- **detection:** RCA: config change 0-2 s before failure
- **risk:** HIGH
- **decision:** REVERSIBLE restore baseline
- **action:** restore + nginx -t + restart (exit 0)
- **verification:** TCP/443 still unreachable -> VERIFICATION FAILED
- **final state:** ROLLBACK to backup, AUTOHEAL FAILED, human required

## Disconnect firewall (`disconnect-firewall`)

pfSense API becomes unreachable for 60 s.

- **trigger:** API timeout
- **events:** adapter raises FirewallUnavailable
- **detection:** FirewallUnreachable
- **risk:** mode DEGRADED
- **decision:** preserve state, block new privileged leases
- **action:** lease requests -> BLOCKED/PENDING, never fake SUCCESS
- **verification:** reconnect, replay PENDING
- **final state:** RECOVERY -> NORMAL

## Database degraded (`database-degraded`)

NEXUS state store latency spikes for 45 s.

- **trigger:** latency
- **events:** self-test and mode engine
- **detection:** DEGRADED
- **risk:** automation restricted
- **decision:** only SAFE actions automatic, snapshots deferred
- **action:** -
- **verification:** degradation expires
- **final state:** RECOVERY -> NORMAL

## DHCP exhaustion (`dhcp-exhaustion`)

VLAN 30 pool fills with expired leases.

- **trigger:** pool 62/64
- **events:** DHCP utilisation
- **detection:** DHCPPoolExhausted
- **risk:** new devices cannot join
- **decision:** SAFE reclaim
- **action:** dhcpd reclaim-expired
- **verification:** pool below 85%
- **final state:** resolved

## Increase CPU (`increase-cpu`)

A portal worker loops at ~97% CPU.

- **trigger:** request loop
- **events:** sustained CPU
- **detection:** HighCPU (3 samples)
- **risk:** portal latency
- **decision:** HIGH_IMPACT container restart -> APPROVAL
- **action:** docker restart portal (after approval)
- **verification:** CPU < 80% + HTTP 200
- **final state:** resolved after human approval

## Break NTP (`break-ntp`)

W32Time stops on DC01 and the clock drifts.

- **trigger:** service stop
- **events:** clock offset grows
- **detection:** NTPClockSkew
- **risk:** Kerberos at risk
- **decision:** SAFE restart + resync
- **action:** Restart-Service W32Time; w32tm /resync
- **verification:** offset < 1 s
- **final state:** resolved

## Disable a service (`disable-service`)

docker is disabled on LINUX01.

- **trigger:** systemctl disable --now
- **events:** unit disabled + stopped
- **detection:** DockerDown + services drift
- **risk:** operational
- **decision:** REVERSIBLE re-enable
- **action:** systemctl enable --now docker
- **verification:** enabled + running + config = intent
- **final state:** resolved

## Unreachable device (`unreachable-device`)

MON01 stops answering.

- **trigger:** host fault
- **events:** no ARP/ICMP
- **detection:** NodeDown
- **risk:** monitoring blind spot -> DEGRADED
- **decision:** no remote path: human required
- **action:** operator power-cycles host
- **verification:** host answers
- **final state:** resolved

## Unexpected port (`unexpected-port`)

xrdp starts listening on APP01:3389.

- **trigger:** package install
- **events:** agent reports new listener
- **detection:** UnexpectedService
- **risk:** APP01 risk rises
- **decision:** REVERSIBLE containment rule
- **action:** DENY NET_USERS -> APP01:3389
- **verification:** policy test DENY, management path intact
- **final state:** mitigated, investigate why xrdp appeared

## Run blackout (`blackout`)

Inject nine faults at once and watch NEXUS detect, correlate, prioritise and remediate them.

- **trigger:** nine simultaneous faults
- **events:** dozens of events
- **detection:** correlated incidents (DNS alert storm becomes one)
- **risk:** EMERGENCY mode
- **decision:** dependency-ordered decisions
- **action:** restarts, rollbacks, quarantine, containment
- **verification:** per-action verification
- **final state:** final incident report

# Simulation guide

The simulated enterprise is defined in `simulation/enterprise.yaml`: six VLANs, nine devices (pfSense, core switch,
DC01, LINUX01, APP01, MON01, three workstations), four users, six groups, eighteen services with dependencies,
certificates, host configurations and disk usage. All names and data are fictional.

## How it behaves

- `simulation/world.py` owns actual state: service processes, configuration files, switch ports, DHCP pools and
  hidden faults. It validates nginx and sshd configs like the real tools would (`nginx -t`, `sshd -t`).
- Metrics (CPU, memory, traffic, latency) are deterministic functions of time with per-device phase, so charts look
  alive but runs are reproducible.
- Downstream symptoms are generated: while DNS or AD is down, workstations log 0xC000005E logon failures; the portal
  answers 503 when its dependencies fail; a stopped W32Time makes the clock drift.
- NEXUS learns about changes through observations - monitoring probes, FIM-style configuration events, DHCP/ARP and
  firewall syslog - never by reading the World's fault flags.

## History

On first start `simulation/history.py` replays a week on a shifted clock using the real engines: Nginx failures
(one that needed a human after a failed fix), an unauthorized firewall rule, SSH drift, disk pressure, a monitoring
outage, leases that expire and get revoked, a pending Docker change awaiting approval and a cosmetic MOTD drift.
Simulated time advances by the detection interval and the step pacing so the recorded timings are realistic.

## Changing the enterprise

Edit `simulation/enterprise.yaml` and the matching `baselines/*.yaml`, then reset the demo. Keep YAML values that
contain commas quoted - flow mappings split on commas (the strict policy schema catches this for policies).

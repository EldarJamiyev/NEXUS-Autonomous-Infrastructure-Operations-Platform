# Real lab deployment

The basic demo needs no real infrastructure. To connect a lab (Windows Server 2022 AD, Ubuntu servers, pfSense,
Prometheus/Grafana, Windows and Linux clients):

1. **Isolate it.** Use a lab network; never point NEXUS at production.
2. **Secure NEXUS.** `NEXUS_ENV=real-lab`, `NEXUS_DEMO_AUTH=false`, a long `NEXUS_SECRET_KEY`, API keys per role,
   HTTPS reverse proxy, `NEXUS_ALERTMANAGER_TOKEN`. Start at **autonomy level 2 (Recommend)**.
3. **Describe intent.** Replace `simulation/enterprise.yaml` inventory and `baselines/` with your hosts; keep the
   same keys. Commit to Git.
4. **Identity.** Run `Get-NexusADInventory.ps1` once, then schedule `Get-NexusSecurityEvents.ps1` every 5 minutes.
5. **Configuration observation.** Apply `ansible/playbooks/site.yml` (installs the nexus-agent timer).
6. **Monitoring.** Scrape your exporters; route alerts to `/api/alerts/alertmanager`.
7. **Firewall (optional).** Enable `PfSenseAdapter` with a key scoped to firewall rules. Watch the Network page:
   human rules are reported (and shadowing analysed) but never changed.
8. **Remediation (optional).** `NEXUS_EXECUTOR=ansible` with an inventory and a least-privilege service account.
   Raise autonomy to 3 only after the runbooks behaved correctly at level 2.

What stays simulated even in a lab: the Chaos Lab (refuses to run outside SIMULATION) and the demo reset.

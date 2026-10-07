# Monitoring integration

`docker compose --profile observability up --build` adds Prometheus, Alertmanager, Grafana, Loki and Promtail.

## Closed loop

1. NEXUS exports `/metrics`: control-plane gauges (`nexus_open_incidents`, `nexus_active_leases`, `nexus_risk_score`,
   `nexus_quarantined_devices`, `nexus_drift_events`, `nexus_policy_conflicts`, `nexus_controller_health`, counters for
   remediation success/failure, a histogram of event dispatch latency) and simulated-world gauges
   (`nexus_sim_service_up`, `nexus_sim_disk_used_percent`, `nexus_sim_node_reachable`, `nexus_sim_cpu_percent`,
   `nexus_sim_cert_days_remaining`).
2. `prometheus/rules/nexus-alerts.yml` defines NodeDown, DiskSpaceCritical, NginxDown, SSHDown, MonitoringAgentDown,
   CertificateExpiring, UnexpectedFirewallRule, ConfigurationDrift, HighRiskDevice, UnknownDevice and NexusControllerDown.
3. Alertmanager posts to `POST /api/alerts/alertmanager`. NEXUS validates each alert against current state (stale
   alerts are discarded), de-duplicates it with its internal detector (same alert names and fingerprint), and
   ignores rules labelled `source="nexus-self"`, which exist for routing NEXUS's own findings to humans.

Validated with `promtool check rules`, `promtool check config` and `amtool check-config`.

## Grafana

Eight provisioned dashboards (folder "NEXUS OMNIS"): Overview, Risk, Incidents, Remediation, Network, Identity,
Leases, Infrastructure Health. Regenerate with `make dashboards`.

## Logs

NEXUS writes structured JSON logs to stdout and `/data/logs/nexus.log`; Promtail ships the file to Loki with `level`
and `logger` labels. Example: `{job="nexus"} | json | event="REMEDIATION_COMPLETED"`.

## Real hosts

Point Prometheus at node_exporter / windows_exporter and rename or relabel alerts so `alertname` matches the NEXUS
vocabulary and a `device` label carries the inventory hostname.

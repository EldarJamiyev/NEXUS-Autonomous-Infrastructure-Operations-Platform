# Ansible integration

`ansible/` contains idempotent roles that enforce the same intent as `baselines/`:

| Role | Enforces |
|---|---|
| common | chrony, unattended upgrades, logrotate, login banner |
| security | `/etc/shadow` and `sshd_config` modes, kernel network hardening |
| ssh | `sshd_config` from the baseline, validated with `sshd -t` before replacement, reload handler |
| monitoring | node_exporter on the baseline port |
| docker | `daemon.json` (live-restore, log limits) |
| nexus-agent | read-only host agent: reports `sshd -T`, unit enablement and `daemon.json` to `/api/ingest/config-report` every 5 min |

Playbooks: `site.yml`, `baseline.yml`, `drift-remediation.yml` (`-e component=ssh`), `monitoring.yml`,
`recovery.yml`, and `remediate.yml` - the entry point for NEXUS's optional `AnsibleExecutor`
(`NEXUS_EXECUTOR=ansible`). `remediate.yml` asserts that the requested operation is in its own allowlist before
including the matching task file, so the allowlist is enforced twice (NEXUS templates, then Ansible).

```bash
cd ansible
ansible-playbook playbooks/baseline.yml --check --diff      # preview
NEXUS_AGENT_API_KEY=<ENGINEER key> ansible-playbook playbooks/site.yml
```

All playbooks pass `ansible-playbook --syntax-check` (also run in CI). They were not applied to live hosts in this repository.

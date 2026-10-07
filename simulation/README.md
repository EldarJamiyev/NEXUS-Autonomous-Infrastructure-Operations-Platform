# Simulated enterprise

`enterprise.yaml` defines the fictional organisation NEXUS manages in SIMULATION mode: VLANs, devices, switch ports,
users, groups, services, dependencies, certificates, host configurations and disks. It is loaded by
`backend/nexus/simulation/seed.py`; the physics live in `world.py`. See [docs/operations/simulation-guide.md](../docs/operations/simulation-guide.md).
Quote YAML values that contain commas.

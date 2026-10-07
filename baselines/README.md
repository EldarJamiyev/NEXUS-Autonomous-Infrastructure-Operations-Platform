# Baselines (Git-controlled desired state)

One file per host (`server:`), templates via `inherits:`, switchport intent in `network.yaml`. NEXUS compares these
with observed state; changes here are infrastructure changes - review them like code. Guide: [docs/operations/drift-guide.md](../docs/operations/drift-guide.md).

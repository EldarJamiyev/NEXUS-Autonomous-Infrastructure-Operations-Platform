"""Alert vocabulary shared by the internal detector, Prometheus rules and Alertmanager webhooks."""

from __future__ import annotations

from typing import Any

ALERTS: dict[str, dict[str, Any]] = {
    "NginxDown": {"category": "SERVICE", "severity": "high", "service": "nginx", "title": "Nginx service failure on {target}"},
    "SSHDown": {"category": "SERVICE", "severity": "high", "service": "ssh", "title": "SSH unavailable on {target}"},
    "DNSServiceDown": {"category": "SERVICE", "severity": "critical", "service": "dns", "title": "DNS service failure on {target}"},
    "ADAuthenticationFailures": {"category": "IDENTITY", "severity": "high", "service": "ad-ds", "title": "Authentication failures against AD on {target}"},
    "PortalHealthCheckFailed": {"category": "APPLICATION", "severity": "high", "service": "portal", "title": "Intranet portal health check failing"},
    "MonitoringAgentDown": {"category": "MONITORING", "severity": "warning", "service": "monitoring-agent", "title": "Monitoring agent down on {target}"},
    "DockerDown": {"category": "SERVICE", "severity": "high", "service": "docker", "title": "Docker engine down on {target}"},
    "NTPClockSkew": {"category": "SERVICE", "severity": "high", "service": "ntp", "title": "Clock skew on {target} threatens Kerberos"},
    "DiskSpaceCritical": {"category": "CAPACITY", "severity": "high", "title": "Disk space critical on {target}"},
    "HighCPU": {"category": "CAPACITY", "severity": "warning", "title": "Sustained high CPU on {target}"},
    "NodeDown": {"category": "AVAILABILITY", "severity": "critical", "title": "{target} unreachable"},
    "CertificateExpiring": {"category": "SECURITY", "severity": "warning", "title": "Certificate expiring on {target}"},
    "CertificateExpired": {"category": "SECURITY", "severity": "high", "title": "Certificate expired on {target}"},
    "DHCPPoolExhausted": {"category": "NETWORK", "severity": "high", "title": "DHCP pool nearly exhausted ({target})"},
    "DHCPConflict": {"category": "SECURITY", "severity": "high", "title": "DHCP/IP address conflict involving {target}"},
    "UnexpectedService": {"category": "SECURITY", "severity": "high", "title": "Unexpected service listening on {target}"},
    "UnexpectedFirewallRule": {"category": "SECURITY", "severity": "critical", "title": "Unauthorized firewall change on {target}", "planned_by": "drift"},
    "ConfigurationDrift": {"category": "SECURITY", "severity": "high", "title": "Configuration drift on {target}", "planned_by": "drift"},
    "UnexpectedDriftAfterMaintenance": {"category": "CONFIGURATION", "severity": "warning", "title": "Unexpected drift after maintenance on {target}", "planned_by": "drift"},
    "UnknownDevice": {"category": "SECURITY", "severity": "warning", "title": "Unknown device {target} on the network"},
    "HighRiskDevice": {"category": "SECURITY", "severity": "high", "title": "High-risk unidentified device {target}"},
    "RepeatedAuthFailures": {"category": "SECURITY", "severity": "high", "title": "Repeated authentication failures from {target}"},
    "PolicyConflict": {"category": "POLICY", "severity": "warning", "title": "Policy conflict blocks activation of {target}"},
    "FirewallUnreachable": {"category": "AVAILABILITY", "severity": "high", "title": "Firewall management API unreachable"},
}
AVAILABILITY_FAMILY = {"SERVICE", "APPLICATION", "IDENTITY", "AVAILABILITY", "MONITORING"}


def meta(name: str) -> dict[str, Any]:
    return ALERTS.get(name, {"category": "GENERAL", "severity": "warning", "title": name + " on {target}"})


def family(category: str) -> str:
    return "AVAILABILITY" if category in AVAILABILITY_FAMILY else category

CORRELATION_GROUPS = {"UnknownDevice": "identity", "HighRiskDevice": "identity", "DHCPConflict": "identity",
                      "ConfigurationDrift": "drift", "UnexpectedFirewallRule": "drift", "UnexpectedDriftAfterMaintenance": "drift"}


def correlation_group(name: str) -> str:
    return CORRELATION_GROUPS.get(name, name)

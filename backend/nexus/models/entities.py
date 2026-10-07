"""Relational infrastructure state model.

Every NEXUS feature reads and writes these tables; there is no separate per-feature store.
String primary keys are the identifiers operators actually use (PC-023, INC-0001, LEASE-99182).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from nexus.models.base import Base


class Counter(Base):
    __tablename__ = "counters"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime | None]


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(128))
    department: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(128), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    console_role: Mapped[str] = mapped_column(String(16), default="VIEWER")
    ad_dn: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime]


class Group(Base):
    __tablename__ = "groups"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(String(256), default="")
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)


class UserGroup(Base):
    __tablename__ = "user_groups"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)


class Vlan(Base):
    __tablename__ = "vlans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    subnet: Mapped[str] = mapped_column(String(32))
    gateway: Mapped[str] = mapped_column(String(32))
    purpose: Mapped[str] = mapped_column(String(128), default="")
    dhcp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    dhcp_pool_size: Mapped[int] = mapped_column(Integer, default=0)
    dhcp_in_use: Mapped[int] = mapped_column(Integer, default=0)
    dhcp_stale: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="up")


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))  # firewall|switch|server|workstation|unknown
    os: Mapped[str] = mapped_column(String(64), default="")
    role: Mapped[str] = mapped_column(String(128), default="")
    vlan_id: Mapped[int | None] = mapped_column(ForeignKey("vlans.id"), nullable=True, index=True)
    expected_vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    owner_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="healthy")
    managed: Mapped[bool] = mapped_column(Boolean, default=True)
    ad_computer: Mapped[bool] = mapped_column(Boolean, default=False)
    expected_hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    dns_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    identity_confidence: Mapped[int] = mapped_column(Integer, default=0)
    identity_level: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    identity_signals: Mapped[dict[str, Any]] = mapped_column(default=dict)
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantine_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    pre_quarantine_vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reachable: Mapped[bool] = mapped_column(Boolean, default=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(default=dict)
    expected_ports: Mapped[list[Any]] = mapped_column(default=list)
    observed_ports: Mapped[list[Any]] = mapped_column(default=list)
    sim_faults: Mapped[dict[str, Any]] = mapped_column(default=dict)  # simulation physics only
    location: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(String(256), default="")
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]


class Interface(Base):
    __tablename__ = "interfaces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    switch_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(32))
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mode: Mapped[str] = mapped_column(String(16), default="access")
    status: Mapped[str] = mapped_column(String(16), default="up")
    speed_mbps: Mapped[int] = mapped_column(Integer, default=1000)


class IpAddress(Base):
    __tablename__ = "ip_addresses"
    address: Mapped[str] = mapped_column(String(45), primary_key=True)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assignment: Mapped[str] = mapped_column(String(16), default="static")
    dhcp_hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires: Mapped[datetime | None]
    conflict_macs: Mapped[list[Any]] = mapped_column(default=list)
    updated_at: Mapped[datetime]


class MacAddress(Base):
    __tablename__ = "mac_addresses"
    address: Mapped[str] = mapped_column(String(17), primary_key=True)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    vendor: Mapped[str] = mapped_column(String(64), default="")
    known: Mapped[bool] = mapped_column(Boolean, default=False)
    interface_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_active_user", "active", "user_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    logon_type: Mapped[str] = mapped_column(String(32), default="Interactive")
    source: Mapped[str] = mapped_column(String(64), default="ad-security-log")
    started_at: Mapped[datetime]
    ended_at: Mapped[datetime | None]
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    active_version: Mapped[int | None] = mapped_column(Integer, nullable=True)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    author: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime]
    checksum: Mapped[str] = mapped_column(String(64))
    content: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))  # ACTIVE|SUPERSEDED|DRAFT|REJECTED|INACTIVE
    note: Mapped[str] = mapped_column(String(256), default="")
    source: Mapped[str] = mapped_column(String(32), default="git")


class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(8))
    source: Mapped[str] = mapped_column(String(64))
    destination: Mapped[str] = mapped_column(String(64))
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(String(256), default="")
    origin: Mapped[str] = mapped_column(String(32))  # baseline|lease|policy|quarantine|manual
    lease_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime]
    created_by: Mapped[str] = mapped_column(String(64), default="nexus")


class Lease(Base):
    __tablename__ = "leases"
    __table_args__ = (Index("ix_leases_status_expires", "status", "expires_at"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64), index=True)
    device_id: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[str] = mapped_column(String(45))
    destination_id: Mapped[str] = mapped_column(String(64))
    protocol: Mapped[str] = mapped_column(String(8), default="TCP")
    port: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String(256), default="")
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(24))  # PENDING|PENDING_APPROVAL|ACTIVE|EXPIRED|REVOKED|DENIED
    firewall_state: Mapped[str] = mapped_column(String(16), default="NONE")  # APPLIED|PENDING|REMOVED|NONE|FAILED
    firewall_rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_at_grant: Mapped[int] = mapped_column(Integer, default=0)
    identity_confidence_at_grant: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    ended_at: Mapped[datetime | None]
    end_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class RiskScore(Base):
    __tablename__ = "risk_scores"
    entity_type: Mapped[str] = mapped_column(String(16), primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    level: Mapped[str] = mapped_column(String(16), default="LOW")
    trust: Mapped[int] = mapped_column(Integer, default=90)
    factors: Mapped[list[Any]] = mapped_column(default=list)
    trust_marks: Mapped[list[Any]] = mapped_column(default=list)
    updated_at: Mapped[datetime]


class RiskEvent(Base):
    __tablename__ = "risk_events"
    __table_args__ = (Index("ix_risk_events_entity", "entity_type", "entity_id", "ts"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime]
    entity_type: Mapped[str] = mapped_column(String(16))
    entity_id: Mapped[str] = mapped_column(String(64))
    old_score: Mapped[int] = mapped_column(Integer)
    new_score: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String(256))
    trust: Mapped[int | None] = mapped_column(Integer, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # name@DEVICE
    name: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(128))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), default="systemd")
    unit: Mapped[str] = mapped_column(String(64), default="")
    ports: Mapped[list[Any]] = mapped_column(default=list)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running|stopped|failed|degraded
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    criticality: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    consumers: Mapped[str] = mapped_column(String(16), default="none")  # all_users|lease_holders|operators|none
    rto_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rpo_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    health_detail: Mapped[str] = mapped_column(String(256), default="")
    last_change: Mapped[datetime | None]


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (UniqueConstraint("source_id", "target_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(String(256), default="")


class ConfigItem(Base):
    __tablename__ = "config_items"
    id: Mapped[str] = mapped_column(String(96), primary_key=True)  # DEVICE:component
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    component: Mapped[str] = mapped_column(String(32))
    actual: Mapped[dict[str, Any]] = mapped_column(default=dict)
    checksum: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime]
    updated_by: Mapped[str] = mapped_column(String(64), default="baseline")


class Certificate(Base):
    __tablename__ = "certificates"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64))
    service_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    issuer: Mapped[str] = mapped_column(String(128), default="NEXUS-LAB-CA")
    not_after: Mapped[datetime]


class DriftEvent(Base):
    __tablename__ = "drift_events"
    __table_args__ = (Index("ix_drift_status_device", "status", "device_id"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(64))
    component: Mapped[str] = mapped_column(String(32))
    key: Mapped[str] = mapped_column(String(128))
    desired: Mapped[Any] = mapped_column(JSON, nullable=True)
    actual: Mapped[Any] = mapped_column(JSON, nullable=True)
    classification: Mapped[str] = mapped_column(String(16))
    risk: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24))
    remediation_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transaction_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    desired_checksum: Mapped[str] = mapped_column(String(64))
    actual_checksum: Mapped[str] = mapped_column(String(64))
    diff: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(128), default="")
    during_maintenance: Mapped[bool] = mapped_column(Boolean, default=False)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detected_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None]


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    target: Mapped[str] = mapped_column(String(64), index=True)
    service_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    labels: Mapped[dict[str, Any]] = mapped_column(default=dict)
    summary: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16))  # FIRING|RESOLVED|STALE
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    validation_note: Mapped[str] = mapped_column(String(256), default="")
    count: Mapped[int] = mapped_column(Integer, default=1)
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    resolved_at: Mapped[datetime | None]


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_status_created", "status", "created_at"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    priority: Mapped[str] = mapped_column(String(4))
    status: Mapped[str] = mapped_column(String(16))  # OPEN|INVESTIGATING|MITIGATED|RESOLVED|FALSE_POSITIVE
    risk: Mapped[int] = mapped_column(Integer, default=0)
    root_cause: Mapped[str | None] = mapped_column(String(256), nullable=True)
    root_cause_entity: Mapped[str | None] = mapped_column(String(96), nullable=True)
    root_cause_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    root_cause_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    affected_users: Mapped[list[Any]] = mapped_column(default=list)
    affected_devices: Mapped[list[Any]] = mapped_column(default=list)
    affected_services: Mapped[list[Any]] = mapped_column(default=list)
    impact: Mapped[dict[str, Any]] = mapped_column(default=dict)
    triage: Mapped[dict[str, Any]] = mapped_column(default=dict)
    recommendations: Mapped[list[Any]] = mapped_column(default=list)
    recurring: Mapped[dict[str, Any]] = mapped_column(default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(64), index=True)
    detection_source: Mapped[str] = mapped_column(String(64))
    human_required: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    correlation_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    mitigated_at: Mapped[datetime | None]
    resolved_at: Mapped[datetime | None]


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime]
    stage: Mapped[str] = mapped_column(String(24))
    message: Mapped[str] = mapped_column(String(512))
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)


class Decision(Base):
    __tablename__ = "decisions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ts: Mapped[datetime]
    trigger: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(64), index=True)
    action_id: Mapped[str] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(16))
    risk: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    policy: Mapped[dict[str, Any]] = mapped_column(default=dict)
    impact: Mapped[dict[str, Any]] = mapped_column(default=dict)
    safety: Mapped[dict[str, Any]] = mapped_column(default=dict)
    confidence_breakdown: Mapped[list[Any]] = mapped_column(default=list)
    reasons: Mapped[list[Any]] = mapped_column(default=list)
    transaction_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    result: Mapped[str | None] = mapped_column(String(32), nullable=True)


class RemediationTransaction(Base):
    __tablename__ = "remediation_transactions"
    __table_args__ = (Index("ix_tx_target_action", "target", "action_id", "status"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(64))
    action_name: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(64))
    params: Mapped[dict[str, Any]] = mapped_column(default=dict)
    trigger: Mapped[str] = mapped_column(String(128))
    category: Mapped[str] = mapped_column(String(16))
    risk: Mapped[str] = mapped_column(String(16))
    automation_confidence: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24))
    result: Mapped[str | None] = mapped_column(String(24), nullable=True)
    steps: Mapped[list[Any]] = mapped_column(default=list)
    pre_state: Mapped[dict[str, Any]] = mapped_column(default=dict)
    backup: Mapped[dict[str, Any]] = mapped_column(default=dict)
    post_state: Mapped[dict[str, Any]] = mapped_column(default=dict)
    commands: Mapped[list[Any]] = mapped_column(default=list)
    verification: Mapped[list[Any]] = mapped_column(default=list)
    rollback_available: Mapped[bool] = mapped_column(Boolean, default=False)
    rollback_status: Mapped[str] = mapped_column(String(24), default="NOT_NEEDED")
    human_action: Mapped[str] = mapped_column(String(16), default="NOT_REQUIRED")
    decision_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    drift_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    requested_by: Mapped[str] = mapped_column(String(64), default="AUTOHEAL")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime]
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # remediation|lease|change
    title: Mapped[str] = mapped_column(String(256))
    target: Mapped[str] = mapped_column(String(64))
    action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transaction_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lease_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    change_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    category: Mapped[str] = mapped_column(String(16))
    risk: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(512))
    required_role: Mapped[str] = mapped_column(String(16), default="ENGINEER")
    status: Mapped[str] = mapped_column(String(16))  # PENDING|APPROVED|REJECTED|EXPIRED
    requested_by: Mapped[str] = mapped_column(String(64))
    requested_at: Mapped[datetime]
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None]
    note: Mapped[str] = mapped_column(String(512), default="")
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ChangeRequest(Base):
    __tablename__ = "change_requests"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    change_type: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict[str, Any]] = mapped_column(default=dict)
    requested_by: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24))
    impact: Mapped[dict[str, Any]] = mapped_column(default=dict)
    window: Mapped[str] = mapped_column(String(64), default="")
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    actor: Mapped[str] = mapped_column(String(64))
    actor_type: Mapped[str] = mapped_column(String(16))  # SYSTEM|AUTOHEAL|OPERATOR|SIMULATION|INTEGRATION
    action: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(String(512))
    target: Mapped[str] = mapped_column(String(64), index=True)
    result: Mapped[str] = mapped_column(String(16))
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    transaction_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    type: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    source: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(String(512))
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)


class StateSnapshot(Base):
    __tablename__ = "state_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    reason: Mapped[str] = mapped_column(String(128))
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
    checksum: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ChatOpsEvent(Base):
    __tablename__ = "chatops_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(index=True)
    provider: Mapped[str] = mapped_column(String(16))
    kind: Mapped[str] = mapped_column(String(32))  # AUTOHEAL_EVENT|AUTOHEAL_FAILED|ESCALATION|INCIDENT|TEST|APPROVAL
    title: Mapped[str] = mapped_column(String(256))
    body: Mapped[str] = mapped_column(Text)
    fields: Mapped[dict[str, Any]] = mapped_column(default=dict)
    delivery_status: Mapped[str] = mapped_column(String(16))  # SENT|FAILED|DRY_RUN|QUEUED
    error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ChaosRun(Base):
    __tablename__ = "chaos_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16))  # INJECTING|OBSERVING|COMPLETED|HUMAN_REQUIRED
    targets: Mapped[list[Any]] = mapped_column(default=list)
    injections: Mapped[list[Any]] = mapped_column(default=list)
    requested_by: Mapped[str] = mapped_column(String(64))
    report_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))  # incident|demo|blackout|handover|brief
    title: Mapped[str] = mapped_column(String(256))
    subject: Mapped[str | None] = mapped_column(String(64), nullable=True)
    markdown: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime]
    created_by: Mapped[str] = mapped_column(String(64), default="NEXUS")

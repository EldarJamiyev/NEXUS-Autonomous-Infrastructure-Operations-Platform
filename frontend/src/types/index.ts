export interface LiveEvent { id: number; ts: string; type: string; severity: string; source: string; target: string | null; user_id?: string | null; message: string; data?: Record<string, unknown>; correlation_id: string | null; phase: string }
export interface MetricPoint { ts: string; cpu: number | null; mem: number | null; net: number | null; latency: number | null }
export interface RiskFactor { key: string; label: string; points: number; evidence: string }
export interface ServiceRef { id: string; name: string; status: string }
export interface Device {
  id: string; kind: string; os: string; role: string; vlan: number | null; ip: string | null; mac: string | null; status: string; criticality: string; managed: boolean;
  identity_confidence: number; identity_level: string; quarantined: boolean; reachable: boolean; risk: number; risk_level: string; trust: number; owner: string | null;
  location: string; metrics: Record<string, any>; last_seen: string; services: ServiceRef[]; open_incidents: number;
}
export interface Incident {
  id: string; title: string; category: string; severity: string; priority: string; status: string; risk: number; root_cause: string | null; root_cause_entity: string | null;
  root_cause_kind: string | null; root_cause_confidence: string | null; target: string; detection_source: string; human_required: boolean; correlation_id: string;
  created_at: string; updated_at: string; resolved_at: string | null; mttr_seconds: number | null; counts: Record<string, number>; recurring: Record<string, any>;
  evidence?: string[]; affected_users?: string[]; affected_devices?: string[]; affected_services?: string[]; impact?: Record<string, any>; triage?: Record<string, any>;
  recommendations?: string[]; summary?: string;
}
export interface TxStep { name: string; status: string; ts: string | null; detail: string }
export interface Probe { probe: string; passed: boolean; detail: string }
export interface Transaction {
  id: string; action_id: string; action_name: string; target: string; params: Record<string, any>; trigger: string; category: string; risk: string; automation_confidence: number;
  status: string; result: string | null; steps: TxStep[]; commands: any[]; verification: Probe[]; rollback_available: boolean; rollback_status: string; human_action: string;
  decision_id: string | null; incident_id: string | null; drift_id: string | null; approval_id: string | null; correlation_id: string | null; requested_by: string;
  error: string | null; created_at: string; started_at: string | null; finished_at: string | null; duration_ms: number | null; backup?: Record<string, any>; pre_state?: Record<string, any>;
  decision?: Decision | null;
}
export interface Decision {
  id: string; ts: string; trigger: string; target: string; action_id: string; outcome: string; category: string; risk: string; confidence: number; evidence: string[];
  policy: Record<string, any>; impact: Record<string, any>; safety: Record<string, any>; confidence_breakdown: { factor: string; points: number }[]; reasons: string[];
  transaction_id: string | null; incident_id: string | null; result: string | null;
}
export interface Drift {
  id: string; device_id: string; component: string; key: string; desired: any; actual: any; classification: string; risk: number; status: string; remediation_action: string | null;
  transaction_id: string | null; incident_id: string | null; desired_checksum: string; actual_checksum: string; checksum_match: boolean; diff: string; source: string;
  during_maintenance: boolean; detected_at: string; resolved_at: string | null;
}
export interface Lease {
  id: string; user_id: string; device_id: string; source_ip: string; destination: string; protocol: string; port: number; reason: string; policy_id: string | null; status: string;
  firewall_state: string; firewall_rule_id: string | null; created_at: string; expires_at: string; created_local: string; expires_local: string; remaining_seconds: number;
  end_reason: string | null; approval_id: string | null; risk_at_grant: number; identity_confidence_at_grant: number;
}
export interface DemoState {
  status: string; scene: number; total: number; steps: string[]; elapsed: number; report_id: string | null;
  current: { number: number; step: number; step_title: string; title: string; narrative: string; page: string } | null;
  log: { t: number; scene?: number; text: string; ok?: boolean }[];
}
export interface ModeState { mode: string; reasons: string[]; behaviors: string[]; since?: string | null }
export interface Status {
  product: string; version: string; environment: string; mode: ModeState; autonomy: { level: number; name: string }; clock: Record<string, any>;
  health: { counts: Record<string, number>; percent: Record<string, number>; total: number; health_percent: number; services_up: number; services_total: number; services_down: number };
  counts: Record<string, number>; global_risk: number; scorecard: Record<string, any>; maintenance: Record<string, any>; firewall: { adapter: string; available: boolean; mode: string };
  chatops: { provider: string; configured: boolean }; demo: DemoState | null; live: boolean;
}

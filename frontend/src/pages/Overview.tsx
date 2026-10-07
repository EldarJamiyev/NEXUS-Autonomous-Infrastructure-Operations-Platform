import { Link, useNavigate } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import type { Device, Incident, LiveEvent, Status, Transaction } from "@/types";
import { Panel, PageHeader, Pill, Risk, Skeleton, ErrorBox, Empty, EntityLink, cx } from "@/components/ui";
import { EventStream } from "@/components/live";
import { RemediationTimeline } from "@/components/timeline";
import { WhyButton } from "@/components/explain";
import { DistributionBar } from "@/charts/MetricChart";
import { type Topology } from "@/graph/TopologyGraph";
import { TopologyMap } from "@/graph/TopologyMap";
import { ago, dur, riskTone, TONE_TEXT, type Tone } from "@/lib/format";

type OverviewData = Status & { recent_incidents: Incident[]; recent_remediations: Transaction[]; top_risk: { id: string; score: number; level: string; factors: { label: string; points: number }[] }[]; recent_events: LiveEvent[]; devices: Device[] };

function Instrument({ label, value, tone = "neutral", to, hint }: { label: string; value: string | number; tone?: Tone; to?: string; hint?: string }) {
  const body = (
    <div className="min-w-0 px-3 py-2">
      <div className="truncate text-[11.5px] text-muted">{label}</div>
      <div className={cx("font-cond text-[26px] font-semibold leading-8 num", tone === "neutral" ? "text-ink" : TONE_TEXT[tone])}>{value}</div>
      {hint && <div className="truncate text-[11px] text-muted">{hint}</div>}
    </div>
  );
  return to ? <Link to={to} className="block hover:bg-inset">{body}</Link> : body;
}

export default function Overview() {
  const navigate = useNavigate();
  const { data, error, reload } = useApi<OverviewData>("/api/overview", { refreshOn: ["INCIDENT", "REMEDIATION", "DRIFT", "QUARANTINE", "LEASE", "RISK", "SYSTEM_MODE", "USER_LOG", "ALERT"] });
  const { data: topo } = useApi<Topology>("/api/network?services=false", { refreshOn: ["INCIDENT", "QUARANTINE", "DEVICE_DISCOVERED", "REMEDIATION_COMPLETED", "RISK"] });
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (!data) return <Skeleton rows={10} />;
  const c = data.counts;
  const h = data.health;
  const sc = data.scorecard;
  return (
    <div className="space-y-4">
      <PageHeader title="Infrastructure overview" description="What is healthy, what is broken, what changed, who is affected - and what NEXUS is doing about it."
        meta={<><Pill tone="auto">Autonomy {data.autonomy.level} · {data.autonomy.name}</Pill><Pill value={data.maintenance.window} /><span className="text-xs text-muted">Next window {data.maintenance.next}</span></>} />
      <div className="grid grid-cols-2 divide-x divide-y divide-line overflow-hidden rounded-md border border-line bg-panel sm:grid-cols-5 xl:grid-cols-10 xl:divide-y-0">
        <Instrument label="System health" value={`${h.health_percent}%`} tone={h.health_percent >= 90 ? "ok" : h.health_percent >= 70 ? "warn" : "crit"} hint={`${h.services_up}/${h.services_total} services up`} to="/devices" />
        <Instrument label="Global risk" value={data.global_risk} tone={riskTone(data.global_risk)} to="/risk" />
        <Instrument label="Devices" value={c.devices} to="/devices" />
        <Instrument label="Users" value={c.users} to="/identity" />
        <Instrument label="Active sessions" value={c.active_sessions} to="/identity" />
        <Instrument label="Active leases" value={c.active_leases} to="/access" />
        <Instrument label="Open incidents" value={c.open_incidents} tone={c.open_incidents ? "crit" : "ok"} to="/incidents" />
        <Instrument label="Drift events" value={c.drift_events} tone={c.drift_events ? "warn" : "ok"} to="/drift" />
        <Instrument label="Quarantined" value={c.quarantined} tone={c.quarantined ? "auto" : "neutral"} to="/twin" />
        <Instrument label="AutoHeal (24 h)" value={c.automated_remediations} tone="auto" hint={c.pending_approvals ? `${c.pending_approvals} awaiting approval` : "verified fixes"} to="/autoheal" />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        <Panel title="Infrastructure health" className="xl:col-span-3">
          <DistributionBar parts={[{ label: "Healthy", value: h.counts.healthy, color: "bg-ok" }, { label: "Warning", value: h.counts.warning, color: "bg-warn" },
            { label: "Critical", value: h.counts.critical, color: "bg-crit" }, { label: "Quarantined", value: h.counts.quarantined, color: "bg-accent" }]} />
          <dl className="mt-4 space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-muted">Firewall control plane</dt><dd><Pill value={data.firewall.available ? "AVAILABLE" : "UNAVAILABLE"} tone={data.firewall.available ? "ok" : "crit"} /></dd></div>
            <div className="flex justify-between"><dt className="text-muted">Adapter</dt><dd className="font-mono text-xs">{data.firewall.adapter}</dd></div>
            <div className="flex justify-between"><dt className="text-muted">ChatOps</dt><dd><Pill value={data.chatops.configured ? data.chatops.provider.toUpperCase() : "DRY_RUN"} /></dd></div>
            <div className="flex justify-between"><dt className="text-muted">Site time</dt><dd className="font-mono text-xs">{data.clock.site_time}{data.clock.acceleration !== 1 ? ` ×${data.clock.acceleration}` : ""}</dd></div>
          </dl>
          <div className="mt-4 border-t border-line pt-3">
            <h3 className="mb-2 text-xs font-medium text-muted">Highest risk</h3>
            <ul className="space-y-1.5">{data.top_risk.map((r) => (
              <li key={r.id} className="flex items-center justify-between gap-2"><EntityLink kind="device" id={r.id} /><span className="flex items-center gap-2"><Risk score={r.score} compact /><WhyButton path={`/api/explain/risk/device/${r.id}`} /></span></li>
            ))}</ul>
          </div>
        </Panel>
        <Panel title="Global infrastructure graph" subtitle="Live state from the backend. Select a device to open it." className="xl:col-span-5" bodyClass="p-3"
          actions={<Link to="/twin" className="text-xs text-info hover:underline">Full digital twin</Link>}>
          {topo ? <TopologyMap topology={topo} onSelect={(n) => navigate(`/devices/${n.id}`)} /> : <Skeleton rows={8} />}
        </Panel>
        <Panel title="Live event stream" className="xl:col-span-4" bodyClass="max-h-[392px] overflow-y-auto px-3 py-2">
          <EventStream initial={data.recent_events} limit={50} />
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        <Panel title="Recent incidents" className="xl:col-span-7" actions={<Link to="/incidents" className="text-xs text-info hover:underline">All incidents</Link>} bodyClass="p-0">
          {data.recent_incidents.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-inset text-xs text-muted"><tr>{["Incident", "Priority", "Asset", "Root cause", "Status", "When"].map((x) => <th key={x} className="px-3 py-2 font-medium">{x}</th>)}</tr></thead>
                <tbody>{data.recent_incidents.map((i) => (
                  <tr key={i.id} className="cursor-pointer border-t border-line hover:bg-inset" onClick={() => navigate(`/incidents/${i.id}`)}>
                    <td className="px-3 py-1.5"><div className="font-mono text-xs text-info">{i.id}</div><div className="max-w-[260px] truncate">{i.title}</div></td>
                    <td className="px-3"><Pill value={i.priority} /></td>
                    <td className="px-3 font-mono text-xs">{i.target}</td>
                    <td className="max-w-[240px] truncate px-3 text-xs text-muted" title={i.root_cause ?? ""}>{i.root_cause ?? "-"}</td>
                    <td className="px-3"><Pill value={i.status} />{i.human_required && i.status !== "RESOLVED" && <Pill tone="warn" className="ml-1">HUMAN</Pill>}</td>
                    <td className="whitespace-nowrap px-3 text-xs text-muted">{ago(i.created_at)}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          ) : <div className="p-4"><Empty title="No incidents" /></div>}
        </Panel>
        <Panel title="AutoHeal scorecard" subtitle={`${sc.label} · last 24 h · measured from this database, not real-world claims`} className="xl:col-span-5">
          <dl className="grid grid-cols-3 gap-x-4 gap-y-3">
            {([["Alerts received", sc.alerts_received], ["Auto-resolved", sc.auto_resolved], ["Human-required", sc.human_required],
               ["Remediation success", sc.remediation_success_pct === null ? "-" : `${sc.remediation_success_pct}%`], ["Rollbacks", sc.rollbacks], ["False positives", sc.false_positives],
               ["Mean detection", dur(sc.mean_detection_seconds)], ["Mean remediation", dur(sc.mean_remediation_seconds)], ["Mean verification", dur(sc.mean_verification_seconds)],
               ["Open incidents", sc.open_incidents], ["Active leases", sc.active_leases], ["Quarantined", sc.quarantined_devices]] as [string, unknown][]).map(([k, v]) => (
              <div key={k}><dt className="text-[11.5px] text-muted">{k}</dt><dd className="font-cond text-xl font-semibold num">{String(v ?? "-")}</dd></div>
            ))}
          </dl>
        </Panel>
      </div>

      {data.recent_remediations[0] && (
        <Panel title="Latest automated action" actions={<Link to={`/autoheal?tx=${data.recent_remediations[0].id}`} className="text-xs text-info hover:underline">Open transaction</Link>}>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
            <span className="font-mono text-xs">{data.recent_remediations[0].id}</span><span className="font-medium">{data.recent_remediations[0].action_name}</span>
            <span className="text-muted">on</span><EntityLink kind="device" id={data.recent_remediations[0].target} /><Pill value={data.recent_remediations[0].status} />
            <span className="text-xs text-muted">{data.recent_remediations[0].trigger}</span>
          </div>
          <RemediationTimeline steps={data.recent_remediations[0].steps} horizontal />
        </Panel>
      )}
    </div>
  );
}

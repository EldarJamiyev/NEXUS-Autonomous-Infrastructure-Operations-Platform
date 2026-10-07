import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Activity, GitCompare, ShieldOff, ShieldPlus } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useMetrics } from "@/hooks/live";
import { useAuth } from "@/api/auth";
import { Button, ErrorBox, KV, Meter, Mono, PageHeader, Panel, Pill, Risk, Skeleton, Status, Tabs, Empty, cx } from "@/components/ui";
import { ConfirmButton, Dialog, useAction } from "@/components/feedback";
import { WhyButton } from "@/components/explain";
import { DiffView } from "@/components/timeline";
import { MetricChart } from "@/charts/MetricChart";
import { DataTable } from "@/components/DataTable";
import { ago, confidenceTone, fmtDateTime, fmtTime, json, riskTone } from "@/lib/format";

type Tab = "overview" | "network" | "services" | "risk" | "config" | "incidents" | "events" | "access";

export default function DeviceDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const { history } = useMetrics();
  const [tab, setTab] = useState<Tab>("overview");
  const [check, setCheck] = useState<any>(null);
  const { run, busy } = useAction();
  const { data: d, error, reload } = useApi<any>(`/api/devices/${id}`, { refreshOn: ["RISK", "QUARANTINE", "INCIDENT", "REMEDIATION", "DRIFT", "SERVICE", "CONFIG", "IDENTITY", "LEASE"] });
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (!d) return <Skeleton rows={12} />;
  const restartable = ["nginx", "ssh", "dns", "ntp", "monitoring-agent", "docker"];
  return (
    <div>
      <PageHeader title={d.id} description={`${d.role} · ${d.os}`}
        meta={<><Status value={d.status} />{d.quarantined && <Pill tone="auto">QUARANTINED · {d.quarantine_reason}</Pill>}<Pill value={d.identity_level}>{d.identity_confidence}% {d.identity_level}</Pill><Pill tone="neutral">{d.criticality}</Pill>{!d.managed && <Pill tone="warn">UNMANAGED</Pill>}</>}
        actions={<>
          <Button icon={<Activity className="h-4 w-4" />} loading={busy === "hc"} onClick={async () => { const r = await run("hc", () => api.post(`/api/devices/${d.id}/healthcheck`)); if (r) setCheck(r); }}>Run health check</Button>
          <Button icon={<GitCompare className="h-4 w-4" />} loading={busy === "cmp"} disabled={!can("OPERATOR")} onClick={() => run("cmp", () => api.post<any>(`/api/devices/${d.id}/compare`), (r: any) => r.compliant ? "Configuration matches Git intent" : `${r.differences.length} difference(s) from Git intent`)}>Compare configuration</Button>
          {d.quarantined
            ? <ConfirmButton label="Release quarantine" icon={<ShieldOff className="h-4 w-4" />} busy={busy === "rel"} confirmTitle={`Release ${d.id}?`} confirmText="The switch port returns to its previous VLAN. Do this only after a human review of the device." onConfirm={() => run("rel", () => api.post<any>(`/api/devices/${d.id}/release`), (r: any) => `Decision ${r.outcome}`)} />
            : <ConfirmButton label="Quarantine" variant="danger" icon={<ShieldPlus className="h-4 w-4" />} busy={busy === "q"} disabled={["firewall", "switch"].includes(d.kind)} confirmTitle={`Quarantine ${d.id}?`} confirmText="NEXUS evaluates the request: quarantine is HIGH_IMPACT, so for managed assets it may need approval. The device moves to VLAN 99 and loses all leases." onConfirm={() => run("q", () => api.post<any>(`/api/devices/${d.id}/quarantine`), (r: any) => `Decision ${r.outcome}: ${r.reasons?.[0] ?? ""}`)} />}
        </>} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "overview", label: "Overview" }, { id: "network", label: "Network" }, { id: "services", label: "Services", count: d.services.length },
        { id: "risk", label: "Risk" }, { id: "config", label: "Configuration", count: d.config.filter((c: any) => c.matches === false).length || undefined },
        { id: "incidents", label: "Incidents", count: d.incidents.length }, { id: "events", label: "Events" }, { id: "access", label: "Sessions & leases" }]} />

      {tab === "overview" && (
        <div className="grid gap-4 xl:grid-cols-3">
          <Panel title="Live metrics" subtitle="Simulated, deterministic signals" className="xl:col-span-2">
            <div className="grid gap-4 md:grid-cols-2">
              <div><h3 className="text-xs text-muted">CPU %</h3><MetricChart points={history[d.id] ?? []} field="cpu" max={100} /></div>
              <div><h3 className="text-xs text-muted">Memory %</h3><MetricChart points={history[d.id] ?? []} field="mem" max={100} /></div>
            </div>
            <div className="mt-3 flex flex-wrap gap-4 text-sm">{Object.entries(d.metrics?.disk ?? {}).map(([m, v]) => <span key={m}>Disk <Mono>{m}</Mono> <span className={cx("font-mono", Number(v) >= 90 ? "text-crit" : Number(v) >= 80 ? "text-warn" : "")}>{String(v)}%</span></span>)}</div>
          </Panel>
          <Panel title="Infrastructure memory" subtitle="What NEXUS remembers about this asset">
            <KV cols={1} items={[["Previous incidents", d.memory.previous_incidents], ["Drift events (SSH)", `${d.memory.drift_events} (${d.memory.ssh_drift})`],
              ["Successful remediations", d.memory.successful_remediations], ["Failed remediations", d.memory.failed_remediations],
              ["Last change", d.memory.last_change ? `${fmtDateTime(d.memory.last_change)} by ${d.memory.last_change_by}` : "-"], ["Current state", <Pill value={d.memory.current_state} />]]} />
          </Panel>
          {check && (
            <Panel title={`Health check · ${check.healthy ? "healthy" : "problems found"}`} className="xl:col-span-3">
              <ul className="grid gap-1 md:grid-cols-2">{check.checks.map((c: any, i: number) => <li key={i} className="flex gap-2 text-sm"><Pill value={c.passed ? "PASS" : "FAIL"} /><span>{c.probe}<span className="ml-1 text-muted">{c.detail}</span></span></li>)}</ul>
            </Panel>
          )}
        </div>
      )}

      {tab === "network" && (
        <Panel title="Network">
          <KV cols={3} items={[["IP address", <Mono>{d.network.ip}</Mono>], ["Assignment", d.network.assignment], ["DHCP hostname", d.network.dhcp_hostname ?? "-"],
            ["MAC", <Mono>{d.network.mac}</Mono>], ["MAC known", d.network.mac_known ? "yes (inventory)" : "no"], ["Vendor OUI", d.network.vendor],
            ["VLAN", `${d.network.vlan} ${d.network.vlan_name ?? ""}`], ["Expected VLAN", d.network.expected_vlan ?? "unknown"], ["Gateway", <Mono>{d.network.gateway}</Mono>],
            ["DNS servers", <Mono>{d.network.dns_servers.join(", ")}</Mono>], ["DNS name", <Mono>{d.network.dns_name ?? "-"}</Mono>], ["Switch port", <Mono>{d.network.switchport ?? "-"}</Mono>],
            ["Listening ports", <Mono>{(d.network.observed_ports ?? []).join(", ") || "-"}</Mono>], ["Expected ports", <Mono>{(d.network.expected_ports ?? []).join(", ") || "-"}</Mono>]]} />
        </Panel>
      )}

      {tab === "services" && (
        <Panel title="Services" bodyClass="p-0">
          <table className="w-full text-left text-sm">
            <thead className="bg-inset text-xs text-muted"><tr>{["Service", "Status", "Ports", "Criticality", "RTO / RPO", "Detail", ""].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
            <tbody>{d.services.map((s: any) => (
              <tr key={s.id} className="border-t border-line">
                <td className="px-3 py-1.5"><div>{s.display_name}</div><Mono className="text-muted">{s.id}</Mono></td>
                <td className="px-3"><Pill value={s.status} />{!s.enabled && <Pill tone="warn" className="ml-1">DISABLED</Pill>}</td>
                <td className="px-3 font-mono text-xs">{s.ports.join(", ") || "-"}</td>
                <td className="px-3"><Pill tone="neutral">{s.criticality}</Pill></td>
                <td className="px-3 text-xs text-muted">{s.rto ? `${s.rto} min` : "-"} / {s.rpo !== null && s.rpo !== undefined ? `${s.rpo} min` : "-"}</td>
                <td className="max-w-[260px] truncate px-3 text-xs text-muted">{s.detail}</td>
                <td className="px-3 text-right">{restartable.includes(s.name) && (
                  <Button size="sm" disabled={!can("ENGINEER")} loading={busy === s.id} title={can("ENGINEER") ? "" : "requires ENGINEER"}
                    onClick={() => run(s.id, () => api.post<any>(`/api/devices/${d.id}/services/${s.name}/restart`), (r: any) => `Decision ${r.outcome}: ${r.reasons?.[0] ?? ""}`)}>Restart</Button>
                )}</td>
              </tr>
            ))}</tbody>
          </table>
          {!d.services.length && <div className="p-4"><Empty title="No managed services on this device" /></div>}
        </Panel>
      )}

      {tab === "risk" && (
        <div className="grid gap-4 xl:grid-cols-3">
          <Panel title="Risk, trust and identity" actions={<WhyButton path={`/api/explain/risk/device/${d.id}`} />}>
            <div className="space-y-3">
              <Meter label="Risk" value={d.risk_detail.score} tone={riskTone(d.risk_detail.score)} />
              <Meter label="Trust" value={d.risk_detail.trust} tone={d.risk_detail.trust >= 80 ? "ok" : d.risk_detail.trust >= 50 ? "warn" : "crit"} />
              <Meter label="Identity" value={d.identity.confidence} tone={confidenceTone(d.identity.confidence)} />
            </div>
            <p className="mt-4 text-xs text-muted">Deterministic prototype rules. Trust drops on anomalies (minor -5, identity mismatch -15, critical incident -30) and recovers +1 per clean reconciliation cycle.</p>
          </Panel>
          <Panel title="Why the score exists" className="xl:col-span-2">
            <ul className="space-y-1.5">{d.risk_detail.factors.map((f: any) => (
              <li key={f.key} className="flex gap-3 rounded border border-line px-3 py-1.5">
                <span className={cx("w-10 shrink-0 text-right font-mono num", f.points >= 0 ? "text-high" : "text-ok")}>{f.points > 0 ? "+" : ""}{f.points}</span>
                <span><span className="text-sm font-medium">{f.label}</span><span className="block text-xs text-muted">{f.evidence}</span></span>
              </li>
            ))}</ul>
          </Panel>
          <Panel title="Identity signals" subtitle={d.identity.note} className="xl:col-span-3" bodyClass="p-0">
            <table className="w-full text-left text-sm"><tbody>{d.identity.signals.map((s: any) => (
              <tr key={s.key} className="border-t border-line first:border-0"><td className="px-3 py-1.5">{s.label}</td>
                <td className="px-3"><Pill value={s.status === null ? "N/A" : s.status ? "PASS" : "FAIL"} tone={s.status === null ? "unk" : s.status ? "ok" : "crit"} /></td>
                <td className="px-3 font-mono text-xs">{s.status ? `+${s.weight}` : s.status === null ? "-" : `0/${s.weight}`}</td><td className="px-3 text-xs text-muted">{s.detail}</td></tr>
            ))}</tbody></table>
          </Panel>
        </div>
      )}

      {tab === "config" && (
        <div className="space-y-4">
          {d.config.map((c: any) => (
            <Panel key={c.component} title={c.component} subtitle={`updated ${ago(c.updated_at)} by ${c.updated_by}`}
              actions={c.matches === null ? <Pill tone="unk">NO INTENT</Pill> : <Pill value={c.matches ? "COMPLIANT" : "DRIFT"} tone={c.matches ? "ok" : "high"} />}>
              <div className="grid gap-4 lg:grid-cols-2">
                <div><h3 className="mb-1 text-xs text-muted">Desired (Git intent)</h3><pre className="overflow-x-auto rounded border border-line bg-inset p-2 font-mono text-xs">{c.desired ? Object.entries(c.desired).map(([k, v]) => `${k}: ${json(v)}`).join("\n") : "not managed by a baseline"}</pre></div>
                <div><h3 className="mb-1 text-xs text-muted">Actual (host agent, normalized)</h3><pre className="overflow-x-auto rounded border border-line bg-inset p-2 font-mono text-xs">{Object.entries(c.actual).map(([k, v]) => `${k}: ${json(v)}`).join("\n")}</pre></div>
              </div>
              {c.desired && <p className="mt-2 font-mono text-[11.5px] text-muted">SHA-256 expected {c.desired_checksum.slice(0, 16)} · actual {c.actual_checksum.slice(0, 16)} · MATCH {c.matches ? "YES" : "NO"}</p>}
              {c.diff && <div className="mt-2"><DiffView diff={c.diff} /></div>}
            </Panel>
          ))}
          {!d.config.length && <Empty title="No configuration reported for this device" hint="Unmanaged or network-only devices do not run a NEXUS host agent." />}
        </div>
      )}

      {tab === "incidents" && (
        <Panel title="Incidents" bodyClass="p-3">
          <DataTable rows={d.incidents} rowKey={(i: any) => i.id} searchable={false} empty="No incidents for this device"
            columns={[{ key: "id", header: "Incident", render: (i: any) => <Link className="font-mono text-xs text-info" to={`/incidents/${i.id}`}>{i.id}</Link> },
              { key: "title", header: "Title" }, { key: "priority", header: "Priority", render: (i: any) => <Pill value={i.priority} /> },
              { key: "status", header: "Status", render: (i: any) => <Pill value={i.status} /> }, { key: "created_at", header: "Opened", render: (i: any) => fmtDateTime(i.created_at) }]} />
        </Panel>
      )}

      {tab === "events" && (
        <Panel title="Events" bodyClass="p-3">
          <ol>{d.events.map((e: any) => (
            <li key={e.id} className="grid grid-cols-[86px_200px_minmax(0,1fr)] gap-2 border-b border-line py-1 text-sm last:border-0">
              <span className="font-mono text-xs text-muted">{fmtTime(e.ts)}</span><span className="font-mono text-xs font-semibold">{e.type}</span><span className="text-muted">{e.message}</span>
            </li>
          ))}</ol>
        </Panel>
      )}

      {tab === "access" && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Sessions"><ul className="space-y-1 text-sm">{d.sessions.map((s: any, i: number) => <li key={i} className="flex justify-between"><span>{s.user}</span><span className="text-muted">{s.active ? `active since ${fmtTime(s.since)}` : `ended ${fmtDateTime(s.ended)}`}</span></li>)}</ul>{!d.sessions.length && <Empty title="No sessions" />}</Panel>
          <Panel title="Leases (from or to this device)"><ul className="space-y-1 text-sm">{d.leases.map((l: any) => <li key={l.id} className="flex justify-between gap-2"><Mono>{l.id}</Mono><span>{l.user_id} → {l.destination}:{l.port}</span><Pill value={l.status} /></li>)}</ul>{!d.leases.length && <Empty title="No leases" />}</Panel>
        </div>
      )}
      <Dialog open={false} onClose={() => undefined} title="">{null}</Dialog>
    </div>
  );
}

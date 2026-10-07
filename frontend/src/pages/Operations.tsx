import { useState } from "react";
import { Link } from "react-router-dom";
import { Save, Sunrise, Users } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, Empty } from "@/components/ui";
import { useAction } from "@/components/feedback";
import { Markdown } from "@/components/Markdown";
import { ago, fmtDateTime } from "@/lib/format";

export default function Operations() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: ops } = useApi<any>("/api/operations/daily", { refreshOn: ["INCIDENT", "DRIFT", "LEASE", "REMEDIATION", "APPROVAL"] });
  const [brief, setBrief] = useState<any>(null);
  const [handover, setHandover] = useState<string | null>(null);
  if (!ops) return <Skeleton rows={10} />;
  const list = (items: any[], render: (x: any) => JSX.Element, empty: string) => items.length ? <ul className="space-y-1 text-sm">{items.map(render)}</ul> : <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="space-y-4">
      <PageHeader title="Daily operations" description="The start-of-shift view: what happened overnight, what is still open, what expires soon, and what needs a human today."
        actions={<>
          <Button variant="primary" icon={<Sunrise className="h-4 w-4" />} loading={busy === "brief"} onClick={() => run("brief", () => api.get<any>("/api/operations/morning-brief")).then((r) => r && setBrief(r))}>Generate morning brief</Button>
          <Button icon={<Users className="h-4 w-4" />} loading={busy === "ho"} onClick={() => run("ho", () => api.get<string>("/api/operations/handover")).then((r) => r && setHandover(r))}>Shift handover</Button>
        </>} />
      {brief && <Panel title="Morning brief"><pre className="overflow-x-auto font-mono text-[12.5px] leading-6">{brief.text}</pre></Panel>}
      {handover && <Panel title="Shift handover" actions={<Button size="sm" icon={<Save className="h-3.5 w-3.5" />} disabled={!can("OPERATOR")} onClick={() => run("save", () => api.post<any>("/api/operations/handover"), (r: any) => `Saved as ${r.id}`)}>Save as report</Button>}><Markdown text={handover} /></Panel>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Panel title="Overnight incidents">{list(ops.overnight_incidents, (i) => <li key={i.id} className="flex justify-between gap-2"><Link className="font-mono text-xs text-info" to={`/incidents/${i.id}`}>{i.id}</Link><span className="flex-1 truncate">{i.title}</span><Pill value={i.status} /></li>, "Quiet night")}</Panel>
        <Panel title="Unresolved alerts">{list(ops.unresolved_alerts, (a) => <li key={a.id} className="flex justify-between gap-2"><Mono>{a.name}</Mono><span className="text-xs">{a.target}</span><span className="text-xs text-muted">{ago(a.since)}</span></li>, "No firing alerts")}</Panel>
        <Panel title="Maintenance"><p className="text-sm"><Pill value={ops.maintenance.current} /></p><p className="mt-2 text-sm">Next window: <span className="font-medium">{ops.maintenance.next}</span></p><p className="text-xs text-muted">{ops.maintenance.detail}</p></Panel>
        <Panel title="Expiring leases (30 min)">{list(ops.expiring_leases, (l) => <li key={l.id} className="flex justify-between gap-2"><Mono>{l.id}</Mono><span>{l.user} → {l.destination}</span><span className="text-xs text-muted">{fmtDateTime(l.expires_at).slice(11)}</span></li>, "No leases expiring soon")}</Panel>
        <Panel title="Configuration drift">{list(ops.drift, (d) => <li key={d.id} className="flex justify-between gap-2"><Mono>{d.id}</Mono><span className="text-xs">{d.device} {d.key}</span><Pill value={d.status} /></li>, "No open drift")}</Panel>
        <Panel title="High-risk devices">{list(ops.high_risk_devices, (d) => <li key={d.id} className="flex justify-between"><Link className="font-mono text-xs text-info" to={`/devices/${d.id}`}>{d.id}</Link><Pill value={d.level}>{d.score} {d.level}</Pill></li>, "No device above risk 50")}</Panel>
        <Panel title="Failed automations">{list(ops.failed_automations, (t) => <li key={t.id} className="flex justify-between gap-2"><Link className="font-mono text-xs text-info" to={`/autoheal?tx=${t.id}`}>{t.id}</Link><span className="flex-1 truncate text-xs">{t.action} on {t.target}</span><Pill value={t.status} /></li>, "None")}</Panel>
        <Panel title="Certificates">{list(ops.certificates, (c) => <li key={c.id} className="flex justify-between gap-2"><Mono>{c.id}</Mono><Pill value={c.days < 0 ? "CRITICAL" : c.days <= 14 ? "EXPIRING" : "VALID"}>{c.days} days</Pill></li>, "No certificates")}</Panel>
        <Panel title="Capacity warnings">{list(ops.capacity_warnings, (c) => <li key={`${c.device}${c.resource}`} className="flex justify-between"><Mono>{c.device}</Mono><span className="text-xs">{c.resource}</span><span className="font-mono text-warn">{c.value}%</span></li>, "No capacity warnings")}</Panel>
      </div>
      {ops.pending_approvals > 0 && <p className="text-sm"><Link className="text-info hover:underline" to="/approvals">{ops.pending_approvals} approval(s) waiting</Link></p>}
    </div>
  );
}

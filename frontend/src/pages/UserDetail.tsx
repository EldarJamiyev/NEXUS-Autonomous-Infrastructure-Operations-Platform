import { useParams } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import { EntityLink, KV, Mono, PageHeader, Panel, Pill, Skeleton, Empty, cx } from "@/components/ui";
import { WhyButton } from "@/components/explain";
import { fmtDateTime, fmtTime } from "@/lib/format";

export default function UserDetail() {
  const { id = "" } = useParams();
  const { data: u } = useApi<any>(`/api/users/${id}`, { refreshOn: ["USER_", "RISK", "LEASE", "AUTH"] });
  if (!u) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title={u.name} description={`${u.title} · ${u.department} · ${u.email}`}
        meta={<>{u.groups.map((g: string) => <Pill key={g} tone={g.endsWith("ADMIN") ? "auto" : "neutral"}>{g}</Pill>)}<Pill tone="neutral">console {u.console_role}</Pill></>} />
      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Directory">
          <KV cols={1} items={[["Distinguished name", <Mono>{u.ad_dn}</Mono>], ["Enabled", u.enabled ? "yes" : "no"], ["Privileged", u.privileged ? "yes (admin group)" : "no"], ["Workstations", u.workstations.join(", ") || "none"]]} />
        </Panel>
        <Panel title={`Risk ${u.risk_detail.score} · trust ${u.risk_detail.trust}`} actions={<WhyButton path={`/api/explain/risk/user/${u.id}`} />} className="xl:col-span-2">
          <ul className="space-y-1">{u.risk_detail.factors.map((f: any) => <li key={f.key} className="flex gap-3 text-sm"><span className="w-8 text-right font-mono text-high">+{f.points}</span><span>{f.label} <span className="text-muted">({f.evidence})</span></span></li>)}</ul>
          {!u.risk_detail.factors.length && <p className="text-sm text-muted">No risk factors.</p>}
        </Panel>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Sessions"><ul className="space-y-1 text-sm">{u.session_history.map((s: any, i: number) => (
          <li key={i} className="flex justify-between gap-2"><EntityLink kind="device" id={s.device} /><Mono>{s.ip}</Mono><span className={cx("text-xs", s.active ? "text-ok" : "text-muted")}>{s.active ? `active since ${fmtTime(s.since)}` : `${fmtDateTime(s.since)} - ${fmtDateTime(s.ended)}`}</span></li>
        ))}</ul>{!u.session_history.length && <Empty title="No sessions recorded" />}</Panel>
        <Panel title="Access leases"><ul className="space-y-1 text-sm">{u.leases.map((l: any) => (
          <li key={l.id} className="flex justify-between gap-2"><Mono>{l.id}</Mono><span>{l.device_id} → {l.destination}:{l.port}</span><Pill value={l.status} /></li>
        ))}</ul>{!u.leases.length && <Empty title="No leases" />}</Panel>
      </div>
      <Panel title="Identity events"><ol>{u.events.map((e: any, i: number) => (
        <li key={i} className="grid grid-cols-[80px_170px_minmax(0,1fr)] gap-2 border-b border-line py-1 text-sm last:border-0"><span className="font-mono text-xs text-muted">{fmtTime(e.ts)}</span><span className="font-mono text-xs">{e.type}</span><span className="text-muted">{e.message}</span></li>
      ))}</ol></Panel>
    </div>
  );
}

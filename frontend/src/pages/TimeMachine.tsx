import { useEffect, useMemo, useState } from "react";
import { Camera } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, Empty, cx, inputClass } from "@/components/ui";
import { useAction } from "@/components/feedback";
import { fmtDateTime, fmtTime, json } from "@/lib/format";

const RANGES = [["1", "1 h"], ["3", "3 h"], ["24", "24 h"], ["168", "7 days"]];

export default function TimeMachine() {
  const { can } = useAuth();
  const { run } = useAction();
  const [hours, setHours] = useState("3");
  const { data: tl, reload } = useApi<any>(`/api/timemachine/timeline?hours=${hours}`, { refreshOn: ["SNAPSHOT"] , interval: 20000 });
  const [idx, setIdx] = useState<number | null>(null);
  const snaps = tl?.snapshots ?? [];
  const i = idx ?? Math.max(0, snaps.length - 1);
  const snap = snaps[i];
  const { data: state } = useApi<any>(snap ? `/api/timemachine/state?at=${encodeURIComponent(snap.ts)}` : null);
  const { data: cmp } = useApi<any>(snap ? `/api/timemachine/compare?a=${snap.id}&b=now` : null);
  useEffect(() => setIdx(null), [hours]);
  const span = useMemo(() => {
    if (!snaps.length) return null;
    const a = new Date(snaps[0].ts).getTime();
    const b = new Date(tl.now).getTime();
    return { a, b, w: Math.max(1, b - a) };
  }, [snaps, tl]);
  const beforeIncident = () => {
    const marker = [...(tl?.markers ?? [])].reverse().find((m: any) => m.type === "INCIDENT_CREATED" || m.type === "QUARANTINE_STARTED");
    if (!marker) return;
    const t = new Date(marker.ts).getTime() - 1000;
    let best = 0;
    snaps.forEach((s: any, k: number) => { if (new Date(s.ts).getTime() <= t) best = k; });
    setIdx(best);
  };
  if (!tl) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title="Network time machine" description="Historical infrastructure state reconstructed from recorded snapshots and events. Rewind to any point and compare it with now."
        actions={<>
          <select aria-label="Range" value={hours} onChange={(e) => setHours(e.target.value)} className={inputClass}>{RANGES.map(([v, l]) => <option key={v} value={v}>Last {l}</option>)}</select>
          <Button onClick={beforeIncident}>Before last incident</Button>
          <Button icon={<Camera className="h-4 w-4" />} disabled={!can("OPERATOR")} onClick={() => run("snap", () => api.post("/api/snapshots", { label: "manual snapshot" }), "Snapshot created").then(reload)}>Create snapshot</Button>
        </>} />
      {!snaps.length ? <Empty title="No snapshots in this range" /> : (
        <Panel title={`State at ${fmtDateTime(snap.ts)}`} subtitle={`${snap.reason}${snap.label ? ` · ${snap.label}` : ""} · snapshot #${snap.id} of ${snaps.length}`}>
          <div className="relative mb-1 h-6">
            {span && tl.markers.map((m: any, k: number) => {
              const left = ((new Date(m.ts).getTime() - span.a) / span.w) * 100;
              return left >= 0 && left <= 100 ? <span key={k} title={`${fmtTime(m.ts)} ${m.type}: ${m.message}`} className={cx("absolute top-1 h-4 w-1 rounded-sm", m.type.includes("INCIDENT_CREATED") || m.type === "FAILURE_INJECTED" ? "bg-crit" : m.type === "INCIDENT_RESOLVED" ? "bg-ok" : m.type === "QUARANTINE_STARTED" ? "bg-accent" : "bg-warn")} style={{ left: `${left}%` }} /> : null;
            })}
          </div>
          <input type="range" min={0} max={snaps.length - 1} value={i} onChange={(e) => setIdx(Number(e.target.value))} aria-label="Point in time" className="w-full" />
          <div className="mt-1 flex justify-between font-mono text-[11px] text-muted"><span>{fmtDateTime(snaps[0].ts)}</span><span>NOW</span></div>
          <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted"><span className="flex items-center gap-1"><span className="h-3 w-1 bg-crit" />failure / incident</span><span className="flex items-center gap-1"><span className="h-3 w-1 bg-ok" />resolved</span><span className="flex items-center gap-1"><span className="h-3 w-1 bg-accent" />quarantine</span><span className="flex items-center gap-1"><span className="h-3 w-1 bg-warn" />drift / mode</span></div>
          <dl className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
            {([["Devices", snap.summary.devices], ["Quarantined", snap.summary.quarantined], ["Services down", snap.summary.services_down], ["Active leases", snap.summary.active_leases],
               ["Open incidents", snap.summary.open_incidents], ["Open drift", snap.summary.open_drift], ["Max device risk", snap.summary.max_risk], ["Mode", snap.summary.mode]] as [string, any][]).map(([k, v]) => (
              <div key={k} className="rounded border border-line px-3 py-2"><dt className="text-[11px] text-muted">{k}</dt><dd className="font-cond text-xl font-semibold">{String(v)}</dd></div>
            ))}
          </dl>
        </Panel>
      )}
      {state && (
        <div className="grid gap-4 xl:grid-cols-3">
          <Panel title="Devices then" bodyClass="p-0"><table className="w-full text-left text-sm"><tbody>{Object.entries(state.state.devices).map(([id, d]: [string, any]) => (
            <tr key={id} className="border-t border-line first:border-0"><td className="px-3 py-1"><Mono>{id}</Mono></td><td><Pill value={d.status} /></td><td className="font-mono text-xs">{d.ip}</td><td className="px-3 font-mono text-xs">risk {d.risk}</td></tr>
          ))}</tbody></table></Panel>
          <Panel title="Leases, incidents and drift then">
            <h3 className="text-xs text-muted">Leases</h3><ul className="mb-3 text-sm">{Object.entries(state.state.leases).map(([id, l]: [string, any]) => <li key={id}><Mono>{id}</Mono> {l.user} → {l.destination} <Pill value={l.status} /></li>)}</ul>
            <h3 className="text-xs text-muted">Incidents</h3><ul className="mb-3 text-sm">{Object.entries(state.state.incidents).map(([id, x]: [string, any]) => <li key={id}><Mono>{id}</Mono> {x.priority} {x.title} <Pill value={x.status} /></li>)}{!Object.keys(state.state.incidents).length && <li className="text-muted">none open</li>}</ul>
            <h3 className="text-xs text-muted">Drift</h3><ul className="text-sm">{Object.entries(state.state.drift).map(([id, x]: [string, any]) => <li key={id}><Mono>{id}</Mono> {x.device} {x.key} <Pill value={x.status} /></li>)}{!Object.keys(state.state.drift).length && <li className="text-muted">none open</li>}</ul>
          </Panel>
          <Panel title="Then vs now" subtitle="Added, removed and changed since the selected moment">
            {!cmp ? <Skeleton /> : (
              <ul className="space-y-2 text-sm">{Object.entries(cmp.diff).filter(([k]) => k !== "totals").map(([cat, d]: [string, any]) => {
                const n = d.added.length + d.removed.length + d.changed.length;
                if (!n) return null;
                return (
                  <li key={cat}><div className="font-medium capitalize">{cat} <span className="font-mono text-xs text-muted">{n}</span></div>
                    <ul className="ml-3 text-xs">
                      {d.added.slice(0, 5).map((x: any) => <li key={`a${x.id}`} className="text-ok">+ {x.id}</li>)}
                      {d.removed.slice(0, 5).map((x: any) => <li key={`r${x.id}`} className="text-crit">- {x.id}</li>)}
                      {d.changed.slice(0, 6).map((x: any) => <li key={`c${x.id}`} className="text-muted">~ {x.id}: {Object.entries(x.fields).slice(0, 2).map(([f, v]: [string, any]) => `${f} ${json(v[0])} → ${json(v[1])}`).join("; ")}</li>)}
                    </ul></li>
                );
              })}</ul>
            )}
          </Panel>
          {state.events_since_snapshot.length > 0 && <Panel title="Events between this snapshot and the selected time" className="xl:col-span-3">{state.events_since_snapshot.map((e: any, k: number) => <p key={k} className="font-mono text-xs"><span className="text-muted">{fmtTime(e.ts)}</span> {e.type} {e.message}</p>)}</Panel>}
        </div>
      )}
    </div>
  );
}

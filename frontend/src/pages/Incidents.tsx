import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import type { Incident } from "@/types";
import { DataTable } from "@/components/DataTable";
import { PageHeader, Panel, Pill, Skeleton, Mono, cx, inputClass } from "@/components/ui";
import { ago, dur, TONE_SOFT, toneOf } from "@/lib/format";

const LEVELS = ["HIGH", "MEDIUM", "LOW"] as const;
const MATRIX: Record<string, string> = { "HIGH:HIGH": "P1", "HIGH:MEDIUM": "P2", "HIGH:LOW": "P3", "MEDIUM:HIGH": "P2", "MEDIUM:MEDIUM": "P3", "MEDIUM:LOW": "P4", "LOW:HIGH": "P3", "LOW:MEDIUM": "P4", "LOW:LOW": "P4" };

export default function Incidents() {
  const navigate = useNavigate();
  const [status, setStatus] = useState("OPEN,INVESTIGATING,MITIGATED");
  const { data } = useApi<Incident[]>(`/api/incidents?limit=300${status ? `&status=${status}` : ""}`, { refreshOn: ["INCIDENT", "ROOT_CAUSE", "SYMPTOM", "REMEDIATION"] });
  const { data: all } = useApi<Incident[]>("/api/incidents?limit=300", { refreshOn: ["INCIDENT"] });
  const matrix = useMemo(() => {
    const m: Record<string, Incident[]> = {};
    for (const i of all ?? []) if (["OPEN", "INVESTIGATING", "MITIGATED"].includes(i.status)) {
      const t = (i as any).triage ?? {};
      const key = `${t.impact ?? "LOW"}:${t.urgency ?? "LOW"}`;
      (m[key] ??= []).push(i);
    }
    return m;
  }, [all]);
  return (
    <div>
      <PageHeader title="Incidents" description="Correlated incidents: one incident, many symptoms. Root causes are deterministic (dependency graph, timing, recent changes), never guessed." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_330px]">
        <Panel title="Incident list" bodyClass="p-3">
          {!data ? <Skeleton rows={8} /> : (
            <DataTable rows={data} rowKey={(i) => i.id} onRowClick={(i) => navigate(`/incidents/${i.id}`)} placeholder="Filter incidents"
              toolbar={<select aria-label="Status filter" value={status} onChange={(e) => setStatus(e.target.value)} className={cx(inputClass, "h-8")}>
                <option value="OPEN,INVESTIGATING,MITIGATED">Active</option><option value="OPEN,INVESTIGATING">Needs action</option><option value="RESOLVED">Resolved</option><option value="FALSE_POSITIVE">False positive</option><option value="">All</option>
              </select>}
              columns={[
                { key: "id", header: "ID", render: (i) => <Mono className="text-info">{i.id}</Mono> },
                { key: "priority", header: "Priority", render: (i) => <Pill value={i.priority} /> },
                { key: "title", header: "Title", render: (i) => <div className="max-w-[340px]"><div className="truncate">{i.title}</div>{i.recurring?.occurrences && <span className="text-[11px] text-warn">recurring · {i.recurring.occurrences} in 7 days</span>}</div> },
                { key: "target", header: "Asset", render: (i) => <Mono>{i.target}</Mono> },
                { key: "root_cause", header: "Root cause", render: (i) => <div className="max-w-[300px]"><div className="truncate text-xs" title={i.root_cause ?? ""}>{i.root_cause ?? "-"}</div>{i.root_cause_confidence && <span className="text-[11px] text-muted">confidence {i.root_cause_confidence}</span>}</div> },
                { key: "status", header: "Status", render: (i) => <span className="flex gap-1"><Pill value={i.status} />{i.human_required && !["RESOLVED", "FALSE_POSITIVE"].includes(i.status) && <Pill tone="warn">HUMAN</Pill>}</span> },
                { key: "created_at", header: "Opened", render: (i) => <span className="whitespace-nowrap text-xs text-muted">{ago(i.created_at)}</span> },
                { key: "mttr_seconds", header: "Time to resolve", sort: (i) => i.mttr_seconds ?? 1e9, render: (i) => <span className="text-xs">{dur(i.mttr_seconds)}</span> },
              ]} />
          )}
        </Panel>
        <Panel title="Priority matrix" subtitle="Impact × urgency of active incidents">
          <div className="grid grid-cols-[64px_repeat(3,minmax(0,1fr))] gap-1 text-center">
            <span />{LEVELS.map((u) => <span key={u} className="text-[11px] text-muted">Urgency {u.toLowerCase()}</span>)}
            {LEVELS.map((imp) => (
              <div key={imp} className="contents">
                <span className="self-center text-right text-[11px] text-muted">Impact {imp.toLowerCase()}</span>
                {LEVELS.map((urg) => {
                  const p = MATRIX[`${imp}:${urg}`];
                  const items = matrix[`${imp}:${urg}`] ?? [];
                  return (
                    <div key={urg} className={cx("flex min-h-[64px] flex-col items-center justify-center rounded border", items.length ? TONE_SOFT[toneOf(p)] : "border-line bg-inset text-muted")}>
                      <span className="font-cond text-sm font-semibold">{p}</span>
                      <span className="font-mono text-lg num">{items.length || ""}</span>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-muted">P1 requires high impact and high urgency (critical asset or many users, plus critical severity or risk ≥ 80).</p>
        </Panel>
      </div>
    </div>
  );
}

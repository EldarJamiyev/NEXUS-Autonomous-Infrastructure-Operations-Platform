import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Check, Circle, Loader2, Siren, Zap } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, Empty, cx } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";
import { fmtTime, ago } from "@/lib/format";

const STAGES = ["trigger", "detection", "incident", "root_cause", "risk", "decision", "action", "verification", "final_state"];

function RunView({ runId, onFix }: { runId: string; onFix: () => void }) {
  const { data: run, reload } = useApi<any>(`/api/chaos/runs/${runId}`, { refreshOn: ["*"] });
  useEffect(() => {
    if (!run || ["COMPLETED", "HUMAN_REQUIRED"].includes(run.status)) return;
    const id = window.setInterval(reload, 1200);
    return () => window.clearInterval(id);
  }, [run?.status, reload]);
  if (!run) return <Skeleton rows={6} />;
  const done = ["COMPLETED", "HUMAN_REQUIRED"].includes(run.status);
  return (
    <Panel title={`${run.id} · ${run.title}`} subtitle={`started ${fmtTime(run.started_at)} by ${run.requested_by}${run.detection_seconds !== null ? ` · detected in ${run.detection_seconds} s` : ""}`}
      actions={<><Pill value={run.status} tone={run.status === "COMPLETED" ? "ok" : run.status === "HUMAN_REQUIRED" ? "warn" : "auto"} />{run.report_id && <Link className="text-xs text-info" to={`/reports?id=${run.report_id}`}>Report {run.report_id}</Link>}</>}
      className={done ? "" : "border-accent/50"}>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <ol className="space-y-1.5">{STAGES.map((s) => {
          const st = run.stages?.[s];
          const ok = st?.done;
          return (
            <li key={s} className="grid grid-cols-[22px_110px_minmax(0,1fr)] items-start gap-2">
              <span className={cx("mt-0.5 flex h-5 w-5 items-center justify-center rounded-full", ok ? "bg-ok text-white" : done ? "bg-inset text-muted" : "bg-accent/15 text-accent")}>
                {ok ? <Check className="h-3 w-3" /> : done ? <Circle className="h-2.5 w-2.5" /> : <Loader2 className="h-3 w-3 animate-spin" />}
              </span>
              <span className="font-cond text-[13px] font-semibold uppercase">{s.replace("_", " ")}</span>
              <span className="break-words text-xs text-muted">{st?.detail ?? "-"}</span>
            </li>
          );
        })}</ol>
        <div className="max-h-[340px] overflow-y-auto rounded border border-line bg-inset p-2">
          <ol>{[...(run.events ?? [])].reverse().map((e: any, i: number) => (
            <li key={i} className="grid grid-cols-[62px_minmax(0,1fr)] gap-2 font-mono text-[11.5px] leading-4"><span className="text-muted">{fmtTime(e.ts)}</span><span><span className="font-semibold">{e.type}</span> <span className="text-muted">{e.message}</span></span></li>
          ))}</ol>
        </div>
      </div>
      {run.human_required && run.operator_fix && (
        <div className="mt-3 flex flex-wrap items-center gap-3 rounded border border-warn/40 bg-warn/10 p-2 text-sm">
          <span>NEXUS escalated to a human for this scenario.</span><Button size="sm" variant="primary" onClick={onFix}>{run.operator_fix}</Button>
          <span className="text-xs text-muted">Simulates the manual intervention; NEXUS then re-verifies.</span>
        </div>
      )}
      {run.human_required && !run.operator_fix && <p className="mt-3 text-sm text-warn">Waiting for a human decision - see <Link className="underline" to="/approvals">Approvals</Link>.</p>}
    </Panel>
  );
}

export default function ChaosLab() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const { data: scenarios } = useApi<any[]>("/api/chaos/scenarios");
  const { data: runs, reload } = useApi<any[]>("/api/chaos/runs", { refreshOn: ["FAILURE_INJECTED", "INCIDENT_RESOLVED", "INCIDENT_UPDATED"] });
  const [active, setActive] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const current = active ?? runs?.[0]?.id ?? null;
  const groups = useMemo(() => {
    const g: Record<string, any[]> = {};
    for (const s of scenarios ?? []) if (s.id !== "blackout") (g[s.category] ??= []).push(s);
    return g;
  }, [scenarios]);
  const start = async (id: string) => {
    const r = await run(id, () => api.post<any>(`/api/chaos/${id}`), `Injected ${id}`);
    if (r) { setActive(r.run); reload(); window.scrollTo({ top: 0, behavior: "smooth" }); }
  };
  if (!scenarios) return <Skeleton rows={10} />;
  return (
    <div className="space-y-4">
      <PageHeader title="Chaos lab" description="Break the simulated enterprise on purpose. Scenarios only change the simulated world; detection, correlation, root cause, decisions, remediation and verification are left entirely to NEXUS."
        actions={<>
          <Link to="/whatif?preset=disaster" className="text-sm text-info hover:underline">Disaster recovery lab</Link>
          <ConfirmButton label="Run full infrastructure blackout" variant="danger" icon={<Siren className="h-4 w-4" />} disabled={!can("ENGINEER")} busy={busy === "blackout"}
            confirmTitle="Run the blackout drill?" confirmText="Nine faults are injected within about eleven seconds: unknown device, firewall drift, SSH drift, DNS outage, monitoring failure, unexpected port, DHCP conflict, policy conflict and an Nginx outage. Watch NEXUS correlate, prioritise and remediate, then read the final report."
            onConfirm={() => start("blackout")} />
        </>} />
      {current ? <RunView key={current} runId={current} onFix={() => run("fix", () => api.post(`/api/chaos/runs/${current}/operator-fix`), "Manual fix applied")} /> : <Empty title="No chaos runs yet" hint="Pick a scenario below and press Break system." />}
      {Object.entries(groups).map(([cat, items]) => (
        <section key={cat}>
          <h2 className="mb-2 font-cond text-[15px] font-semibold capitalize">{cat.replace("-", " ")}</h2>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">{items.map((s) => (
            <article key={s.id} className="flex flex-col rounded-md border border-line bg-panel p-3">
              <div className="flex items-start justify-between gap-2"><h3 className="font-medium">{s.title}</h3>{!s.automatic && <Pill tone="warn" title="Ends with a human step by design">HUMAN STEP</Pill>}</div>
              <p className="mt-1 flex-1 text-xs text-muted">{s.description}</p>
              <button className="mt-2 text-left text-xs text-info hover:underline" onClick={() => setOpen(open === s.id ? null : s.id)}>{open === s.id ? "Hide" : "What should happen"}</button>
              {open === s.id && (
                <dl className="mt-2 space-y-1 border-t border-line pt-2 text-[11.5px]">{Object.entries(s.expect).map(([k, v]) => (
                  <div key={k} className="grid grid-cols-[84px_minmax(0,1fr)] gap-1"><dt className="font-cond font-semibold uppercase text-muted">{k.replace("_", " ")}</dt><dd>{String(v)}</dd></div>
                ))}</dl>
              )}
              <Button className="mt-3" variant="danger" size="sm" icon={<Zap className="h-3.5 w-3.5" />} disabled={!can("ENGINEER")} loading={busy === s.id} onClick={() => start(s.id)}>Break system</Button>
            </article>
          ))}</div>
        </section>
      ))}
      <Panel title="Recent runs" bodyClass="p-0">
        <table className="w-full text-left text-sm"><tbody>{(runs ?? []).map((r) => (
          <tr key={r.id} className={cx("cursor-pointer border-t border-line first:border-0 hover:bg-inset", r.id === current && "bg-accent/10")} onClick={() => setActive(r.id)}>
            <td className="px-4 py-1.5"><Mono>{r.id}</Mono></td><td>{r.title}</td><td><Pill value={r.status} /></td><td className="text-xs text-muted">{r.requested_by}</td><td className="px-4 text-xs text-muted">{ago(r.started_at)}</td>
          </tr>
        ))}</tbody></table>
      </Panel>
    </div>
  );
}

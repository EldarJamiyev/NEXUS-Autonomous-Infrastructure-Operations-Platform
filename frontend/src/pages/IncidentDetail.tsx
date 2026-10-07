import { useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { CheckCircle2, Download, FileText, RefreshCw } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, ErrorBox, KV, Mono, PageHeader, Panel, Pill, Skeleton, EntityLink, cx, inputClass, Empty } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";
import { WhyButton } from "@/components/explain";
import { IncidentTimeline, RemediationTimeline } from "@/components/timeline";
import { openAuthed } from "@/lib/download";
import { fmtDateTime, fmtTime, dur } from "@/lib/format";

const STAGES = ["EVENT", "OBSERVATION", "CORRELATION", "ROOT_CAUSE", "DECISION", "REMEDIATION", "VERIFICATION", "RESOLUTION"];

export default function IncidentDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const { run, busy } = useAction();
  const [filter, setFilter] = useState("");
  const { data: inc, error, reload } = useApi<any>(`/api/incidents/${id}`, { refreshOn: ["INCIDENT", "REMEDIATION", "VERIFICATION", "ROLLBACK", "ROOT_CAUSE", "SYMPTOM", "DECISION", "CHATOPS"] });
  const events = useMemo(() => (inc?.events ?? []).filter((e: any) => !filter || `${e.type} ${e.target} ${e.message} ${e.severity} ${e.correlation_id}`.toLowerCase().includes(filter.toLowerCase())), [inc, filter]);
  if (error) return <ErrorBox error={error} retry={reload} />;
  if (!inc) return <Skeleton rows={12} />;
  const stagesSeen = new Set(inc.timeline.map((t: any) => t.stage));
  const active = !["RESOLVED", "FALSE_POSITIVE"].includes(inc.status);
  return (
    <div className="space-y-4">
      <PageHeader title={`${inc.id} · ${inc.title}`} description={inc.summary}
        meta={<><Pill value={inc.priority} /><Pill value={inc.severity} /><Pill value={inc.status} /><Pill tone="neutral">{inc.category}</Pill>
          {inc.human_required && active && <Pill tone="warn">HUMAN ACTION REQUIRED</Pill>}<span className="font-mono text-xs text-muted">{inc.correlation_id}</span></>}
        actions={<>
          <Button icon={<FileText className="h-4 w-4" />} onClick={() => openAuthed(`/api/incidents/${inc.id}/report?format=html`)}>Report</Button>
          <Button icon={<Download className="h-4 w-4" />} onClick={() => openAuthed(`/api/incidents/${inc.id}/report`, `${inc.id}.md`)}>Markdown</Button>
          {active && <Button disabled={!can("OPERATOR")} loading={busy === "ack"} onClick={() => run("ack", () => api.post(`/api/incidents/${inc.id}/acknowledge`), "Acknowledged")}>Acknowledge</Button>}
          {active && <Button icon={<RefreshCw className="h-4 w-4" />} disabled={!can("ENGINEER")} loading={busy === "retry"} onClick={() => run("retry", () => api.post<any>(`/api/incidents/${inc.id}/remediate`), (r: any) => `Decision ${r.outcome}`)}>Retry remediation</Button>}
          {active && <ConfirmButton label="Resolve" icon={<CheckCircle2 className="h-4 w-4" />} disabled={!can("OPERATOR")} confirmTitle={`Resolve ${inc.id}?`} confirmText="Mark the incident resolved by an operator. The audit trail records who closed it." onConfirm={() => run("res", () => api.post(`/api/incidents/${inc.id}/resolve`, { reason: "resolved by operator" }), "Resolved")} />}
          {active && <ConfirmButton label="False positive" disabled={!can("OPERATOR")} confirmTitle="Mark as false positive?" confirmText="The incident is closed as FALSE_POSITIVE and counted in the scorecard." onConfirm={() => run("fp", () => api.post(`/api/incidents/${inc.id}/false-positive`, { reason: "false positive" }), "Marked false positive")} />}
        </>} />

      <ol className="flex flex-wrap items-center gap-1" aria-label="Investigation pipeline">
        {STAGES.map((s, i) => (
          <li key={s} className="flex items-center">
            <span className={cx("rounded px-2 py-1 font-cond text-[12px] font-semibold", stagesSeen.has(s) ? (s === "RESOLUTION" ? "bg-ok/15 text-ok" : "bg-accent/15 text-accent") : "bg-inset text-muted")}>{s.replace("_", " ")}</span>
            {i < STAGES.length - 1 && <span className="mx-1 text-muted">→</span>}
          </li>
        ))}
      </ol>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="What happened" className="xl:col-span-2">
          <KV cols={3} items={[["Detected", fmtDateTime(inc.created_at)], ["Affected asset", <EntityLink kind="device" id={inc.target} />], ["Detection source", inc.detection_source],
            ["Mitigated", fmtDateTime(inc.mitigated_at)], ["Resolved", fmtDateTime(inc.resolved_at)], ["Time to resolve", dur(inc.mttr_seconds)]]} />
          <div className="mt-4 rounded border border-high/40 bg-high/5 p-3">
            <div className="flex items-center justify-between gap-2"><h3 className="text-sm font-semibold">Root cause</h3><span className="flex items-center gap-2"><Pill value={inc.root_cause_confidence ?? "-"} tone="info">confidence {inc.root_cause_confidence}</Pill><WhyButton path={`/api/explain/incident/${inc.id}`} /></span></div>
            <p className="mt-1 text-[15px]">{inc.root_cause ?? "Not determined yet"}</p>
            <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm text-muted">{(inc.evidence ?? []).map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>
          </div>
          {inc.recurring?.occurrences && (
            <div className="mt-3 rounded border border-warn/40 bg-warn/5 p-3 text-sm">
              <p className="font-semibold text-warn">Recurring failure · {inc.recurring.occurrences} occurrences in {inc.recurring.period_days} days</p>
              <p className="text-muted">Recommended investigation: {inc.recurring.recommended_investigation?.join(" / ")}. {inc.recurring.note}</p>
            </div>
          )}
        </Panel>
        <Panel title="Blast radius">
          <div className="grid grid-cols-3 gap-2 text-center">
            {(["users", "devices", "services"] as const).map((k) => <div key={k} className="rounded border border-line py-2"><div className="font-cond text-2xl font-semibold num">{inc.counts?.[k] ?? 0}</div><div className="text-xs capitalize text-muted">{k}</div></div>)}
          </div>
          <KV cols={1} items={[["Users", (inc.affected_users ?? []).join(", ") || "none"], ["Devices", (inc.affected_devices ?? []).join(", ") || "none"], ["Services", (inc.affected_services ?? []).join(", ") || "none"]]} />
          {inc.triage?.factors && <ul className="mt-3 space-y-0.5 border-t border-line pt-2 text-xs text-muted">{inc.triage.factors.map((f: string) => <li key={f}>{f}</li>)}</ul>}
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Timeline"><IncidentTimeline items={inc.timeline} /></Panel>
        <div className="space-y-4">
          {inc.transactions.map((tx: any) => (
            <Panel key={tx.id} title={`${tx.id} · ${tx.action_name}`} subtitle={`${tx.category} · confidence ${tx.automation_confidence}% · requested by ${tx.requested_by}`} actions={<Pill value={tx.status} />}>
              <RemediationTimeline steps={tx.steps} />
              {tx.verification?.length > 0 && <div className="mt-2 border-t border-line pt-2"><h3 className="mb-1 text-xs text-muted">Verification</h3>
                <ul className="space-y-0.5 text-sm">{tx.verification.map((v: any, i: number) => <li key={i} className="flex gap-2"><Pill value={v.passed ? "PASS" : "FAIL"} /><span>{v.probe} <span className="text-muted">{v.detail}</span></span></li>)}</ul></div>}
              <p className="mt-2 text-xs text-muted">Rollback: {tx.rollback_status} · Human action: {tx.human_action}</p>
            </Panel>
          ))}
          {!inc.transactions.length && <Panel title="Remediation"><Empty title="No automated remediation" hint={(inc.recommendations ?? []).join(" ") || "No catalogued action applies."} /></Panel>}
          {inc.decisions.length > 0 && (
            <Panel title="Decision records">
              <ul className="space-y-2">{inc.decisions.map((d: any) => (
                <li key={d.id} className="rounded border border-line p-2 text-sm">
                  <div className="flex flex-wrap items-center gap-2"><Mono>{d.id}</Mono><span>{d.action_id}</span><Pill value={d.outcome} /><span className="text-xs text-muted">{d.confidence}% confidence</span><span className="ml-auto"><WhyButton path={`/api/explain/decision/${d.id}`} /></span></div>
                  <p className="mt-1 text-xs text-muted">{d.reasons.join("; ")}</p>
                </li>
              ))}</ul>
            </Panel>
          )}
        </div>
      </div>

      <Panel title="Event forensics" subtitle="All events related by correlation ID or asset" bodyClass="p-3"
        actions={<input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by type, device, user, severity, correlation ID" aria-label="Filter events" className={cx(inputClass, "w-80")} />}>
        <div className="max-h-[420px] overflow-y-auto">
          <table className="w-full text-left text-sm">
            <thead className="sticky top-0 bg-inset text-xs text-muted"><tr>{["Time", "Phase", "Type", "Target", "Message", "Correlation"].map((h) => <th key={h} className="px-2 py-1.5 font-medium">{h}</th>)}</tr></thead>
            <tbody>{events.map((e: any) => (
              <tr key={e.id} className="border-t border-line align-top">
                <td className="px-2 py-1 font-mono text-xs text-muted">{fmtTime(e.ts)}</td><td className="px-2 font-cond text-[11px] text-accent">{e.phase}</td>
                <td className="px-2 font-mono text-xs font-semibold">{e.type}</td><td className="px-2 font-mono text-xs">{e.target ?? "-"}</td>
                <td className="px-2 text-xs text-muted">{e.message}</td><td className="px-2 font-mono text-[11px] text-muted">{e.correlation_id ?? ""}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Panel>

      {(inc.chatops.length > 0 || (inc.recommendations ?? []).length > 0) && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="ChatOps">{inc.chatops.map((m: any) => <pre key={m.id} className="mb-2 overflow-x-auto rounded border border-line bg-inset p-2 font-mono text-xs">{m.body}{"\n"}[{m.provider} · {m.delivery_status}]</pre>)}{!inc.chatops.length && <Empty title="No notifications" />}</Panel>
          <Panel title="Recommendations"><ul className="list-disc space-y-1 pl-5 text-sm">{(inc.recommendations ?? []).map((r: string, i: number) => <li key={i}>{r}</li>)}</ul></Panel>
        </div>
      )}
    </div>
  );
}

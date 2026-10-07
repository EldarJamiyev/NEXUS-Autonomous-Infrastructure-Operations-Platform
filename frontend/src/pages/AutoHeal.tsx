import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { RotateCcw } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import type { Transaction } from "@/types";
import { DataTable } from "@/components/DataTable";
import { KV, Mono, PageHeader, Panel, Pill, Skeleton, EntityLink, Empty, cx, inputClass } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";
import { WhyButton } from "@/components/explain";
import { RemediationTimeline } from "@/components/timeline";
import { ago, dur, ms } from "@/lib/format";

export default function AutoHeal() {
  const [params, setParams] = useSearchParams();
  const selectedId = params.get("tx");
  const { can } = useAuth();
  const { run, busy } = useAction();
  const [status, setStatus] = useState("");
  const { data: txs } = useApi<Transaction[]>(`/api/remediations?limit=200${status ? `&status=${status}` : ""}`, { refreshOn: ["REMEDIATION", "VERIFICATION", "ROLLBACK", "APPROVAL", "DECISION"] });
  const { data: sc } = useApi<Record<string, any>>("/api/remediations/scorecard?hours=168", { refreshOn: ["REMEDIATION_COMPLETED", "REMEDIATION_FAILED", "INCIDENT_RESOLVED"] });
  const { data: catalog } = useApi<any[]>("/api/remediations/catalog");
  const sel = selectedId ?? txs?.[0]?.id ?? null;
  const { data: tx } = useApi<Transaction>(sel ? `/api/remediations/${sel}` : null, { refreshOn: ["REMEDIATION", "VERIFICATION", "ROLLBACK", "CHATOPS"] });
  const active = useMemo(() => (txs ?? []).filter((t) => ["PLANNED", "RUNNING"].includes(t.status)), [txs]);
  return (
    <div className="space-y-4">
      <PageHeader title="Auto-healing" description="Every automated change is a transaction: policy and safety checks, backup, allowlisted execution, verification of the real end state, commit or rollback, ChatOps, audit." />
      {sc && (
        <div className="grid grid-cols-2 divide-x divide-y divide-line overflow-hidden rounded-md border border-line bg-panel sm:grid-cols-4 xl:grid-cols-8 xl:divide-y-0">
          {([["Alerts received", sc.alerts_received], ["Auto-resolved", sc.auto_resolved], ["Human-required", sc.human_required], ["Success rate", sc.remediation_success_pct === null ? "-" : `${sc.remediation_success_pct}%`],
             ["Rollbacks", sc.rollbacks], ["Mean detection", dur(sc.mean_detection_seconds)], ["Mean remediation", dur(sc.mean_remediation_seconds)], ["Mean verification", dur(sc.mean_verification_seconds)]] as [string, any][]).map(([k, v]) => (
            <div key={k} className="px-3 py-2"><div className="text-[11.5px] text-muted">{k}</div><div className="font-cond text-2xl font-semibold num">{v ?? "-"}</div></div>
          ))}
        </div>
      )}
      <p className="-mt-2 text-xs text-muted">{sc?.label} over 7 days. {sc?.notes}</p>
      {active.length > 0 && (
        <Panel title="Running now" className="border-accent/50">
          <div className="space-y-4">{active.map((t) => (
            <div key={t.id}>
              <div className="mb-2 flex flex-wrap items-center gap-2 text-sm"><Mono>{t.id}</Mono><span className="font-medium">{t.action_name}</span><EntityLink kind="device" id={t.target} /><Pill value={t.status} tone="auto" /></div>
              <RemediationTimeline steps={t.steps} horizontal />
            </div>
          ))}</div>
        </Panel>
      )}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_520px]">
        <Panel title="Transactions" bodyClass="p-3">
          {!txs ? <Skeleton rows={8} /> : (
            <DataTable rows={txs} rowKey={(t) => t.id} selected={sel} onRowClick={(t) => setParams({ tx: t.id })} placeholder="Filter transactions"
              toolbar={<select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)} className={cx(inputClass, "h-8")}>
                <option value="">All</option><option value="COMMITTED">Committed</option><option value="ROLLED_BACK,FAILED">Failed / rolled back</option><option value="AWAITING_APPROVAL">Pending approval</option><option value="RUNNING,PLANNED">Running</option>
              </select>}
              columns={[
                { key: "id", header: "TX", render: (t) => <Mono className="text-info">{t.id}</Mono> },
                { key: "action_name", header: "Action", render: (t) => <div><div>{t.action_name}</div><div className="max-w-[260px] truncate text-[11px] text-muted">{t.trigger}</div></div> },
                { key: "target", header: "Target", render: (t) => <Mono>{t.target}</Mono> },
                { key: "category", header: "Category", render: (t) => <Pill tone="neutral">{t.category}</Pill> },
                { key: "status", header: "Status", render: (t) => <Pill value={t.status} /> },
                { key: "duration_ms", header: "Duration", render: (t) => <span className="text-xs">{ms(t.duration_ms)}</span> },
                { key: "created_at", header: "When", render: (t) => <span className="whitespace-nowrap text-xs text-muted">{ago(t.created_at)}</span> },
              ]} />
          )}
        </Panel>
        <Panel title={tx ? `${tx.id} · ${tx.action_name}` : "Transaction"} subtitle={tx ? `${tx.target} · ${tx.trigger}` : undefined} actions={tx && <Pill value={tx.status} />}>
          {!tx ? <Empty title="Select a transaction" /> : (
            <div className="space-y-4">
              {tx.decision && (
                <div className="rounded border border-line">
                  <div className="flex items-center justify-between border-b border-line px-3 py-1.5"><span className="font-cond text-sm font-semibold">Automation safety</span><WhyButton path={`/api/explain/decision/${tx.decision.id}`} /></div>
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-1 px-3 py-2 text-sm">
                    {(["preconditions", "policy", "risk", "rollback", "verification", "approval", "decision"] as const).map((k) => (
                      <div key={k} className="flex justify-between gap-2"><dt className="capitalize text-muted">{k}</dt><dd><Pill value={String(tx.decision!.safety[k] ?? "-")} /></dd></div>
                    ))}
                    <div className="flex justify-between gap-2"><dt className="text-muted">Confidence</dt><dd className="font-mono">{tx.automation_confidence}%</dd></div>
                  </dl>
                </div>
              )}
              <RemediationTimeline steps={tx.steps} />
              <div>
                <h3 className="mb-1 text-xs text-muted">Commands (allowlisted templates)</h3>
                <ul className="space-y-1">{(tx.commands ?? []).filter((c: any) => c.command && "exit_code" in c).map((c: any, i: number) => (
                  <li key={i} className="rounded border border-line bg-inset p-2 font-mono text-xs">
                    <div className="flex justify-between gap-2"><span>{c.rollback ? "[rollback] " : ""}$ {c.command}</span><span className={c.exit_code === 0 ? "text-ok" : "text-crit"}>exit {c.exit_code}</span></div>
                    {c.output && <div className="mt-1 whitespace-pre-wrap text-muted">{c.output}</div>}
                  </li>
                ))}</ul>
              </div>
              {tx.verification?.length > 0 && <div><h3 className="mb-1 text-xs text-muted">Verification of the desired end state</h3>
                <ul className="space-y-0.5 text-sm">{tx.verification.map((v, i) => <li key={i} className="flex gap-2"><Pill value={v.passed ? "PASS" : "FAIL"} /><span>{v.probe} <span className="text-muted">{v.detail}</span></span></li>)}</ul></div>}
              <KV items={[["Backup", Object.keys(tx.backup ?? {}).join(", ") || "none"], ["Rollback", tx.rollback_status], ["Human action", tx.human_action],
                ["Incident", tx.incident_id ? <Link className="text-info" to={`/incidents/${tx.incident_id}`}>{tx.incident_id}</Link> : "-"], ["Correlation", <Mono>{tx.correlation_id ?? "-"}</Mono>], ["Requested by", tx.requested_by]]} />
              {tx.status === "COMMITTED" && tx.rollback_available && (
                <ConfirmButton label="Roll back this change" icon={<RotateCcw className="h-4 w-4" />} disabled={!can("ENGINEER")} busy={busy === "rb"} confirmTitle={`Roll back ${tx.id}?`}
                  confirmText="The pre-change backup is restored. The re-appearing drift is accepted for 15 minutes so NEXUS does not immediately re-apply the fix."
                  onConfirm={() => run("rb", () => api.post(`/api/remediations/${tx.id}/rollback`), "Rolled back")} />
              )}
            </div>
          )}
        </Panel>
      </div>
      <Panel title="Remediation catalog" subtitle="Only these actions can ever run, and only through validated command templates" bodyClass="p-3">
        {catalog && <DataTable rows={catalog} rowKey={(a) => a.id} pageSize={30} placeholder="Filter actions"
          columns={[{ key: "id", header: "ID", render: (a) => <Mono>{a.id}</Mono> }, { key: "name", header: "Action", render: (a) => <div><div>{a.name}</div><div className="max-w-[420px] truncate text-[11px] text-muted">{a.description}</div></div> },
            { key: "category", header: "Category", render: (a) => <Pill tone={a.category === "SAFE" ? "ok" : a.category === "REVERSIBLE" ? "info" : a.category === "HIGH_IMPACT" ? "warn" : "crit"}>{a.category}</Pill> },
            { key: "permission", header: "Permission" }, { key: "base_confidence", header: "Confidence", render: (a) => `${a.base_confidence}%` },
            { key: "rollback", header: "Rollback", render: (a) => a.rollback_available ? <Pill tone="ok">AVAILABLE</Pill> : <span className="text-xs text-muted">not required</span> },
            { key: "verification", header: "Probes", render: (a) => <span className="text-xs">{a.verification.length}</span> }]} />}
      </Panel>
    </div>
  );
}

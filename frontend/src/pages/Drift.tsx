import { useState } from "react";
import { Link } from "react-router-dom";
import { Radar, Wrench } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import type { Drift } from "@/types";
import { DataTable } from "@/components/DataTable";
import { Button, KV, Mono, PageHeader, Panel, Pill, Skeleton, Empty, cx, inputClass } from "@/components/ui";
import { ConfirmButton, useAction } from "@/components/feedback";
import { WhyButton } from "@/components/explain";
import { DiffView } from "@/components/timeline";
import { ago, json } from "@/lib/format";

export default function DriftPage() {
  const { can } = useAuth();
  const { run, busy } = useAction();
  const [status, setStatus] = useState("OPEN,APPROVAL_REQUIRED,REMEDIATING,FAILED,EXPECTED");
  const { data } = useApi<Drift[]>(`/api/drift${status ? `?status=${status}` : ""}`, { refreshOn: ["DRIFT", "REMEDIATION", "CONFIG", "APPROVAL"] });
  const { data: all } = useApi<Drift[]>("/api/drift", { refreshOn: ["DRIFT"] });
  const [sel, setSel] = useState<string | null>(null);
  const d = (data ?? []).find((x) => x.id === sel) ?? (all ?? []).find((x) => x.id === sel) ?? data?.[0] ?? null;
  return (
    <div className="space-y-4">
      <PageHeader title="Configuration drift" description="Desired state lives in Git (baselines/ and policies/). NEXUS normalizes what host agents, the firewall and the switch report, compares, classifies and fixes - with SHA-256 evidence and real diffs."
        actions={<Button icon={<Radar className="h-4 w-4" />} disabled={!can("OPERATOR")} loading={busy === "scan"} onClick={() => run("scan", () => api.post<any>("/api/drift/scan"), (r: any) => `Scan complete: ${r.new.length} new, ${r.cleared.length} cleared`)}>Scan now</Button>} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_560px]">
        <Panel title="Drift events" bodyClass="p-3">
          {!data ? <Skeleton rows={8} /> : (
            <DataTable rows={data} rowKey={(x) => x.id} selected={d?.id} onRowClick={(x) => setSel(x.id)} placeholder="Filter drift"
              toolbar={<select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)} className={cx(inputClass, "h-8")}>
                <option value="OPEN,APPROVAL_REQUIRED,REMEDIATING,FAILED,EXPECTED">Active</option><option value="REMEDIATED,RESOLVED_EXTERNALLY,ACCEPTED">Closed</option><option value="">All</option></select>}
              columns={[{ key: "id", header: "ID", render: (x) => <Mono className="text-info">{x.id}</Mono> }, { key: "device_id", header: "Device", render: (x) => <Mono>{x.device_id}</Mono> },
                { key: "key", header: "Setting", render: (x) => <Mono>{x.component}.{x.key}</Mono>, search: (x) => `${x.component}.${x.key}` },
                { key: "classification", header: "Class", render: (x) => <Pill tone={x.classification === "CRITICAL" ? "crit" : x.classification === "SECURITY" ? "high" : x.classification === "OPERATIONAL" ? "warn" : "unk"}>{x.classification}</Pill> },
                { key: "risk", header: "Risk", render: (x) => <span className="font-mono">{x.risk}</span> }, { key: "status", header: "Status", render: (x) => <Pill value={x.status} /> },
                { key: "detected_at", header: "Detected", render: (x) => <span className="text-xs text-muted">{ago(x.detected_at)}</span> }]} />
          )}
        </Panel>
        <Panel title={d ? `${d.id} · ${d.device_id}` : "Drift detail"} actions={d && <WhyButton path={`/api/explain/drift/${d.id}`} />}>
          {!d ? <Empty title="No drift selected" /> : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded border border-ok/40 bg-ok/5 p-3"><div className="text-xs text-muted">Desired (Git intent)</div><div className="mt-1 break-all font-mono text-sm">{d.component}.{d.key} = {json(d.desired)}</div></div>
                <div className="rounded border border-crit/40 bg-crit/5 p-3"><div className="text-xs text-muted">Actual</div><div className="mt-1 break-all font-mono text-sm">{d.component}.{d.key} = {json(d.actual)}</div></div>
              </div>
              <dl className="grid grid-cols-3 gap-2 font-mono text-xs">
                <div><dt className="font-sans text-muted">EXPECTED</dt><dd>{d.desired_checksum.slice(0, 12)}…</dd></div>
                <div><dt className="font-sans text-muted">ACTUAL</dt><dd>{d.actual_checksum.slice(0, 12)}…</dd></div>
                <div><dt className="font-sans text-muted">MATCH</dt><dd className={d.checksum_match ? "text-ok" : "text-crit"}>{d.checksum_match ? "YES" : "NO"}</dd></div>
              </dl>
              <DiffView diff={d.diff} />
              <KV items={[["Classification", d.classification], ["Risk", d.risk], ["Status", <Pill value={d.status} />], ["Remediation", d.remediation_action ?? "report only"],
                ["Intent source", <Mono>{d.source}</Mono>], ["Transaction", d.transaction_id ? <Link className="text-info" to={`/autoheal?tx=${d.transaction_id}`}>{d.transaction_id}</Link> : "-"]]} />
              {d.during_maintenance && <Pill tone="warn">Detected during maintenance</Pill>}
              {!["REMEDIATED", "RESOLVED_EXTERNALLY", "ACCEPTED"].includes(d.status) && (
                <div className="flex flex-wrap gap-2">
                  {d.remediation_action && <Button variant="auto" icon={<Wrench className="h-4 w-4" />} disabled={!can("ENGINEER")} loading={busy === "rem"} onClick={() => run("rem", () => api.post<any>(`/api/drift/${d.id}/remediate`), (r: any) => `Decision ${r.outcome}: ${r.reasons?.[0] ?? ""}`)}>Remediate to intent</Button>}
                  <ConfirmButton label="Accept as intended" disabled={!can("ENGINEER")} confirmTitle={`Accept ${d.id}?`} confirmText="The difference is treated as intended. Update Git so the intent matches reality, otherwise it will be detected again." onConfirm={() => run("acc", () => api.post(`/api/drift/${d.id}/accept`, { note: "accepted from console" }), "Drift accepted")} />
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}

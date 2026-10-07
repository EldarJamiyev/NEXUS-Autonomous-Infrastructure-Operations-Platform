import { useState } from "react";
import { Link } from "react-router-dom";
import { Check, X } from "lucide-react";
import { api } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { useAuth } from "@/api/auth";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, Empty, inputClass, cx } from "@/components/ui";
import { Dialog, useAction } from "@/components/feedback";
import { DataTable } from "@/components/DataTable";
import { ago, fmtDateTime } from "@/lib/format";

export default function Approvals() {
  const { can, principal } = useAuth();
  const { run, busy } = useAction();
  const { data } = useApi<any[]>("/api/approvals", { refreshOn: ["APPROVAL", "REMEDIATION", "LEASE", "DRIFT"] });
  const [decide, setDecide] = useState<{ a: any; verb: "approve" | "reject" } | null>(null);
  const [note, setNote] = useState("");
  if (!data) return <Skeleton rows={8} />;
  const pending = data.filter((a) => a.status === "PENDING");
  return (
    <div className="space-y-4">
      <PageHeader title="Approvals" description="Human-in-the-loop gate: HIGH_IMPACT and CRITICAL actions, low-confidence fixes, after-hours access and risky changes wait here. Requesters cannot approve their own requests." />
      {pending.length === 0 && <Empty title="Nothing waiting for approval" hint="Approval requests appear here when NEXUS will not act on its own." />}
      <div className="grid gap-4 lg:grid-cols-2">
        {pending.map((a) => (
          <Panel key={a.id} title={a.title} subtitle={`${a.id} · requested by ${a.requested_by} ${ago(a.requested_at)}`} actions={<><Pill tone="neutral">{a.kind}</Pill><Pill value={a.category} tone="warn" /></>}>
            <p className="text-sm">{a.reason}</p>
            {a.safety && (
              <dl className="mt-3 grid grid-cols-3 gap-2 text-xs">
                {(["preconditions", "rollback", "verification", "risk", "approval"] as const).map((k) => <div key={k}><dt className="capitalize text-muted">{k}</dt><dd><Pill value={String(a.safety[k])} /></dd></div>)}
                <div><dt className="text-muted">Confidence</dt><dd className="font-mono">{a.confidence}%</dd></div>
              </dl>
            )}
            {a.evidence?.length > 0 && <ul className="mt-3 list-disc space-y-0.5 pl-5 text-xs text-muted">{a.evidence.slice(0, 4).map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button variant="auto" icon={<Check className="h-4 w-4" />} disabled={!can(a.required_role === "ADMIN" ? "ADMIN" : "ENGINEER") || principal?.user_id === a.requested_by} onClick={() => { setNote(""); setDecide({ a, verb: "approve" }); }}>Approve</Button>
              <Button icon={<X className="h-4 w-4" />} disabled={!can("OPERATOR")} onClick={() => { setNote(""); setDecide({ a, verb: "reject" }); }}>Reject</Button>
              <span className="text-xs text-muted">needs {a.required_role}{principal?.user_id === a.requested_by ? " · you requested this" : ""}</span>
              {a.incident_id && <Link className="ml-auto text-xs text-info" to={`/incidents/${a.incident_id}`}>{a.incident_id}</Link>}
              {a.transaction_id && <Link className="text-xs text-info" to={`/autoheal?tx=${a.transaction_id}`}>{a.transaction_id}</Link>}
            </div>
          </Panel>
        ))}
      </div>
      <Panel title="History" bodyClass="p-3">
        <DataTable rows={data.filter((a) => a.status !== "PENDING")} rowKey={(a) => a.id} placeholder="Filter decisions"
          columns={[{ key: "id", header: "ID", render: (a) => <Mono>{a.id}</Mono> }, { key: "title", header: "Request" }, { key: "status", header: "Decision", render: (a) => <Pill value={a.status} /> },
            { key: "decided_by", header: "By", render: (a) => a.decided_by ?? "-" }, { key: "decided_at", header: "When", render: (a) => fmtDateTime(a.decided_at) },
            { key: "note", header: "Note", render: (a) => <span className="text-xs text-muted">{a.note}</span> }]} />
      </Panel>
      <Dialog open={!!decide} onClose={() => setDecide(null)} title={decide ? `${decide.verb === "approve" ? "Approve" : "Reject"} ${decide.a.id}` : ""}
        footer={<><Button onClick={() => setDecide(null)}>Cancel</Button><Button variant={decide?.verb === "approve" ? "auto" : "danger"} loading={!!busy}
          onClick={async () => { if (!decide) return; await run(decide.verb, () => api.post(`/api/approvals/${decide.a.id}/${decide.verb}`, { note }), decide.verb === "approve" ? "Approved - NEXUS will execute and verify" : "Rejected"); setDecide(null); }}>
          {decide?.verb === "approve" ? "Approve" : "Reject"}</Button></>}>
        <p className="mb-2 text-sm">{decide?.a.title}</p>
        <label className="text-xs text-muted" htmlFor="note">Note for the audit trail</label>
        <textarea id="note" value={note} onChange={(e) => setNote(e.target.value)} rows={3} className={cx(inputClass, "mt-1 h-auto w-full py-1.5")} />
      </Dialog>
    </div>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";
import { qs } from "@/api/client";
import { useApi } from "@/hooks/useApi";
import { Button, Mono, PageHeader, Panel, Pill, Skeleton, cx, inputClass } from "@/components/ui";
import { fmtDateTime } from "@/lib/format";

export default function Audit() {
  const [q, setQ] = useState("");
  const [actorType, setActorType] = useState("");
  const [result, setResult] = useState("");
  const [offset, setOffset] = useState(0);
  const limit = 50;
  const { data } = useApi<any>(`/api/audit?${qs({ q, actor_type: actorType, result, limit, offset })}`, { refreshOn: offset === 0 ? ["REMEDIATION", "LEASE", "INCIDENT", "APPROVAL", "POLICY", "SETTING"] : [] });
  return (
    <div>
      <PageHeader title="Audit timeline" description="Every meaningful action: who, what, why, target, result, time and correlation ID. Automated actions and human actions are recorded the same way." />
      <Panel bodyClass="p-3">
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <input value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} placeholder="Search action, reason, target, TX, incident, correlation ID" aria-label="Search audit" className={cx(inputClass, "w-96")} />
          <select aria-label="Actor type" value={actorType} onChange={(e) => { setActorType(e.target.value); setOffset(0); }} className={inputClass}>
            <option value="">All actors</option><option value="AUTOHEAL">AutoHeal</option><option value="OPERATOR">Operators</option><option value="SYSTEM">System</option><option value="INTEGRATION">Integrations</option></select>
          <select aria-label="Result" value={result} onChange={(e) => { setResult(e.target.value); setOffset(0); }} className={inputClass}>
            <option value="">All results</option><option value="SUCCESS">Success</option><option value="FAILED">Failed</option><option value="PENDING">Pending</option><option value="APPROVED">Approved</option><option value="REJECTED">Rejected</option></select>
          <span className="ml-auto text-xs text-muted">{data ? `${data.total} records` : ""}</span>
        </div>
        {!data ? <Skeleton rows={10} /> : (
          <div className="overflow-x-auto rounded border border-line">
            <table className="w-full text-left text-sm">
              <thead className="bg-inset text-xs text-muted"><tr>{["Time", "Who", "What", "Why", "Target", "Result", "Correlation"].map((h) => <th key={h} className="whitespace-nowrap px-3 py-2 font-medium">{h}</th>)}</tr></thead>
              <tbody>{data.items.map((a: any) => (
                <tr key={a.id} className="border-t border-line align-top">
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-xs text-muted">{fmtDateTime(a.ts)}</td>
                  <td className="px-3"><div className="font-medium">{a.actor}</div><div className="text-[11px] text-muted">{a.actor_type}</div></td>
                  <td className="px-3">{a.action}</td><td className="max-w-[360px] px-3 text-xs text-muted">{a.reason}</td><td className="px-3"><Mono>{a.target}</Mono></td>
                  <td className="px-3"><Pill value={a.result} /></td>
                  <td className="px-3 font-mono text-[11px]">{a.transaction_id ? <Link className="text-info" to={`/autoheal?tx=${a.transaction_id}`}>{a.transaction_id}</Link> : null}{a.incident_id && <div><Link className="text-info" to={`/incidents/${a.incident_id}`}>{a.incident_id}</Link></div>}<div className="text-muted">{a.correlation_id}</div></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        {data && data.total > limit && (
          <div className="mt-2 flex items-center justify-end gap-2 text-xs text-muted">
            <Button size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>Newer</Button>
            <span>{offset + 1}-{Math.min(offset + limit, data.total)} of {data.total}</span>
            <Button size="sm" disabled={offset + limit >= data.total} onClick={() => setOffset(offset + limit)}>Older</Button>
          </div>
        )}
      </Panel>
    </div>
  );
}

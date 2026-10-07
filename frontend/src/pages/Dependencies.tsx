import { useState } from "react";
import { useApi } from "@/hooks/useApi";
import { DependencyGraph } from "@/graph/DependencyGraph";
import { Mono, PageHeader, Panel, Pill, Skeleton } from "@/components/ui";

export default function Dependencies() {
  const { data } = useApi<any>("/api/dependencies", { refreshOn: ["SERVICE", "REMEDIATION", "INCIDENT", "ALERT"] });
  const [sel, setSel] = useState<string | null>(null);
  if (!data) return <Skeleton rows={10} />;
  const node = data.nodes.find((n: any) => n.id === sel);
  const upstream = data.edges.filter((e: any) => e.source === sel);
  const downstream = data.edges.filter((e: any) => e.target === sel);
  const order = data.failing.length ? data.recovery_order : data.full_recovery_order;
  return (
    <div className="space-y-4">
      <PageHeader title="Service dependencies" description="What depends on what. Used for impact propagation, correlation (one incident, many symptoms) and recovery ordering."
        meta={data.failing.length ? <Pill tone="crit">{data.failing.length} service(s) failing: {data.failing.join(", ")}</Pill> : <Pill tone="ok">All services running</Pill>} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <DependencyGraph nodes={data.nodes} edges={data.edges} selected={sel} onSelect={setSel} height={540} />
        <Panel title={node ? node.name : "Select a service"} subtitle={node ? `${node.id} · ${node.layer}` : "Arrows point from a dependency to the services that need it"}>
          {node && (
            <div className="space-y-3 text-sm">
              <div className="flex gap-2"><Pill value={node.status} /><Pill tone="neutral">{node.criticality}</Pill></div>
              <p>RTO {node.rto ?? "-"} min · RPO {node.rpo ?? "-"} min · consumers: {node.consumers}</p>
              <div><h3 className="text-xs text-muted">Depends on</h3>{upstream.map((e: any) => <p key={e.target}><Mono>{e.target}</Mono> <span className="text-xs text-muted">{e.description}</span></p>)}{!upstream.length && <p className="text-muted">nothing</p>}</div>
              <div><h3 className="text-xs text-muted">Needed by</h3>{downstream.map((e: any) => <p key={e.source}><Mono>{e.source}</Mono> <span className="text-xs text-muted">{e.description}</span></p>)}{!downstream.length && <p className="text-muted">nothing</p>}</div>
            </div>
          )}
        </Panel>
      </div>
      <Panel title={data.failing.length ? "Recovery order for the failing services" : "Full recovery order (if everything failed)"} subtitle="Dependencies first, ties broken by infrastructure layer" bodyClass="p-0">
        <table className="w-full text-left text-sm"><thead className="bg-inset text-xs text-muted"><tr>{["#", "Service", "Layer", "Why this position", "RTO", "RPO"].map((h) => <th key={h} className="px-3 py-2 font-medium">{h}</th>)}</tr></thead>
          <tbody>{order.map((r: any) => <tr key={r.order} className="border-t border-line"><td className="px-3 py-1.5 font-mono">{r.order}</td><td className="px-3"><Mono>{r.service}</Mono> <span className="text-xs text-muted">{r.name}</span></td><td className="px-3 text-xs">{r.layer}</td><td className="px-3 text-xs text-muted">{r.reason}</td><td className="px-3 text-xs">{r.rto_minutes ? `${r.rto_minutes} min` : "-"}</td><td className="px-3 text-xs">{r.rpo_minutes !== null && r.rpo_minutes !== undefined ? `${r.rpo_minutes} min` : "-"}</td></tr>)}</tbody></table>
      </Panel>
    </div>
  );
}

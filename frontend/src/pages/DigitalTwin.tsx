import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "@/hooks/useApi";
import { TopologyGraph, impactSet, neighbourhood, type TopoNode, type Topology } from "@/graph/TopologyGraph";
import { Panel, PageHeader, Pill, Risk, Skeleton, KV, Mono, cx, inputClass, Status } from "@/components/ui";
import { WhyButton } from "@/components/explain";

export default function DigitalTwin() {
  const { data } = useApi<Topology & { vlans: any[] }>("/api/network", { refreshOn: ["INCIDENT", "QUARANTINE", "DEVICE_DISCOVERED", "REMEDIATION", "RISK", "SERVICE", "ALERT"] });
  const [showServices, setShowServices] = useState(true);
  const [heat, setHeat] = useState(true);
  const [mode, setMode] = useState<"impact" | "selection" | "none">("impact");
  const [selected, setSelected] = useState<TopoNode | null>(null);
  const [search, setSearch] = useState("");
  const highlight = useMemo(() => {
    if (!data) return null;
    if (mode === "impact") { const s = impactSet(data); return s.size ? s : null; }
    if (mode === "selection" && selected) return neighbourhood(data, selected.id);
    return null;
  }, [data, mode, selected]);
  if (!data) return <Skeleton rows={12} />;
  const impact = impactSet(data);
  const node = selected ? data.nodes.find((n) => n.id === selected.id) ?? selected : null;
  const deps = node ? data.edges.filter((e) => e.kind === "depends" && (e.source === node.id || e.target === node.id)) : [];
  return (
    <div>
      <PageHeader title="Digital twin" description="Internet, firewall, switch, VLANs, servers, clients, services and their dependencies, built from live NEXUS state. Incidents light up the propagation path."
        meta={impact.size > 0
          ? <Pill tone="crit">{impact.size} nodes on an active incident path · root cause {data.highlights.root_causes?.join(", ") || "under analysis"}</Pill>
          : <Pill tone="ok">No active incident impact</Pill>} />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Find node or IP" aria-label="Find node" className={cx(inputClass, "w-48")} />
        <label className="flex items-center gap-1.5 text-sm"><input type="checkbox" checked={showServices} onChange={(e) => setShowServices(e.target.checked)} />Services and dependencies</label>
        <label className="flex items-center gap-1.5 text-sm"><input type="checkbox" checked={heat} onChange={(e) => setHeat(e.target.checked)} />Risk scores</label>
        <label className="flex items-center gap-1.5 text-sm">Highlight
          <select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)} className={cx(inputClass, "h-7")}>
            <option value="impact">Incident impact</option><option value="selection">Selected node path</option><option value="none">Nothing</option>
          </select>
        </label>
        <span className="ml-auto flex flex-wrap items-center gap-3 text-xs text-muted">
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-ok" />healthy</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-warn" />warning</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-crit" />critical</span>
          <span className="flex items-center gap-1"><span className="h-2 w-3 rounded-sm border border-dashed border-accent" />quarantined</span>
          <span className="flex items-center gap-1"><span className="h-px w-4 border-t border-dashed border-accent" />depends on</span>
        </span>
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
        <TopologyGraph topology={data} showServices={showServices} highlight={highlight} selectedId={node?.id} onSelect={setSelected} search={search} heat={heat} height="calc(100vh - 230px)" />
        <Panel title={node ? node.label : "Select a node"} subtitle={node ? node.type.toUpperCase() : "Click any node for its live state"}>
          {!node && <p className="text-sm text-muted">Devices show identity, risk, services and incidents. Services show their dependencies. VLANs show subnet and members.</p>}
          {node?.type === "device" || node?.type === "firewall" || node?.type === "switch" ? (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2"><Status value={node.status} />{node.data.quarantined && <Pill tone="auto">QUARANTINED</Pill>}<Pill value={node.data.identity_level} /></div>
              <KV items={[["IP", <Mono>{node.data.ip}</Mono>], ["MAC", <Mono>{node.data.mac}</Mono>], ["VLAN", node.data.vlan], ["OS", node.data.os],
                ["Identity", `${node.data.identity_confidence}%`], ["Last seen", <Mono>{String(node.data.last_seen).slice(11, 19)}</Mono>]]} />
              <div className="flex items-center justify-between"><Risk score={node.data.risk} level={node.data.risk_level} /><WhyButton path={`/api/explain/risk/device/${node.id}`} /></div>
              <div>
                <h3 className="mb-1 text-xs font-medium text-muted">Services</h3>
                <ul className="space-y-1">{(node.data.services as any[]).map((s) => <li key={s.id} className="flex justify-between text-sm"><span>{s.name}</span><Pill value={s.status} /></li>)}</ul>
                {!(node.data.services as any[]).length && <p className="text-sm text-muted">No managed services</p>}
              </div>
              {node.data.open_incidents > 0 && <Pill tone="crit">{node.data.open_incidents} open incident(s)</Pill>}
              <Link to={`/devices/${node.id}`} className="inline-block text-sm text-info hover:underline">Open device page</Link>
            </div>
          ) : node?.type === "service" ? (
            <div className="space-y-3 text-sm">
              <KV items={[["Status", <Pill value={node.data.status} />], ["Host", node.data.device], ["Criticality", node.data.criticality], ["Ports", (node.data.ports ?? []).join(", ") || "-"]]} />
              <div><h3 className="mb-1 text-xs font-medium text-muted">Dependencies</h3>
                <ul className="space-y-1">{deps.map((e) => <li key={e.id} className="text-xs"><Mono>{e.source}</Mono> depends on <Mono>{e.target}</Mono><span className="block text-muted">{e.label}</span></li>)}</ul>
                {!deps.length && <p className="text-xs text-muted">No declared dependencies</p>}
              </div>
            </div>
          ) : node?.type === "vlan" ? (
            <KV cols={1} items={[["Name", node.data.name], ["Subnet", <Mono>{node.data.subnet}</Mono>], ["Gateway", <Mono>{node.data.gateway}</Mono>], ["Purpose", node.data.purpose], ["Members", node.data.members]]} />
          ) : null}
        </Panel>
      </div>
    </div>
  );
}

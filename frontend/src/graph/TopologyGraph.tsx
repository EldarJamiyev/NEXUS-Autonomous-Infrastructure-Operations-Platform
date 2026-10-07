import { memo, useMemo } from "react";
import { Background, Controls, Handle, MiniMap, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import dagre from "@dagrejs/dagre";
import { Cog, Globe, HelpCircle, Layers, Monitor, Network, Server, Shield } from "lucide-react";
import { riskTone, toneOf, TONE_BG, TONE_TEXT } from "@/lib/format";
import { cx } from "@/components/ui";

export interface TopoNode { id: string; type: string; label: string; status: string; data: Record<string, any>; affected?: boolean; root_cause?: boolean }
export interface TopoEdge { id: string; source: string; target: string; kind: string; label?: string }
export interface Topology { nodes: TopoNode[]; edges: TopoEdge[]; highlights: Record<string, string[]> }

const SIZE: Record<string, { w: number; h: number }> = {
  internet: { w: 120, h: 40 }, firewall: { w: 178, h: 58 }, switch: { w: 178, h: 58 }, vlan: { w: 150, h: 46 }, device: { w: 172, h: 58 }, service: { w: 158, h: 36 },
};
const ICON: Record<string, JSX.Element> = {
  internet: <Globe className="h-4 w-4" />, firewall: <Shield className="h-4 w-4" />, switch: <Network className="h-4 w-4" />, vlan: <Layers className="h-4 w-4" />,
  server: <Server className="h-4 w-4" />, workstation: <Monitor className="h-4 w-4" />, unknown: <HelpCircle className="h-4 w-4" />, service: <Cog className="h-3.5 w-3.5" />,
};

type InfraData = TopoNode & { dim: boolean; selected: boolean; match: boolean; heat: boolean } & Record<string, unknown>;

const InfraNode = memo(({ data }: NodeProps<Node<InfraData>>) => {
  const d = data;
  const tone = d.type === "vlan" || d.type === "internet" ? "neutral" : toneOf(d.status);
  const kind = d.type === "device" ? (d.data.kind as string) : d.type;
  const risk = (d.data.risk as number) ?? 0;
  const sub = d.type === "vlan" ? d.data.subnet : d.type === "service" ? d.data.status : d.data.ip ?? d.data.role ?? "";
  return (
    <div title={`${d.label} - ${d.status}`}
      className={cx("relative flex h-full w-full items-center gap-2 rounded-md border bg-panel px-2.5 shadow-sm transition-opacity",
        d.type === "service" ? "rounded-full px-3" : "",
        d.data.quarantined ? "border-dashed border-accent" : tone === "crit" ? "border-crit" : tone === "warn" ? "border-warn" : "border-line",
        d.affected && "pulse-crit", d.selected && "ring-2 ring-accent", d.match && "ring-2 ring-info", d.dim && "opacity-25")}>
      <Handle type="target" position={Position.Left} className="!h-1 !w-1 !border-0 !bg-transparent" />
      <span className={cx("shrink-0", d.type === "service" ? TONE_TEXT[toneOf(d.data.status)] : "text-muted")}>{ICON[kind] ?? ICON.server}</span>
      <span className="min-w-0 flex-1 leading-tight">
        <span className="block truncate font-cond text-[13px] font-semibold">{d.label}</span>
        {sub && <span className="block truncate font-mono text-[10.5px] text-muted">{String(sub)}</span>}
      </span>
      {d.type === "device" && (
        <span className="flex flex-col items-end gap-0.5">
          <span className={cx("h-2 w-2 rounded-full", TONE_BG[tone])} />
          {d.heat && <span className={cx("font-mono text-[10px] num", TONE_TEXT[riskTone(risk)])}>{risk}</span>}
        </span>
      )}
      {d.root_cause && <span className="absolute -top-2 right-2 rounded bg-crit px-1 font-cond text-[10px] font-semibold text-white">ROOT CAUSE</span>}
      {d.data.quarantined && <span className="absolute -top-2 left-2 rounded bg-accent px-1 font-cond text-[10px] font-semibold text-white">VLAN 99</span>}
      <Handle type="source" position={Position.Right} className="!h-1 !w-1 !border-0 !bg-transparent" />
    </div>
  );
});
const nodeTypes = { infra: InfraNode };

export function layoutGraph(nodes: TopoNode[], edges: TopoEdge[], direction: "TB" | "LR" = "TB", allDepends = false) {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: direction, nodesep: direction === "TB" ? 22 : 10, ranksep: direction === "TB" ? 54 : 64, marginx: 10, marginy: 10 });
  g.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((n) => g.setNode(n.id, { width: SIZE[n.type]?.w ?? 160, height: SIZE[n.type]?.h ?? 50 }));
  edges.filter((e) => e.kind !== "depends" || allDepends).forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return new Map(nodes.map((n) => {
    const p = g.node(n.id);
    const s = SIZE[n.type] ?? { w: 160, h: 50 };
    return [n.id, { x: (p?.x ?? 0) - s.w / 2, y: (p?.y ?? 0) - s.h / 2 }];
  }));
}

export function TopologyGraph({ topology, showServices, highlight, selectedId, onSelect, search, heat, height = 560, interactive = true }: {
  topology: Topology; showServices: boolean; highlight?: Set<string> | null; selectedId?: string | null; onSelect?: (n: TopoNode) => void; search?: string;
  heat?: boolean; height?: number | string; interactive?: boolean;
}) {
  const { nodes, edges } = useMemo(() => {
    const visible = topology.nodes.filter((n) => showServices || n.type !== "service");
    const ids = new Set(visible.map((n) => n.id));
    const vEdges = topology.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
    const pos = layoutGraph(visible, vEdges, "LR");
    const q = search?.trim().toLowerCase();
    const rfNodes: Node<InfraData>[] = visible.map((n) => ({
      id: n.id, type: "infra", position: pos.get(n.id)!, width: SIZE[n.type]?.w, height: SIZE[n.type]?.h, draggable: interactive,
      data: { ...n, dim: !!highlight && highlight.size > 0 && !highlight.has(n.id), selected: n.id === selectedId,
              match: !!q && (n.label.toLowerCase().includes(q) || String(n.data.ip ?? "").includes(q)), heat: !!heat },
    }));
    const rfEdges: Edge[] = vEdges.map((e) => {
      const lit = highlight && highlight.has(e.source) && highlight.has(e.target);
      const dep = e.kind === "depends";
      return {
        id: e.id, source: e.source, target: e.target, animated: dep, label: e.kind === "access" ? e.label : undefined,
        labelStyle: { fontSize: 9, fill: "rgb(var(--muted))", fontFamily: "IBM Plex Mono" }, labelBgStyle: { fill: "rgb(var(--inset))" },
        style: { stroke: lit ? "rgb(var(--crit))" : dep ? "rgb(var(--accent) / 0.55)" : undefined, strokeDasharray: dep ? "4 3" : undefined, strokeWidth: lit ? 2 : undefined },
      };
    });
    return { nodes: rfNodes, edges: rfEdges };
  }, [topology, showServices, highlight, selectedId, search, heat, interactive]);

  return (
    <div style={{ height }} className="w-full overflow-hidden rounded border border-line">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.04 }} minZoom={0.2} maxZoom={2}
        nodesConnectable={false} elementsSelectable={interactive} panOnDrag={interactive} zoomOnScroll={interactive}
        onNodeClick={(_, n) => onSelect?.(topology.nodes.find((x) => x.id === n.id)!)} proOptions={{ hideAttribution: true }}>
        <Background gap={18} size={1} color="rgb(var(--line))" />
        {interactive && <Controls showInteractive={false} />}
        {interactive && <MiniMap pannable zoomable style={{ width: 150, height: 96 }} nodeColor={(n) => (toneOf((n.data as unknown as InfraData).status) === "crit" ? "rgb(var(--crit))" : "rgb(var(--line))")} />}
      </ReactFlow>
    </div>
  );
}

/** Impact propagation: the incident's affected entities plus every node on the path to them. */
export function impactSet(topology: Topology): Set<string> {
  const h = topology.highlights ?? {};
  const set = new Set<string>([...(h.affected_devices ?? []), ...(h.affected_services ?? []), ...(h.root_causes ?? [])]);
  if (!set.size) return set;
  for (const n of topology.nodes) if (n.type === "vlan" && n.affected) set.add(n.id);
  return set;
}

export function neighbourhood(topology: Topology, id: string): Set<string> {
  const set = new Set([id]);
  const walk = (cur: string, dir: "up" | "down", depth: number) => {
    if (depth > 6) return;
    for (const e of topology.edges) {
      const next = dir === "down" ? (e.source === cur ? e.target : null) : e.target === cur ? e.source : null;
      if (next && !set.has(next)) { set.add(next); walk(next, dir, depth + 1); }
    }
  };
  walk(id, "down", 0);
  walk(id, "up", 0);
  return set;
}

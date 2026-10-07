import { useMemo } from "react";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import { layoutGraph, type TopoNode } from "./TopologyGraph";
import { toneOf, TONE_BG } from "@/lib/format";
import { cx } from "@/components/ui";

export interface DepNode { id: string; name: string; device: string; status: string; criticality: string; layer: string; rto: number | null; rpo: number | null }
export interface DepEdge { source: string; target: string; description: string }

export function DependencyGraph({ nodes, edges, selected, onSelect, height = 520 }: { nodes: DepNode[]; edges: DepEdge[]; selected?: string | null; onSelect?: (id: string) => void; height?: number }) {
  const rf = useMemo(() => {
    const topo: TopoNode[] = nodes.map((n) => ({ id: n.id, type: "service", label: n.name, status: n.status, data: {} }));
    const pos = layoutGraph(topo, edges.map((e, i) => ({ id: `d${i}`, source: e.target, target: e.source, kind: "depends" })), "LR", true);
    const rfNodes: Node[] = nodes.map((n) => {
      const tone = toneOf(n.status);
      return {
        id: n.id, position: pos.get(n.id)!, width: 158, height: 36,
        data: { label: (
          <div className={cx("flex items-center gap-2 text-left", selected === n.id && "font-semibold")}>
            <span className={cx("h-2 w-2 shrink-0 rounded-full", TONE_BG[tone])} />
            <span className="min-w-0 leading-tight"><span className="block truncate font-cond text-[12.5px]">{n.name}</span><span className="block truncate font-mono text-[10px] text-muted">{n.id}</span></span>
          </div>
        ) },
        style: { width: 158, height: 36, padding: "2px 8px", borderRadius: 6, background: "rgb(var(--panel))", color: "rgb(var(--ink))",
                 border: `1px solid ${tone === "crit" ? "rgb(var(--crit))" : selected === n.id ? "rgb(var(--accent))" : "rgb(var(--line))"}` },
      };
    });
    const rfEdges: Edge[] = edges.map((e, i) => ({ id: `e${i}`, source: e.target, target: e.source, label: undefined, animated: toneOf(nodes.find((n) => n.id === e.target)?.status) === "crit",
      markerEnd: { type: MarkerType.ArrowClosed, color: "rgb(var(--muted))" }, style: { stroke: "rgb(var(--muted) / 0.6)" } }));
    return { rfNodes, rfEdges };
  }, [nodes, edges, selected]);
  return (
    <div style={{ height }} className="overflow-hidden rounded border border-line">
      <ReactFlow nodes={rf.rfNodes} edges={rf.rfEdges} fitView nodesConnectable={false} onNodeClick={(_, n) => onSelect?.(n.id)} proOptions={{ hideAttribution: true }}>
        <Background gap={18} size={1} color="rgb(var(--line))" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

import { ArrowDown } from "lucide-react";
import type { Topology, TopoNode } from "./TopologyGraph";
import { riskTone, toneOf, TONE_BG, TONE_TEXT } from "@/lib/format";
import { cx } from "@/components/ui";

function Chip({ n, onSelect, wide }: { n: TopoNode; onSelect?: (n: TopoNode) => void; wide?: boolean }) {
  const tone = toneOf(n.status);
  const risk = (n.data.risk as number) ?? 0;
  return (
    <button onClick={() => onSelect?.(n)} title={`${n.label} - ${n.status}`}
      className={cx("flex w-full items-center gap-2 rounded border bg-panel px-2 py-1 text-left hover:bg-inset", wide && "max-w-[220px]",
        n.data.quarantined ? "border-dashed border-accent" : tone === "crit" ? "border-crit" : tone === "warn" ? "border-warn" : "border-line", n.affected && "pulse-crit")}>
      <span className={cx("h-2 w-2 shrink-0 rounded-full", TONE_BG[tone])} />
      <span className="min-w-0 flex-1 leading-tight"><span className="block truncate font-cond text-[13px] font-semibold">{n.label}</span><span className="block truncate font-mono text-[10.5px] text-muted">{String(n.data.ip ?? "")}</span></span>
      {n.data.risk !== undefined && <span className={cx("font-mono text-[11px] num", TONE_TEXT[riskTone(risk)])}>{risk}</span>}
    </button>
  );
}

/** Compact, readable topology for the overview: perimeter on top, one column per populated VLAN. */
export function TopologyMap({ topology, onSelect }: { topology: Topology; onSelect?: (n: TopoNode) => void }) {
  const fw = topology.nodes.find((n) => n.type === "firewall");
  const sw = topology.nodes.find((n) => n.type === "switch");
  const members = (vlanId: string) => topology.edges.filter((e) => e.source === vlanId && e.kind === "access").map((e) => topology.nodes.find((n) => n.id === e.target)!).filter(Boolean);
  const vlans = topology.nodes.filter((n) => n.type === "vlan" && members(n.id).length > 0);
  return (
    <div className="flex flex-col items-center gap-1.5">
      <span className="rounded-full border border-line px-3 py-0.5 font-cond text-[12px] text-muted">Internet</span>
      <ArrowDown className="h-3 w-3 text-muted" />
      <div className="flex w-full justify-center gap-3">{fw && <Chip n={fw} onSelect={onSelect} wide />}{sw && <Chip n={sw} onSelect={onSelect} wide />}</div>
      <ArrowDown className="h-3 w-3 text-muted" />
      <div className="grid w-full gap-2" style={{ gridTemplateColumns: `repeat(${Math.max(1, vlans.length)}, minmax(0, 1fr))` }}>
        {vlans.map((v) => (
          <div key={v.id} className={cx("min-w-0 rounded border bg-inset p-1.5", v.affected ? "border-crit/60" : v.data.vlan === 99 ? "border-accent/60" : "border-line")}>
            <div className="mb-1.5 px-0.5 leading-tight"><span className="font-cond text-[12.5px] font-semibold">VLAN {v.data.vlan}</span> <span className="text-[11px] text-muted">{String(v.data.name).toLowerCase()}</span>
              <span className="block font-mono text-[10px] text-muted">{v.data.subnet}</span></div>
            <div className="space-y-1">{members(v.id).map((n) => <Chip key={n.id} n={n} onSelect={onSelect} />)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

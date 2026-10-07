import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricPoint } from "@/types";
import { fmtTime } from "@/lib/format";

export function MetricChart({ points, field, height = 120, unit = "%", max }: { points: MetricPoint[]; field: "cpu" | "mem" | "net" | "latency"; height?: number; unit?: string; max?: number }) {
  const data = points.map((p) => ({ t: fmtTime(p.ts), v: p[field] }));
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -18 }}>
          <defs>
            <linearGradient id={`g-${field}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="rgb(var(--info))" stopOpacity={0.35} />
              <stop offset="100%" stopColor="rgb(var(--info))" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgb(var(--line))" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="t" tick={{ fontSize: 10, fill: "rgb(var(--muted))" }} interval="preserveStartEnd" minTickGap={40} />
          <YAxis tick={{ fontSize: 10, fill: "rgb(var(--muted))" }} domain={[0, max ?? "auto"]} width={42} unit={unit === "%" ? "" : ""} />
          <Tooltip contentStyle={{ background: "rgb(var(--panel))", border: "1px solid rgb(var(--line))", fontSize: 12 }} formatter={(v: number) => [`${v ?? "-"} ${unit}`, field]} />
          <Area type="monotone" dataKey="v" stroke="rgb(var(--info))" strokeWidth={1.6} fill={`url(#g-${field})`} isAnimationActive={false} connectNulls />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function Spark({ points, field }: { points: MetricPoint[]; field: "cpu" | "mem" }) {
  const data = points.slice(-40).map((p) => ({ v: p[field] }));
  return (
    <div className="h-6 w-20">
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 1, right: 0, bottom: 1, left: 0 }}>
          <Area type="monotone" dataKey="v" stroke="rgb(var(--muted))" strokeWidth={1} fill="rgb(var(--muted) / 0.12)" isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Stacked distribution bar (healthy / warning / critical / quarantined). */
export function DistributionBar({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded-sm ring-1 ring-line">
        {parts.map((p) => p.value > 0 && <span key={p.label} className={p.color} style={{ width: `${(100 * p.value) / total}%` }} title={`${p.label} ${p.value}`} />)}
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {parts.map((p) => (
          <li key={p.label} className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-sm ${p.color}`} />{p.label}<span className="font-mono text-muted num">{Math.round((100 * p.value) / total)}% ({p.value})</span></li>
        ))}
      </ul>
    </div>
  );
}
